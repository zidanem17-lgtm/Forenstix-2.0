"""
FORENSTIX 2.0 — Enhanced Core Forensic Analysis Engine

Extends the original Forenstix analyzer with:
  • Domain/hostname IOC extraction
  • File hash IOC extraction (MD5/SHA-1/SHA-256 patterns inside files)
  • YARA rule scanning with bundled community ruleset
  • Richer IOC metadata (deduplication, type tags)
  • Preserved 100% API compatibility with Forenstix v1
"""

import hashlib
import math
import os
import re
import struct
import json
import datetime
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

# ─── Magic byte signatures ────────────────────────────────────────────────
MAGIC_SIGNATURES = {
    b'\xFF\xD8\xFF': ('JPEG Image', '.jpg'),
    b'\x89PNG\r\n\x1a\n': ('PNG Image', '.png'),
    b'GIF87a': ('GIF Image (87a)', '.gif'),
    b'GIF89a': ('GIF Image (89a)', '.gif'),
    b'%PDF': ('PDF Document', '.pdf'),
    b'PK\x03\x04': ('ZIP Archive / Office Document', '.zip'),
    b'PK\x05\x06': ('ZIP Archive (empty)', '.zip'),
    b'Rar!\x1a\x07': ('RAR Archive', '.rar'),
    b'\x1f\x8b': ('GZIP Archive', '.gz'),
    b'BZ': ('BZIP2 Archive', '.bz2'),
    b'\x7fELF': ('ELF Executable (Linux)', '.elf'),
    b'MZ': ('Windows Executable (PE)', '.exe'),
    b'\xCA\xFE\xBA\xBE': ('Java Class / Mach-O Fat Binary', '.class'),
    b'\xFE\xED\xFA': ('Mach-O Executable (macOS)', '.macho'),
    b'\xCF\xFA\xED\xFE': ('Mach-O Executable (macOS, 64-bit)', '.macho'),
    b'SQLite format 3': ('SQLite Database', '.sqlite'),
    b'\x00\x00\x01\x00': ('ICO Icon', '.ico'),
    b'RIFF': ('RIFF Container (AVI/WAV)', '.riff'),
    b'\x00\x00\x00\x1c\x66\x74\x79\x70': ('MP4 Video', '.mp4'),
    b'\x00\x00\x00\x18\x66\x74\x79\x70': ('MP4 Video', '.mp4'),
    b'\x00\x00\x00\x20\x66\x74\x79\x70': ('MP4 Video', '.mp4'),
    b'\x49\x44\x33': ('MP3 Audio (ID3)', '.mp3'),
    b'\xFF\xFB': ('MP3 Audio', '.mp3'),
    b'\xFF\xF3': ('MP3 Audio', '.mp3'),
    b'OggS': ('OGG Audio', '.ogg'),
    b'fLaC': ('FLAC Audio', '.flac'),
    b'\x50\x4B\x03\x04\x14\x00\x06\x00': ('MS Office Open XML', '.docx'),
    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('MS Office Legacy (DOC/XLS/PPT)', '.doc'),
    b'<!DOCTYPE html': ('HTML Document', '.html'),
    b'<html': ('HTML Document', '.html'),
    b'<?xml': ('XML Document', '.xml'),
    b'\x37\x7A\xBC\xAF\x27\x1C': ('7-Zip Archive', '.7z'),
    b'\x04\x22\x4D\x18': ('LZ4 Archive', '.lz4'),
    b'\x28\xB5\x2F\xFD': ('Zstandard Archive', '.zst'),
}

EXTENSION_TYPE_MAP = {
    '.jpg': 'image', '.jpeg': 'image', '.png': 'image', '.gif': 'image',
    '.bmp': 'image', '.ico': 'image', '.webp': 'image', '.svg': 'image',
    '.pdf': 'document', '.doc': 'document', '.docx': 'document',
    '.xls': 'spreadsheet', '.xlsx': 'spreadsheet',
    '.ppt': 'presentation', '.pptx': 'presentation',
    '.exe': 'executable', '.dll': 'executable', '.sys': 'executable',
    '.bat': 'script', '.cmd': 'script', '.ps1': 'script', '.sh': 'script',
    '.py': 'script', '.js': 'script', '.vbs': 'script',
    '.zip': 'archive', '.rar': 'archive', '.7z': 'archive',
    '.gz': 'archive', '.tar': 'archive', '.bz2': 'archive',
    '.mp3': 'audio', '.wav': 'audio', '.flac': 'audio', '.ogg': 'audio',
    '.mp4': 'video', '.avi': 'video', '.mkv': 'video', '.mov': 'video',
    '.txt': 'text', '.csv': 'text', '.log': 'text', '.json': 'text',
    '.html': 'web', '.htm': 'web', '.xml': 'web', '.css': 'web',
}

DANGEROUS_REAL_TYPES = {
    'Windows Executable (PE)', 'ELF Executable (Linux)',
    'Mach-O Executable (macOS)', 'Mach-O Executable (macOS, 64-bit)',
}

# ─── IOC regexes ─────────────────────────────────────────────────────────
_RE_URL = re.compile(r'https?://[^\s<>"\']{4,200}')
_RE_EMAIL = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_RE_IP4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|co|gov|edu|mil|int|info|biz|name|mobi|'
    r'xyz|app|dev|cloud|online|site|tech|ai|cc|uk|de|fr|ru|cn|'
    r'jp|au|ca|br|in|nl|se|no|fi|dk|pl|it|es)\b',
    re.IGNORECASE,
)
_RE_MD5 = re.compile(r'\b[0-9a-fA-F]{32}\b')
_RE_SHA1 = re.compile(r'\b[0-9a-fA-F]{40}\b')
_RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')

# Private/loopback IPs to skip during IOC extraction
_PRIVATE_IP_PREFIXES = ('127.', '0.', '10.', '172.16.', '172.17.', '172.18.',
                         '172.19.', '172.2', '172.3', '192.168.', '255.')


# ─── Public API ───────────────────────────────────────────────────────────

def compute_hashes(filepath: str) -> Dict[str, str]:
    """MD5 + SHA-1 + SHA-256 of file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
    }


def detect_file_type(filepath: str) -> Dict[str, Any]:
    """Detect actual file type using magic bytes."""
    with open(filepath, 'rb') as f:
        header = f.read(32)

    for sig, (file_type, ext) in sorted(MAGIC_SIGNATURES.items(), key=lambda x: -len(x[0])):
        if header[:len(sig)] == sig:
            return {
                'detected_type': file_type,
                'detected_extension': ext,
                'magic_bytes': header[:len(sig)].hex(),
                'match_confidence': 'high',
            }

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            f.read(1024)
        return {
            'detected_type': 'Plain Text / Script',
            'detected_extension': '.txt',
            'magic_bytes': header[:8].hex(),
            'match_confidence': 'medium',
        }
    except (UnicodeDecodeError, ValueError):
        return {
            'detected_type': 'Unknown Binary',
            'detected_extension': 'unknown',
            'magic_bytes': header[:8].hex(),
            'match_confidence': 'low',
        }


def calculate_entropy(filepath: str) -> Dict[str, Any]:
    """Shannon entropy of file contents."""
    with open(filepath, 'rb') as f:
        data = f.read()
    if not data:
        return {'entropy': 0.0, 'assessment': 'Empty file', 'risk_level': 'info'}

    counts = Counter(data)
    total = len(data)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())

    if entropy > 7.9:
        return {'entropy': round(entropy, 4), 'max_possible': 8.0,
                'assessment': 'Very high entropy — likely encrypted, compressed, or packed',
                'risk_level': 'high'}
    if entropy > 7.0:
        return {'entropy': round(entropy, 4), 'max_possible': 8.0,
                'assessment': 'High entropy — possibly compressed or obfuscated',
                'risk_level': 'medium'}
    if entropy > 5.0:
        return {'entropy': round(entropy, 4), 'max_possible': 8.0,
                'assessment': 'Moderate entropy — typical for compiled binaries or mixed content',
                'risk_level': 'low'}
    if entropy > 3.0:
        return {'entropy': round(entropy, 4), 'max_possible': 8.0,
                'assessment': 'Low-moderate entropy — typical for text or structured data',
                'risk_level': 'info'}
    return {'entropy': round(entropy, 4), 'max_possible': 8.0,
            'assessment': 'Low entropy — highly structured or repetitive data',
            'risk_level': 'info'}


def extract_metadata(filepath: str) -> Dict[str, Any]:
    """Filesystem metadata + EXIF/PDF + IOC strings."""
    stat = os.stat(filepath)
    filename = os.path.basename(filepath)
    _, ext = os.path.splitext(filename)

    meta: Dict[str, Any] = {
        'filename': filename,
        'extension': ext.lower(),
        'file_size_bytes': stat.st_size,
        'file_size_human': _human_size(stat.st_size),
        'created': datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'accessed': datetime.datetime.fromtimestamp(stat.st_atime).isoformat(),
    }

    exif = _extract_exif(filepath, ext.lower())
    if exif:
        meta['exif'] = exif

    if ext.lower() == '.pdf':
        pdf_meta = _extract_pdf_metadata(filepath)
        if pdf_meta:
            meta['pdf_metadata'] = pdf_meta

    iocs = _extract_iocs(filepath)
    if iocs:
        meta['notable_strings'] = iocs

    return meta


def check_anomalies(filepath: str, file_type_info: Dict, metadata: Dict,
                    entropy_info: Dict) -> List[Dict]:
    """Flag suspicious anomalies."""
    anomalies = []
    ext = metadata.get('extension', '').lower()
    detected = file_type_info.get('detected_type', '')

    if ext and ext != file_type_info.get('detected_extension', ''):
        is_dangerous = detected in DANGEROUS_REAL_TYPES
        anomalies.append({
            'type': 'EXTENSION_MISMATCH',
            'severity': 'critical' if is_dangerous else 'warning',
            'title': 'File Extension Mismatch',
            'detail': f'File claims to be "{ext}" but magic bytes indicate "{detected}".',
            'recommendation': (
                'Do not open this file. The extension has been changed to disguise its true type.'
                if is_dangerous else
                'Verify the file origin. The extension does not match the actual content.'
            ),
        })

    if detected in DANGEROUS_REAL_TYPES and ext not in ('.exe', '.dll', '.sys', '.elf', '.macho'):
        anomalies.append({
            'type': 'HIDDEN_EXECUTABLE',
            'severity': 'critical',
            'title': 'Hidden Executable Detected',
            'detail': f'This file is actually a "{detected}" disguised with a "{ext}" extension.',
            'recommendation': 'DANGER: This file is a disguised executable. Quarantine immediately.',
        })

    if entropy_info.get('entropy', 0) > 7.9:
        anomalies.append({
            'type': 'HIGH_ENTROPY',
            'severity': 'warning',
            'title': 'Extremely High Entropy',
            'detail': f'Entropy of {entropy_info["entropy"]} suggests encryption, packing, or steganography.',
            'recommendation': 'Investigate whether this file has been encrypted or packed to evade detection.',
        })

    basename = os.path.basename(filepath)
    parts = basename.split('.')
    if len(parts) > 2:
        anomalies.append({
            'type': 'DOUBLE_EXTENSION',
            'severity': 'warning',
            'title': 'Multiple File Extensions',
            'detail': f'File has multiple extensions: {".".join(parts[1:])}.',
            'recommendation': 'Multiple extensions can be used to trick users. Verify the file type.',
        })

    if metadata.get('file_size_bytes', 0) == 0:
        anomalies.append({
            'type': 'ZERO_BYTE',
            'severity': 'info',
            'title': 'Zero-Byte File',
            'detail': 'This file contains no data.',
            'recommendation': 'Empty files may indicate failed transfers or evidence tampering.',
        })

    try:
        created = datetime.datetime.fromisoformat(metadata.get('created', ''))
        modified = datetime.datetime.fromisoformat(metadata.get('modified', ''))
        if created > modified:
            anomalies.append({
                'type': 'TIMESTAMP_ANOMALY',
                'severity': 'warning',
                'title': 'Timestamp Inconsistency',
                'detail': 'File creation date is later than modification date.',
                'recommendation': 'Timestamps may have been altered.',
            })
    except (ValueError, TypeError):
        pass

    return anomalies


def run_yara(filepath: str) -> List[Dict]:
    """Scan file with bundled YARA rules. Returns list of matches."""
    try:
        import yara  # type: ignore
        rules_path = Path(__file__).parent / 'yara_rules' / 'community.yar'
        if not rules_path.exists():
            return []
        rules = yara.compile(str(rules_path))
        matches = rules.match(filepath)
        return [
            {
                'rule': m.rule,
                'tags': list(m.tags),
                'meta': dict(m.meta),
                'strings': [
                    {'offset': s.instances[0].offset if s.instances else 0,
                     'identifier': s.identifier,
                     'data': s.instances[0].matched_data.hex() if s.instances else ''}
                    for s in m.strings[:5]
                ],
            }
            for m in matches
        ]
    except ImportError:
        return []
    except Exception:
        return []


def analyze_file(filepath: str) -> Dict[str, Any]:
    """Full forensic analysis. 100% API-compatible with Forenstix v1."""
    results: Dict[str, Any] = {
        'analysis_timestamp': datetime.datetime.now().isoformat(),
        'tool': 'FORENSTIX v2.0',
    }

    results['hashes'] = compute_hashes(filepath)
    results['file_type'] = detect_file_type(filepath)
    results['entropy'] = calculate_entropy(filepath)
    results['metadata'] = extract_metadata(filepath)
    results['anomalies'] = check_anomalies(
        filepath,
        results['file_type'],
        results['metadata'],
        results['entropy'],
    )

    # YARA scan (new in v2)
    yara_hits = run_yara(filepath)
    if yara_hits:
        results['yara_matches'] = yara_hits
        results['anomalies'].append({
            'type': 'YARA_MATCH',
            'severity': 'critical',
            'title': f'YARA Rule Match ({len(yara_hits)} rule{"s" if len(yara_hits) > 1 else ""})',
            'detail': ', '.join(m['rule'] for m in yara_hits),
            'recommendation': 'YARA rules matched known malware patterns. Treat as hostile.',
        })

    results['risk_score'] = _calculate_risk_score(results)
    return results


# ─── Private helpers ─────────────────────────────────────────────────────

def _human_size(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f'{size_bytes:.1f} {unit}'
        size_bytes //= 1024
    return f'{size_bytes:.1f} PB'


def _extract_iocs(filepath: str) -> Optional[Dict[str, List]]:
    """Extract URLs, emails, IPs, domains, and embedded hashes."""
    try:
        with open(filepath, 'rb') as f:
            raw = f.read(2097152)  # 2 MB
        text = raw.decode('ascii', errors='ignore')
    except Exception:
        return None

    # URLs
    urls = list(dict.fromkeys(_RE_URL.findall(text)))[:15]

    # Emails
    emails = list(dict.fromkeys(_RE_EMAIL.findall(text)))[:15]

    # IPs (exclude private / special)
    raw_ips = _RE_IP4.findall(text)
    ips = []
    seen_ips: set = set()
    for ip in raw_ips:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            if not any(ip.startswith(p) for p in _PRIVATE_IP_PREFIXES) and ip not in seen_ips:
                ips.append(ip)
                seen_ips.add(ip)
        if len(ips) >= 15:
            break

    # Domains (strip those already in URLs/emails to avoid duplication)
    url_hosts = set()
    for u in urls:
        m = re.match(r'https?://([^/?\s:]+)', u)
        if m:
            url_hosts.add(m.group(1).lower())
    email_domains = {e.split('@')[1].lower() for e in emails if '@' in e}

    raw_domains = _RE_DOMAIN.findall(text)
    domains = []
    seen_dom: set = set()
    for d in raw_domains:
        dl = d.lower()
        if dl not in url_hosts and dl not in email_domains and dl not in seen_dom:
            domains.append(d)
            seen_dom.add(dl)
        if len(domains) >= 15:
            break

    # Embedded hashes (exclude the file's own hashes computed separately)
    sha256s = list(dict.fromkeys(_RE_SHA256.findall(text)))[:5]
    sha1s = [h for h in list(dict.fromkeys(_RE_SHA1.findall(text)))[:5] if h not in sha256s]
    md5s = [h for h in list(dict.fromkeys(_RE_MD5.findall(text)))[:5]
            if h not in sha256s and h not in sha1s]

    result = {}
    if urls:
        result['urls'] = urls
    if emails:
        result['emails'] = emails
    if ips:
        result['ip_addresses'] = ips
    if domains:
        result['domains'] = domains
    if sha256s:
        result['hashes_sha256'] = sha256s
    if sha1s:
        result['hashes_sha1'] = sha1s
    if md5s:
        result['hashes_md5'] = md5s

    return result or None


def _extract_exif(filepath: str, ext: str) -> Optional[Dict]:
    if ext not in ('.jpg', '.jpeg'):
        return None
    exif: Dict = {}
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        if b'Exif' not in data[:100]:
            return None
        region = data[:min(65536, len(data))]
        for tag in [b'Make', b'Model', b'Software', b'DateTime', b'Artist',
                    b'Copyright', b'ImageDescription']:
            idx = region.find(tag)
            if idx != -1:
                vs = idx + len(tag) + 1
                ve = region.find(b'\x00', vs)
                if ve != -1 and ve - vs < 200:
                    try:
                        val = region[vs:ve].decode('ascii', errors='ignore').strip()
                        if val and val.isprintable():
                            exif[tag.decode()] = val
                    except Exception:
                        pass
        if b'GPS' in region:
            exif['gps_data_present'] = True
    except Exception:
        pass
    return exif if exif else None


def _extract_pdf_metadata(filepath: str) -> Optional[Dict]:
    meta: Dict = {}
    try:
        with open(filepath, 'rb') as f:
            data = f.read(8192).decode('latin-1', errors='ignore')
        for field in ['Title', 'Author', 'Creator', 'Producer', 'CreationDate', 'ModDate']:
            marker = f'/{field}'
            idx = data.find(marker)
            if idx != -1:
                ps = data.find('(', idx)
                pe = data.find(')', ps + 1) if ps != -1 else -1
                if ps != -1 and pe != -1 and pe - ps < 300:
                    val = data[ps + 1:pe].strip()
                    if val:
                        meta[field] = val
    except Exception:
        pass
    return meta if meta else None


def _calculate_risk_score(results: Dict) -> Dict[str, Any]:
    score = 0
    for anomaly in results.get('anomalies', []):
        score += {'critical': 35, 'warning': 15, 'info': 5}.get(anomaly['severity'], 0)

    entropy = results.get('entropy', {}).get('entropy', 0)
    if entropy > 7.9:
        score += 15
    elif entropy > 7.0:
        score += 8

    if results.get('file_type', {}).get('detected_type', '') in DANGEROUS_REAL_TYPES:
        score += 10

    score = min(score, 100)
    label = 'CLEAN'
    if score >= 70:
        label = 'CRITICAL'
    elif score >= 40:
        label = 'SUSPICIOUS'
    elif score >= 15:
        label = 'CAUTION'

    return {'score': score, 'label': label}
