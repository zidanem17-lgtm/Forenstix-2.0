/*
 * FORENSTIX 2.0 — Bundled YARA Detection Rules
 *
 * Community patterns for common malware indicators.
 * Add your own rules below — any valid YARA syntax is supported.
 *
 * Sources / attribution:
 *   - YARA-Rules project (GPL-2.0) — https://github.com/Yara-Rules/rules
 *   - Neo23x0 signature-base (LGPL-2.1) — https://github.com/Neo23x0/signature-base
 *   - Custom Forenstix patterns
 */


// ─── Executable disguised as non-executable ──────────────────────────────

rule Hidden_PE_Executable {
    meta:
        description = "Windows PE executable without .exe/.dll extension"
        severity    = "critical"
        category    = "masquerading"
    strings:
        $mz = { 4D 5A }   // MZ header
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe
}

rule Hidden_ELF_Executable {
    meta:
        description = "ELF binary (Linux/Android) without typical executable extension"
        severity    = "critical"
        category    = "masquerading"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0
}


// ─── Obfuscation and packing ──────────────────────────────────────────────

rule Packed_UPX {
    meta:
        description = "UPX packed binary"
        severity    = "medium"
        category    = "packing"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        any of them
}

rule Base64_Encoded_Executable {
    meta:
        description = "Base64-encoded PE or ELF payload"
        severity    = "high"
        category    = "obfuscation"
    strings:
        $b64_mz  = "TVqQAAMAAAAEAAAA" ascii  // MZ base64
        $b64_elf = "f0VMRg" ascii             // ELF base64
    condition:
        any of them
}

rule Powershell_Base64_Encoded_Command {
    meta:
        description = "PowerShell -EncodedCommand execution"
        severity    = "high"
        category    = "obfuscation"
    strings:
        $enc1 = "-EncodedCommand" nocase ascii
        $enc2 = "-enc " nocase ascii
        $enc3 = "-e " nocase ascii
        $ps   = "powershell" nocase ascii
    condition:
        $ps and any of ($enc1, $enc2, $enc3)
}

rule Powershell_Download_Cradle {
    meta:
        description = "PowerShell download cradle (IEX / DownloadString / WebClient)"
        severity    = "high"
        category    = "dropper"
    strings:
        $iex    = "IEX(" nocase ascii
        $iex2   = "Invoke-Expression" nocase ascii
        $dl     = "DownloadString" nocase ascii
        $wc     = "WebClient" nocase ascii
        $bitsad = "BitsTransfer" nocase ascii
    condition:
        ($iex or $iex2) and ($dl or $wc or $bitsad)
}

rule VBA_AutoOpen_Macro {
    meta:
        description = "Office document with AutoOpen/AutoExec macro"
        severity    = "high"
        category    = "macro"
    strings:
        $ao1 = "AutoOpen" ascii nocase
        $ao2 = "AutoExec" ascii nocase
        $ao3 = "Document_Open" ascii nocase
        $ao4 = "Workbook_Open" ascii nocase
        $shell = "Shell(" ascii nocase
        $wscript = "WScript.Shell" ascii nocase
    condition:
        any of ($ao1, $ao2, $ao3, $ao4) and any of ($shell, $wscript)
}


// ─── Webshells ─────────────────────────────────────────────────────────────

rule PHP_Webshell_Generic {
    meta:
        description = "PHP webshell — eval(base64_decode) or system/exec via $_REQUEST"
        severity    = "critical"
        category    = "webshell"
    strings:
        $eval_b64 = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $req_exec = /\$_(REQUEST|POST|GET|COOKIE)\s*\[.{1,30}\]\s*\)/ nocase
        $sys      = /system\s*\(/ nocase
        $passthru = /passthru\s*\(/ nocase
        $exec     = /exec\s*\(/ nocase
    condition:
        $eval_b64 or ($req_exec and any of ($sys, $passthru, $exec))
}

rule ASPX_Webshell_Generic {
    meta:
        description = "ASPX webshell — Process.Start or cmd.exe invocation"
        severity    = "critical"
        category    = "webshell"
    strings:
        $proc  = "Process.Start" ascii
        $cmd   = "cmd.exe" ascii nocase
        $shell = "Shell(" ascii nocase
        $aspx  = "<%@" ascii
    condition:
        $aspx and ($proc or $cmd or $shell)
}


// ─── Credential theft ─────────────────────────────────────────────────────

rule Mimikatz_Strings {
    meta:
        description = "Mimikatz credential dumping tool"
        severity    = "critical"
        category    = "credential_theft"
        author      = "Florian Roth"
    strings:
        $mimi1 = "sekurlsa::logonpasswords" nocase ascii
        $mimi2 = "privilege::debug" nocase ascii
        $mimi3 = "lsadump::sam" nocase ascii
        $mimi4 = "mimikatz" nocase ascii
        $mimi5 = "mimilib" ascii
    condition:
        2 of them
}

rule Credential_File_References {
    meta:
        description = "References to SAM, NTDS, or LSA credential stores"
        severity    = "high"
        category    = "credential_theft"
    strings:
        $sam   = "\\SAM" ascii nocase
        $ntds  = "ntds.dit" ascii nocase
        $lsa   = "\\lsa" ascii nocase
        $shadow = "\\System32\\config\\SYSTEM" ascii nocase
    condition:
        any of them
}


// ─── Network C2 indicators ─────────────────────────────────────────────────

rule Hardcoded_IP_Port_Beacon {
    meta:
        description = "Hard-coded IP:port pattern typical of C2 beacons"
        severity    = "medium"
        category    = "c2"
    strings:
        $ip_port = /\b(?:\d{1,3}\.){3}\d{1,3}:\d{4,5}\b/
    condition:
        #ip_port > 3
}

rule Tor_Exit_Node_Reference {
    meta:
        description = "Reference to .onion address (Tor hidden service)"
        severity    = "medium"
        category    = "c2"
    strings:
        $onion = /[a-z2-7]{16,56}\.onion/ nocase
    condition:
        $onion
}


// ─── Ransomware indicators ─────────────────────────────────────────────────

rule Ransomware_Extension_Rename {
    meta:
        description = "Common ransomware ransom note filenames"
        severity    = "critical"
        category    = "ransomware"
    strings:
        $note1 = "YOUR_FILES_ARE_ENCRYPTED" nocase ascii
        $note2 = "HOW_TO_DECRYPT" nocase ascii
        $note3 = "RECOVER_FILES" nocase ascii
        $note4 = "README_DECRYPT" nocase ascii
        $note5 = "DECRYPT_INSTRUCTIONS" nocase ascii
        $note6 = "!!!RESTORE" nocase ascii
    condition:
        any of them
}

rule Ransomware_Crypto_API {
    meta:
        description = "Combination of crypto API and file enumeration typical of ransomware"
        severity    = "high"
        category    = "ransomware"
    strings:
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "CryptGenKey" ascii
        $crypt3 = "CryptImportKey" ascii
        $enum1  = "FindFirstFileW" ascii
        $enum2  = "FindNextFileW" ascii
    condition:
        (any of ($crypt1, $crypt2, $crypt3)) and (any of ($enum1, $enum2))
}


// ─── Suspicious scripting ─────────────────────────────────────────────────

rule Suspicious_JS_Eval_Obfuscation {
    meta:
        description = "JavaScript eval() with encoded/split string — common obfuscation pattern"
        severity    = "medium"
        category    = "obfuscation"
    strings:
        $eval   = /eval\s*\(/ ascii
        $split  = /\.split\s*\(/ ascii
        $join   = /\.join\s*\(/ ascii
        $chcode = /fromCharCode/ ascii
    condition:
        $eval and (2 of ($split, $join, $chcode))
}

rule Batch_Script_Persistence {
    meta:
        description = "Batch script writing to HKLM Run key (persistence)"
        severity    = "high"
        category    = "persistence"
    strings:
        $reg1 = "reg add" nocase ascii
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii
        $run2 = "CurrentVersion\\Run" nocase ascii
    condition:
        $reg1 and any of ($run1, $run2)
}


// ─── Data exfiltration ────────────────────────────────────────────────────

rule DNS_Tunneling_Pattern {
    meta:
        description = "Suspiciously long DNS query strings — possible DNS tunneling"
        severity    = "medium"
        category    = "exfiltration"
    strings:
        $long_subdomain = /[a-zA-Z0-9]{40,}\./ ascii
    condition:
        #long_subdomain > 5
}

rule Embedded_SSH_Private_Key {
    meta:
        description = "Embedded RSA/EC/Ed25519 private key"
        severity    = "high"
        category    = "credential_leak"
    strings:
        $rsa  = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $ec   = "-----BEGIN EC PRIVATE KEY-----" ascii
        $pem  = "-----BEGIN PRIVATE KEY-----" ascii
        $ed   = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
    condition:
        any of them
}

rule AWS_Access_Key_Hardcoded {
    meta:
        description = "Hardcoded AWS access key ID pattern"
        severity    = "high"
        category    = "credential_leak"
    strings:
        $aws = /AKIA[0-9A-Z]{16}/ ascii
    condition:
        $aws
}
