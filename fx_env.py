"""
fx_env.py — Forenstix-2.0 environment detection

Determines which execution backend to use and what package managers are
available for native/WSL installs.  The result is a singleton returned by
:func:`detect` that every other module can import without re-running probes.

Backends (in preference order when Docker is present):
  docker  — docker run --rm <image> <args>
  wsl     — wsl -d <distro> -- bash -lc <cmd>
  native  — bash -lc <cmd>   (Linux/macOS)
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Environment:
    backend: str                        # "docker" | "wsl" | "native"
    os_name: str                        # "linux" | "macos" | "windows"
    wsl_distro: Optional[str] = None    # e.g. "kali-linux", "Ubuntu"
    docker_available: bool = False
    docker_version: Optional[str] = None
    sudo_available: bool = False
    package_managers: List[str] = field(default_factory=list)
    python: str = sys.executable
    go_available: bool = False
    cargo_available: bool = False
    ruby_available: bool = False
    node_available: bool = False

    def as_dict(self) -> dict:
        return {
            "backend": self.backend,
            "os": self.os_name,
            "wsl_distro": self.wsl_distro,
            "docker": self.docker_available,
            "docker_version": self.docker_version,
            "sudo": self.sudo_available,
            "package_managers": self.package_managers,
            "go": self.go_available,
            "cargo": self.cargo_available,
            "ruby": self.ruby_available,
            "node": self.node_available,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str], timeout: int = 5) -> Optional[str]:
    """Run a command and return stdout, or None on failure."""
    try:
        r = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        return r.stdout.decode(errors="replace").strip() if r.returncode == 0 else None
    except Exception:
        return None


def _cmd_exists(name: str) -> bool:
    return shutil.which(name) is not None


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def _detect_os() -> str:
    s = platform.system().lower()
    if s == "linux":
        return "linux"
    if s == "darwin":
        return "macos"
    if s == "windows":
        return "windows"
    return s


def _detect_wsl_distro() -> Optional[str]:
    """Return the name of the first non-default WSL distro, or None."""
    if _detect_os() != "windows":
        # On Linux inside WSL, /proc/version contains "microsoft"
        try:
            pv = Path("/proc/version").read_text(errors="replace").lower()
            if "microsoft" in pv:
                # We *are* inside WSL — read distro name from /etc/os-release
                for line in Path("/etc/os-release").read_text(errors="replace").splitlines():
                    if line.startswith("NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return None

    out = _run(["wsl", "--list", "--quiet"])
    if out:
        distros = [d.strip() for d in out.splitlines() if d.strip()]
        # prefer kali, then ubuntu, then whatever is first
        for preferred in ("kali-linux", "Ubuntu", "Debian"):
            for d in distros:
                if preferred.lower() in d.lower():
                    return d
        if distros:
            return distros[0]
    return None


def _detect_docker() -> tuple[bool, Optional[str]]:
    """Return (available, version_string)."""
    if not _cmd_exists("docker"):
        return False, None
    out = _run(["docker", "version", "--format", "{{.Server.Version}}"])
    if out:
        return True, out
    # daemon not running — still usable for our purposes only if it can start
    return False, None


def _detect_sudo() -> bool:
    if _detect_os() == "windows":
        return False
    # Check if sudo exists and we either have NOPASSWD or are already root
    if not _cmd_exists("sudo"):
        return False
    if os.geteuid() == 0:
        return True
    out = _run(["sudo", "-n", "true"])
    return out is not None


def _detect_package_managers() -> List[str]:
    candidates = [
        "apt-get", "apt", "brew", "dnf", "yum", "pacman",
        "apk", "zypper", "pip3", "pip", "gem", "go", "cargo", "npm",
    ]
    return [c for c in candidates if _cmd_exists(c)]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def detect() -> Environment:
    """Probe the host and return a cached :class:`Environment`."""
    os_name = _detect_os()
    docker_ok, docker_ver = _detect_docker()
    wsl_distro = _detect_wsl_distro()

    # Choose backend
    if docker_ok:
        backend = "docker"
    elif wsl_distro and os_name == "windows":
        backend = "wsl"
    else:
        backend = "native"

    env = Environment(
        backend=backend,
        os_name=os_name,
        wsl_distro=wsl_distro,
        docker_available=docker_ok,
        docker_version=docker_ver,
        sudo_available=_detect_sudo(),
        package_managers=_detect_package_managers(),
        go_available=_cmd_exists("go"),
        cargo_available=_cmd_exists("cargo"),
        ruby_available=_cmd_exists("ruby"),
        node_available=_cmd_exists("node") or _cmd_exists("nodejs"),
    )
    return env


def main() -> None:
    import json as _json
    print(_json.dumps(detect().as_dict(), indent=2))


if __name__ == "__main__":
    main()
