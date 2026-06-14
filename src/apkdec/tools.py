"""Management of the optional external decompilers (jadx, apktool).

Full Java-source / smali decompilation is delegated to mature JVM tools. This
module locates a Java runtime, downloads the tools on demand into a per-user
cache, and exposes their executables. Everything degrades gracefully with clear,
platform-specific guidance when Java is missing.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional, Tuple

# Pinned fallback versions used when the GitHub "latest" API is unreachable
# (e.g. offline, or rate-limited). Kept current but intentionally overridable.
_JADX_FALLBACK = "1.5.1"
_APKTOOL_FALLBACK = "2.10.0"

_USER_AGENT = "apkdec (+https://github.com/)"


def cache_dir() -> Path:
    """Return the per-user cache directory, honouring APKDEC_HOME."""
    override = os.environ.get("APKDEC_HOME")
    base = Path(override) if override else Path.home() / ".apkdec"
    return base


def tools_dir() -> Path:
    d = cache_dir() / "tools"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Java detection
# ---------------------------------------------------------------------------
def find_java() -> Optional[str]:
    """Return a path to a usable ``java`` executable, or ``None``."""
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
        if candidate.exists():
            return str(candidate)
    return shutil.which("java")


def java_version(java: str) -> str:
    try:
        proc = subprocess.run(
            [java, "-version"], capture_output=True, text=True, timeout=15
        )
        # ``java -version`` prints to stderr.
        first = (proc.stderr or proc.stdout).splitlines()
        return first[0].strip() if first else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def java_install_hint() -> str:
    system = platform.system()
    if system == "Darwin":
        return (
            "Java not found. Install a JDK (17+ recommended):\n"
            "  brew install openjdk\n"
            "  sudo ln -sfn $(brew --prefix)/opt/openjdk/libexec/openjdk.jdk "
            "/Library/Java/JavaVirtualMachines/openjdk.jdk\n"
            "Or download from https://adoptium.net/"
        )
    if system == "Windows":
        return (
            "Java not found. Install a JDK (17+ recommended):\n"
            "  winget install Microsoft.OpenJDK.17\n"
            "Or download from https://adoptium.net/ , then reopen your terminal."
        )
    return (
        "Java not found. Install a JDK (17+ recommended):\n"
        "  sudo apt install default-jdk      # Debian/Ubuntu\n"
        "  sudo dnf install java-17-openjdk  # Fedora\n"
        "Or download from https://adoptium.net/"
    )


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------
def _http_get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _download(url: str, dest: Path) -> None:
    """Stream ``url`` to ``dest`` with a simple progress indicator."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(req, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        done = 0
        block = 1024 * 64
        with open(tmp, "wb") as fh:
            while True:
                chunk = resp.read(block)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if total:
                    pct = done * 100 // total
                    sys.stderr.write(
                        "\r  downloading %s ... %3d%% (%d/%d KiB)"
                        % (dest.name, pct, done // 1024, total // 1024)
                    )
                else:
                    sys.stderr.write("\r  downloading %s ... %d KiB" % (dest.name, done // 1024))
                sys.stderr.flush()
    sys.stderr.write("\n")
    tmp.replace(dest)


def _latest_release_asset(repo: str, suffix: str) -> Optional[Tuple[str, str]]:
    """Look up the latest GitHub release asset whose name ends with ``suffix``.

    Returns ``(version_tag, download_url)`` or ``None`` on any failure.
    """
    url = "https://api.github.com/repos/%s/releases/latest" % repo
    try:
        data = json.loads(_http_get(url).decode("utf-8"))
    except (urllib.error.URLError, ValueError, OSError):
        return None
    tag = data.get("tag_name", "")
    for asset in data.get("assets", []):
        name = asset.get("name", "")
        if name.endswith(suffix):
            return tag, asset["browser_download_url"]
    return None


# ---------------------------------------------------------------------------
# jadx
# ---------------------------------------------------------------------------
def jadx_executable() -> Optional[Path]:
    """Return the path to an installed jadx launcher, if present."""
    for base in sorted(tools_dir().glob("jadx-*"), reverse=True):
        launcher = base / "bin" / ("jadx.bat" if os.name == "nt" else "jadx")
        if launcher.exists():
            return launcher
    return None


def ensure_jadx() -> Path:
    """Download and unpack jadx if needed; return its launcher path."""
    existing = jadx_executable()
    if existing:
        return existing

    asset = _latest_release_asset("skylot/jadx", ".zip")
    if asset:
        tag, dl_url = asset
        version = tag.lstrip("v")
    else:
        version = _JADX_FALLBACK
        dl_url = (
            "https://github.com/skylot/jadx/releases/download/"
            "v%s/jadx-%s.zip" % (version, version)
        )

    archive = tools_dir() / ("jadx-%s.zip" % version)
    target = tools_dir() / ("jadx-%s" % version)
    _download(dl_url, archive)
    with zipfile.ZipFile(archive, "r") as zf:
        zf.extractall(target)
    archive.unlink(missing_ok=True)

    launcher = target / "bin" / ("jadx.bat" if os.name == "nt" else "jadx")
    if not launcher.exists():
        raise RuntimeError("jadx launcher not found after extraction: %s" % launcher)
    if os.name != "nt":
        _make_executable(launcher)
    return launcher


# ---------------------------------------------------------------------------
# apktool
# ---------------------------------------------------------------------------
def apktool_jar() -> Optional[Path]:
    jars = sorted(tools_dir().glob("apktool-*.jar"), reverse=True)
    return jars[0] if jars else None


def ensure_apktool() -> Path:
    """Download the apktool jar if needed; return its path."""
    existing = apktool_jar()
    if existing:
        return existing

    asset = _latest_release_asset("iBotPeaches/Apktool", ".jar")
    if asset:
        tag, dl_url = asset
        version = tag.lstrip("v")
    else:
        version = _APKTOOL_FALLBACK
        dl_url = (
            "https://github.com/iBotPeaches/Apktool/releases/download/"
            "v%s/apktool_%s.jar" % (version, version)
        )

    dest = tools_dir() / ("apktool-%s.jar" % version)
    _download(dl_url, dest)
    return dest


def _make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
