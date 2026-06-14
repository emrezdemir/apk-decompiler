"""Orchestrates full decompilation by driving the external JVM tools."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from . import tools


class DecompileError(Exception):
    """Raised when a decompilation engine fails or cannot be run."""


def _require_java() -> str:
    java = tools.find_java()
    if not java:
        raise DecompileError(tools.java_install_hint())
    return java


def run_jadx(apk: str, out_dir: str, extra_args=None) -> int:
    """Decompile ``apk`` to Java source with jadx into ``out_dir``."""
    _require_java()
    launcher = tools.ensure_jadx()
    cmd = [str(launcher), "-d", out_dir]
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(apk)
    return _run(cmd)


def run_apktool(apk: str, out_dir: str, extra_args=None) -> int:
    """Decode ``apk`` to smali + resources with apktool into ``out_dir``."""
    java = _require_java()
    jar = tools.ensure_apktool()
    cmd = [java, "-jar", str(jar), "d", "-f", "-o", out_dir]
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(apk)
    return _run(cmd)


def _run(cmd) -> int:
    """Run a subprocess, streaming its output, returning the exit code."""
    sys.stderr.write("  running: %s\n" % " ".join(_quote(c) for c in cmd))
    sys.stderr.flush()
    try:
        proc = subprocess.run(cmd)
    except FileNotFoundError as exc:
        raise DecompileError("could not launch tool: %s" % exc) from exc
    return proc.returncode


def _quote(token: str) -> str:
    token = str(token)
    return '"%s"' % token if " " in token else token
