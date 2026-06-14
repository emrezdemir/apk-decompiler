"""Static security analysis of an APK for defensive / educational review.

This produces the kind of quick triage a security reviewer wants before diving
into full decompilation: manifest hardening issues, the exported attack surface,
risky permissions, weak signing, and obvious hardcoded secrets in the bytecode.

It is intentionally heuristic and read-only. Findings are starting points for
manual review, not proof of a vulnerability. Only analyze software you are
authorized to assess (see DISCLAIMER.md).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List

from . import apk, axml

_ANDROID = "{%s}" % axml.ANDROID_NS

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Android "dangerous" / high-impact permissions worth calling out.
_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.BODY_SENSORS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.WRITE_SETTINGS",
}

# High-signal secret patterns. Each entry: (severity, label, compiled regex).
_SECRET_PATTERNS = [
    ("high", "Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("high", "AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("high", "Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("high", "Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("high", "GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("medium", "Stripe secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("medium", "Firebase database URL", re.compile(r"https?://[a-z0-9.-]+\.firebaseio\.com")),
    ("medium", "JSON Web Token (JWT)", re.compile(r"eyJ[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_=-]{8,}\.[A-Za-z0-9_=-]{6,}")),
]

_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]{6,}")
_URL_IGNORE = re.compile(
    r"(schemas\.android\.com|w3\.org|apache\.org|java\.sun\.com|"
    r"xmlpull\.org|googleapis\.com/auth|bouncycastle\.org|json\.org|"
    r"example\.com|github\.com/[A-Za-z]|developer\.android\.com)"
)

_MAX_EXAMPLES = 15


@dataclass
class Finding:
    """A single security observation."""

    severity: str  # high | medium | low | info
    title: str
    detail: str


def analyze(path: str) -> List[Finding]:
    """Run all checks and return findings sorted by severity (worst first)."""
    findings: List[Finding] = []

    try:
        root = ET.fromstring(apk.decode_manifest(path))
    except (apk.ApkError, ET.ParseError, axml.AXMLError):
        root = None

    info = apk.get_info(path)

    if root is not None:
        findings += _check_manifest(root, info)
    findings += _check_signing(info)

    try:
        strings = apk.dump_strings(path, min_len=6)
    except apk.ApkError:
        strings = []
    findings += _scan_secrets(strings)

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return findings


def _bool_attr(elem, name: str):
    value = elem.get(_ANDROID + name)
    if value is None:
        return None
    return value == "true"


def _min_sdk_int(info: "apk.ApkInfo") -> int:
    try:
        return int(info.min_sdk)
    except (TypeError, ValueError):
        return 0


def _check_manifest(root, info) -> List[Finding]:
    findings: List[Finding] = []
    app = root.find("application")
    min_sdk = _min_sdk_int(info)

    if app is not None:
        if _bool_attr(app, "debuggable"):
            findings.append(
                Finding(
                    "high",
                    "Application is debuggable",
                    "android:debuggable=\"true\" lets anyone attach a debugger and "
                    "run code in the app's context. Must never ship in release builds.",
                )
            )

        backup = _bool_attr(app, "allowBackup")
        if backup is True or (backup is None and min_sdk and min_sdk < 31):
            findings.append(
                Finding(
                    "medium",
                    "Backups allowed",
                    "android:allowBackup is enabled (explicitly or by default). App "
                    "data can be extracted via `adb backup` on many devices.",
                )
            )

        if _bool_attr(app, "usesCleartextTraffic") is True:
            findings.append(
                Finding(
                    "medium",
                    "Cleartext traffic allowed",
                    "android:usesCleartextTraffic=\"true\" permits unencrypted HTTP, "
                    "exposing traffic to interception.",
                )
            )
        elif app.get(_ANDROID + "networkSecurityConfig") is None and min_sdk and min_sdk < 28:
            findings.append(
                Finding(
                    "low",
                    "No network security config",
                    "No android:networkSecurityConfig and minSdk < 28: cleartext "
                    "traffic is allowed by platform default.",
                )
            )

        if _bool_attr(app, "testOnly") is True:
            findings.append(
                Finding("medium", "Test-only build", "android:testOnly=\"true\" is set.")
            )

        findings += _check_exported(app)

    if min_sdk and min_sdk < 23:
        findings.append(
            Finding(
                "low",
                "Low minSdkVersion (%d)" % min_sdk,
                "Targets very old Android versions that lack modern platform "
                "mitigations and may have unpatched vulnerabilities.",
            )
        )

    dangerous = sorted(set(info.permissions) & _DANGEROUS_PERMISSIONS)
    if dangerous:
        findings.append(
            Finding(
                "info",
                "Requests %d sensitive permission(s)" % len(dangerous),
                "\n".join("    - " + p for p in dangerous),
            )
        )

    return findings


def _is_exported(comp) -> bool:
    explicit = comp.get(_ANDROID + "exported")
    if explicit is not None:
        return explicit == "true"
    # Default (pre-API-31): exported if it declares an intent-filter.
    return comp.find("intent-filter") is not None


def _check_exported(app) -> List[Finding]:
    findings: List[Finding] = []
    labels = {
        "activity": "activity",
        "activity-alias": "activity",
        "service": "service",
        "receiver": "receiver",
        "provider": "provider",
    }
    exposed = []
    for tag, kind in labels.items():
        for comp in app.findall(tag):
            if _is_exported(comp) and comp.get(_ANDROID + "permission") is None:
                name = comp.get(_ANDROID + "name", "?")
                exposed.append("%s (%s)" % (name, kind))

    if exposed:
        shown = exposed[:_MAX_EXAMPLES]
        more = "" if len(exposed) <= _MAX_EXAMPLES else "\n    ... and %d more" % (
            len(exposed) - _MAX_EXAMPLES
        )
        findings.append(
            Finding(
                "medium",
                "%d exported component(s) without a permission" % len(exposed),
                "These form the app's IPC attack surface (reachable by other apps):\n"
                + "\n".join("    - " + e for e in shown)
                + more,
            )
        )
    return findings


def _check_signing(info) -> List[Finding]:
    schemes = info.signature_schemes
    if not schemes:
        return [
            Finding(
                "medium",
                "No signature detected",
                "Could not detect a v1/v2/v3 signature. The APK may be unsigned or "
                "tampered with.",
            )
        ]
    has_modern = any("v2" in s or "v3" in s for s in schemes)
    if not has_modern:
        return [
            Finding(
                "medium",
                "Only legacy v1 (JAR) signing",
                "Without an APK Signature Scheme v2+, the package is exposed to the "
                "Janus-style tampering class (CVE-2017-13156).",
            )
        ]
    return []


def _scan_secrets(strings: List[str]) -> List[Finding]:
    findings: List[Finding] = []

    for severity, label, pattern in _SECRET_PATTERNS:
        hits = sorted({m.group(0) for s in strings for m in [pattern.search(s)] if m})
        if hits:
            findings.append(
                Finding(
                    severity,
                    "Possible %s in code (%d)" % (label, len(hits)),
                    "\n".join("    - " + _redact(h) for h in hits[:_MAX_EXAMPLES]),
                )
            )

    urls = sorted(
        {
            m.group(0)
            for s in strings
            for m in [_URL_RE.search(s)]
            if m and not _URL_IGNORE.search(m.group(0))
        }
    )
    if urls:
        more = "" if len(urls) <= _MAX_EXAMPLES else "\n    ... and %d more" % (
            len(urls) - _MAX_EXAMPLES
        )
        findings.append(
            Finding(
                "info",
                "Hardcoded HTTP(S) endpoint(s) (%d)" % len(urls),
                "\n".join("    - " + u for u in urls[:_MAX_EXAMPLES]) + more,
            )
        )

    return findings


def _redact(secret: str) -> str:
    """Show enough of a secret to recognise it without printing it in full."""
    if len(secret) <= 12 or secret.startswith("-----BEGIN"):
        return secret[:12] + "..."
    return "%s...%s" % (secret[:6], secret[-4:])
