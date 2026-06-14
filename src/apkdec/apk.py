"""High-level APK inspection built on the pure-Python ``axml`` and ``dex``
readers. No external tools or JVM required for anything in this module.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from . import axml, dex

_ANDROID = "{%s}" % axml.ANDROID_NS


class ApkError(Exception):
    """Raised when a file cannot be read as an APK."""


@dataclass
class ApkInfo:
    """Structured summary of an APK's manifest and contents."""

    path: str
    package: str = ""
    version_code: str = ""
    version_name: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    compile_sdk: str = ""
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    features: List[str] = field(default_factory=list)
    launchable_activity: str = ""
    debuggable: bool = False
    file_count: int = 0
    dex_files: List[str] = field(default_factory=list)
    total_classes: int = 0
    total_methods: int = 0
    signature_schemes: List[str] = field(default_factory=list)
    abis: List[str] = field(default_factory=list)
    native_libs: List[str] = field(default_factory=list)


def _open(path: str) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(path, "r")
    except (zipfile.BadZipFile, FileNotFoundError, OSError) as exc:
        raise ApkError("cannot open %r as an APK: %s" % (path, exc)) from exc


def decode_manifest(path: str) -> str:
    """Return the decoded text XML of an APK's ``AndroidManifest.xml``."""
    with _open(path) as zf:
        try:
            raw = zf.read("AndroidManifest.xml")
        except KeyError as exc:
            raise ApkError("APK has no AndroidManifest.xml") from exc
    return axml.decode(raw)


def _qualify(pkg: str, name: str) -> str:
    """Expand a relative component name (``.Foo``) to a fully-qualified one."""
    if name.startswith("."):
        return pkg + name
    if "." not in name and pkg:
        return pkg + "." + name
    return name


def _resolve_int_attr(value: str) -> str:
    """Manifest sdk/version ints can be stored as hex; normalise to decimal."""
    if value.startswith("0x"):
        try:
            return str(int(value, 16))
        except ValueError:
            return value
    return value


def get_info(path: str) -> ApkInfo:
    """Inspect an APK and return an :class:`ApkInfo` summary."""
    info = ApkInfo(path=path)
    with _open(path) as zf:
        names = zf.namelist()
        info.file_count = len(names)
        info.dex_files = sorted(
            n for n in names if n.endswith(".dex") and "/" not in n
        )
        info.native_libs = sorted(
            n for n in names if n.startswith("lib/") and n.endswith(".so")
        )
        info.abis = sorted(
            {n.split("/")[1] for n in info.native_libs if n.count("/") >= 2}
        )

        try:
            manifest_xml = axml.decode(zf.read("AndroidManifest.xml"))
            _populate_from_manifest(info, manifest_xml)
        except (KeyError, axml.AXMLError):
            pass

        for dex_name in info.dex_files:
            try:
                d = dex.parse(zf.read(dex_name))
                info.total_classes += d.class_count
                info.total_methods += d.method_count
            except dex.DexError:
                continue

        info.signature_schemes = _detect_signatures(zf, path, names)
    return info


def _populate_from_manifest(info: ApkInfo, manifest_xml: str) -> None:
    try:
        root = ET.fromstring(manifest_xml)
    except ET.ParseError:
        return

    info.package = root.get("package", "")
    info.version_code = _resolve_int_attr(root.get(_ANDROID + "versionCode", ""))
    info.version_name = root.get(_ANDROID + "versionName", "")
    info.compile_sdk = _resolve_int_attr(root.get(_ANDROID + "compileSdkVersion", ""))

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        info.min_sdk = _resolve_int_attr(uses_sdk.get(_ANDROID + "minSdkVersion", ""))
        info.target_sdk = _resolve_int_attr(
            uses_sdk.get(_ANDROID + "targetSdkVersion", "")
        )

    for perm in root.findall("uses-permission"):
        name = perm.get(_ANDROID + "name")
        if name:
            info.permissions.append(name)

    for feat in root.findall("uses-feature"):
        name = feat.get(_ANDROID + "name")
        if name:
            info.features.append(name)

    app = root.find("application")
    if app is not None:
        info.debuggable = app.get(_ANDROID + "debuggable", "false") == "true"
        pkg = info.package
        _collect_components(app, "activity", info.activities, pkg)
        _collect_components(app, "activity-alias", info.activities, pkg)
        _collect_components(app, "service", info.services, pkg)
        _collect_components(app, "receiver", info.receivers, pkg)
        _collect_components(app, "provider", info.providers, pkg)
        info.launchable_activity = _find_launchable(app, pkg)


def _collect_components(app, tag: str, bucket: List[str], pkg: str) -> None:
    for comp in app.findall(tag):
        name = comp.get(_ANDROID + "name")
        if name:
            bucket.append(_qualify(pkg, name))


def _find_launchable(app, pkg: str) -> str:
    for activity in list(app.findall("activity")) + list(app.findall("activity-alias")):
        for intent in activity.findall("intent-filter"):
            actions = {a.get(_ANDROID + "name") for a in intent.findall("action")}
            categories = {c.get(_ANDROID + "name") for c in intent.findall("category")}
            if (
                "android.intent.action.MAIN" in actions
                and "android.intent.category.LAUNCHER" in categories
            ):
                name = activity.get(_ANDROID + "name", "")
                return _qualify(pkg, name)
    return ""


def _detect_signatures(zf, path: str, names: List[str]) -> List[str]:
    schemes: List[str] = []
    if any(
        n.upper().startswith("META-INF/")
        and n.upper().endswith((".RSA", ".DSA", ".EC"))
        for n in names
    ):
        schemes.append("v1 (JAR)")
    try:
        if _has_apk_sig_block(path):
            schemes.append("v2/v3 (APK Signing Block)")
    except OSError:
        pass
    return schemes


def _has_apk_sig_block(path: str) -> bool:
    """Detect the APK Signing Block magic that backs v2/v3/v4 signatures."""
    magic = b"APK Sig Block 42"
    with open(path, "rb") as fh:
        data = fh.read()
    return magic in data[-1024 * 256:]  # block sits just before the central dir


def extract(path: str, out_dir: str) -> Path:
    """Extract every entry of the APK and write a decoded manifest alongside.

    Returns the output directory path.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with _open(path) as zf:
        # zipfile already guards against path traversal in extractall().
        zf.extractall(out)
        try:
            decoded = axml.decode(zf.read("AndroidManifest.xml"))
            (out / "AndroidManifest.decoded.xml").write_text(decoded, encoding="utf-8")
        except (KeyError, axml.AXMLError):
            pass
    return out


def dex_summary(path: str, list_classes: bool = False) -> Dict[str, object]:
    """Return aggregated DEX statistics (and optionally all class names)."""
    with _open(path) as zf:
        dex_names = sorted(n for n in zf.namelist() if n.endswith(".dex") and "/" not in n)
        per_dex = []
        all_classes: List[str] = []
        for name in dex_names:
            try:
                d = dex.parse(zf.read(name))
            except dex.DexError:
                continue
            per_dex.append(
                {
                    "name": name,
                    "version": d.version,
                    "classes": d.class_count,
                    "methods": d.method_count,
                    "fields": d.field_count,
                    "strings": d.string_count,
                }
            )
            if list_classes:
                all_classes.extend(dex.iter_class_names(d))
    return {"dex": per_dex, "classes": sorted(set(all_classes))}


def dump_strings(path: str, min_len: int = 1) -> List[str]:
    """Return de-duplicated, sorted strings from all DEX files in the APK."""
    seen = set()
    with _open(path) as zf:
        for name in sorted(zf.namelist()):
            if not (name.endswith(".dex") and "/" not in name):
                continue
            try:
                d = dex.parse(zf.read(name))
            except dex.DexError:
                continue
            for s in dex.iter_strings(d):
                if len(s) >= min_len:
                    seen.add(s)
    return sorted(seen)
