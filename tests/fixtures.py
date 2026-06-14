"""Builders that synthesize minimal-but-valid Android binary artifacts.

These let the test-suite exercise the pure-Python parsers without shipping a
real (copyrighted, large) APK in the repository.
"""

from __future__ import annotations

import struct
import zipfile
from io import BytesIO
from typing import List, Tuple

from apkdec import axml

NO_ENTRY = 0xFFFFFFFF


def _string_pool_utf8(strings: List[str]) -> bytes:
    """Build a UTF-8 string-pool chunk (type 0x0001)."""
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(len(data))
        raw = s.encode("utf-8")
        data += bytes([len(s) & 0x7F, len(raw) & 0x7F]) + raw + b"\x00"
    while len(data) % 4:  # align string data block
        data += b"\x00"

    header_size = 28
    offsets_blob = b"".join(struct.pack("<I", o) for o in offsets)
    strings_start = header_size + len(offsets_blob)
    chunk_size = strings_start + len(data)

    chunk = struct.pack(
        "<HHIIIIII",
        0x0001,            # type: string pool
        header_size,       # header size
        chunk_size,        # chunk size
        len(strings),      # string count
        0,                 # style count
        0x00000100,        # flags: UTF-8
        strings_start,     # strings start
        0,                 # styles start
    )
    return chunk + offsets_blob + bytes(data)


def _string_pool_utf16(strings: List[str]) -> bytes:
    """Build a UTF-16 string-pool chunk (the AXML default encoding)."""
    data = bytearray()
    offsets = []
    for s in strings:
        offsets.append(len(data))
        raw = s.encode("utf-16-le")
        data += struct.pack("<H", len(s) & 0x7FFF) + raw + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"

    header_size = 28
    offsets_blob = b"".join(struct.pack("<I", o) for o in offsets)
    strings_start = header_size + len(offsets_blob)
    chunk_size = strings_start + len(data)
    chunk = struct.pack(
        "<HHIIIIII",
        0x0001, header_size, chunk_size, len(strings), 0, 0, strings_start, 0,
    )
    return chunk + offsets_blob + bytes(data)


def _resource_map(ids: List[int]) -> bytes:
    """Build a resource-map chunk (type 0x0180)."""
    header_size = 8
    chunk_size = header_size + len(ids) * 4
    chunk = struct.pack("<HHI", 0x0180, header_size, chunk_size)
    return chunk + b"".join(struct.pack("<I", i) for i in ids)


def _start_namespace(prefix_idx: int, uri_idx: int) -> bytes:
    return struct.pack(
        "<HHIIIII", 0x0100, 0x0010, 24, 1, NO_ENTRY, prefix_idx, uri_idx
    )


def _end_namespace(prefix_idx: int, uri_idx: int) -> bytes:
    return struct.pack(
        "<HHIIIII", 0x0101, 0x0010, 24, 1, NO_ENTRY, prefix_idx, uri_idx
    )


def _start_element(
    ns_idx: int, name_idx: int, attrs: List[Tuple[int, int, int, int, int]]
) -> bytes:
    """attrs: list of (ns_idx, name_idx, raw_value_idx, data_type, data)."""
    body = struct.pack(
        "<IIHHHHHH",
        ns_idx if ns_idx is not None else NO_ENTRY,
        name_idx,
        0x0014,        # attribute start
        0x0014,        # attribute size
        len(attrs),    # attribute count
        0,             # id index
        0,             # class index
        0,             # style index
    )
    for a_ns, a_name, a_raw, a_type, a_data in attrs:
        body += struct.pack(
            "<IIIHBBI",
            a_ns if a_ns is not None else NO_ENTRY,
            a_name,
            a_raw,
            0x0008,    # value size
            0,         # res0
            a_type,
            a_data,
        )
    chunk_size = 16 + len(body)
    header = struct.pack("<HHII", 0x0102, 0x0010, chunk_size, 1)  # type, hsize, size, line
    header += struct.pack("<I", NO_ENTRY)  # comment
    return header + body


def _end_element(ns_idx: int, name_idx: int) -> bytes:
    return struct.pack(
        "<HHIIIII",
        0x0103,
        0x0010,
        24,
        1,
        NO_ENTRY,
        ns_idx if ns_idx is not None else NO_ENTRY,
        name_idx,
    )


def build_manifest_axml_utf16() -> bytes:
    """Same document as :func:`build_manifest_axml` but UTF-16 encoded."""
    return _build_manifest(_string_pool_utf16)


def build_resmap_axml() -> bytes:
    """A manifest whose attribute name is empty and resolved via resource map.

    This mirrors how some compiled manifests store framework attributes: the
    name string is blank and the real name comes from the resource-map id.
    """
    strings = ["", "android", axml.ANDROID_NS, "manifest"]  # index 0 = empty name
    body = bytearray()
    body += _string_pool_utf8(strings)
    body += _resource_map([0x0101021B])  # index 0 -> android:versionCode
    body += _start_namespace(1, 2)
    body += _start_element(NO_ENTRY, 3, [(2, 0, NO_ENTRY, 0x10, 5)])
    body += _end_element(NO_ENTRY, 3)
    body += _end_namespace(1, 2)
    file_size = 8 + len(body)
    return struct.pack("<HHI", 0x0003, 0x0008, file_size) + bytes(body)


def build_manifest_axml() -> bytes:
    """A tiny but structurally valid compiled AndroidManifest.xml."""
    return _build_manifest(_string_pool_utf8)


def _build_manifest(pool_builder) -> bytes:
    strings = [
        "android",                       # 0 - ns prefix
        axml.ANDROID_NS,                 # 1 - ns uri
        "manifest",                      # 2
        "package",                       # 3
        "com.example.app",               # 4
        "versionCode",                   # 5
        "versionName",                   # 6
        "1.0",                           # 7
        "uses-permission",               # 8
        "name",                          # 9
        "android.permission.INTERNET",   # 10
    ]
    body = bytearray()
    body += pool_builder(strings)
    body += _start_namespace(0, 1)
    # <manifest package="com.example.app" android:versionCode="42"
    #           android:versionName="1.0">
    body += _start_element(
        NO_ENTRY,
        2,
        [
            (NO_ENTRY, 3, 4, 0x03, 4),    # package (string)
            (1, 5, NO_ENTRY, 0x10, 42),   # android:versionCode (int)
            (1, 6, 7, 0x03, 7),           # android:versionName (string)
        ],
    )
    # <uses-permission android:name="android.permission.INTERNET" />
    body += _start_element(NO_ENTRY, 8, [(1, 9, 10, 0x03, 10)])
    body += _end_element(NO_ENTRY, 8)
    body += _end_element(NO_ENTRY, 2)
    body += _end_namespace(0, 1)

    file_size = 8 + len(body)
    header = struct.pack("<HHI", 0x0003, 0x0008, file_size)
    return header + bytes(body)


def build_risky_manifest_axml() -> bytes:
    """A manifest that deliberately trips several security checks."""
    strings = [
        "android",                      # 0 prefix
        axml.ANDROID_NS,                # 1 uri
        "manifest",                     # 2
        "package",                      # 3
        "com.evil.app",                 # 4
        "uses-permission",              # 5
        "name",                         # 6
        "android.permission.READ_SMS",  # 7
        "application",                  # 8
        "debuggable",                   # 9
        "activity",                     # 10
        "exported",                     # 11
        "com.evil.app.Main",            # 12
        "true",                         # 13
    ]
    TRUE = 0xFFFFFFFF
    body = bytearray()
    body += _string_pool_utf8(strings)
    body += _start_namespace(0, 1)
    body += _start_element(NO_ENTRY, 2, [(NO_ENTRY, 3, 4, 0x03, 4)])  # <manifest package=...>
    body += _start_element(NO_ENTRY, 5, [(1, 6, 7, 0x03, 7)])         # <uses-permission name=READ_SMS/>
    body += _end_element(NO_ENTRY, 5)
    body += _start_element(NO_ENTRY, 8, [(1, 9, 13, 0x12, TRUE)])     # <application debuggable=true>
    body += _start_element(                                            # <activity name exported=true/>
        NO_ENTRY, 10, [(1, 6, 12, 0x03, 12), (1, 11, 13, 0x12, TRUE)]
    )
    body += _end_element(NO_ENTRY, 10)
    body += _end_element(NO_ENTRY, 8)
    body += _end_element(NO_ENTRY, 2)
    body += _end_namespace(0, 1)
    file_size = 8 + len(body)
    return struct.pack("<HHI", 0x0003, 0x0008, file_size) + bytes(body)


def build_risky_apk() -> bytes:
    """An APK that exercises the security analyzer: debuggable, exported
    component, dangerous permission, a hardcoded secret and a native library."""
    api_key = "AIzaSy" + "A1234567890abcdefghijklmnopqrstuvw"  # matches Google API key regex
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", build_risky_manifest_axml())
        zf.writestr("classes.dex", build_dex([api_key], ["Lcom/evil/app/Main;"]))
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF placeholder")
        zf.writestr("META-INF/CERT.RSA", b"\x30\x82fake-cert")
    return buf.getvalue()


def build_dex(strings: List[str], class_descriptors: List[str]) -> bytes:
    """Build a minimal valid DEX with given strings and class definitions."""
    # Layout: header(0x70) | string_ids | type_ids | class_defs | string_data
    all_strings = list(strings)
    # Ensure descriptors are present in the string table; map to indices.
    type_descs = []
    for desc in class_descriptors:
        if desc not in all_strings:
            all_strings.append(desc)
        type_descs.append(all_strings.index(desc))

    string_ids_off = 0x70
    type_ids_off = string_ids_off + len(all_strings) * 4
    class_defs_off = type_ids_off + len(type_descs) * 4
    string_data_off = class_defs_off + len(class_descriptors) * 32

    # Encode string data (uleb128 length + MUTF-8 bytes + NUL) and record offsets.
    string_data = bytearray()
    string_offsets = []
    for s in all_strings:
        string_offsets.append(string_data_off + len(string_data))
        raw = s.encode("utf-8")
        string_data += _uleb128(len(s)) + raw + b"\x00"

    out = bytearray(string_data_off)
    # string_ids -> absolute offset of each string's data
    for i, off in enumerate(string_offsets):
        struct.pack_into("<I", out, string_ids_off + i * 4, off)
    # type_ids -> string index of the descriptor
    for i, str_idx in enumerate(type_descs):
        struct.pack_into("<I", out, type_ids_off + i * 4, str_idx)
    # class_defs -> only the first field (type_idx into type_ids) matters here
    for i in range(len(class_descriptors)):
        struct.pack_into("<I", out, class_defs_off + i * 32, i)

    out += string_data

    # Header
    out[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", out, 0x20, len(out))      # file_size
    struct.pack_into("<I", out, 0x24, 0x70)          # header_size
    struct.pack_into("<I", out, 0x28, 0x12345678)    # endian_tag
    struct.pack_into("<I", out, 0x38, len(all_strings))
    struct.pack_into("<I", out, 0x3C, string_ids_off)
    struct.pack_into("<I", out, 0x40, len(type_descs))
    struct.pack_into("<I", out, 0x44, type_ids_off)
    struct.pack_into("<I", out, 0x60, len(class_descriptors))
    struct.pack_into("<I", out, 0x64, class_defs_off)
    return bytes(out)


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def build_apk() -> bytes:
    """Build an in-memory APK (zip) with a manifest and one dex."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", build_manifest_axml())
        zf.writestr(
            "classes.dex",
            build_dex(["hello", "world"], ["Lcom/example/app/MainActivity;"]),
        )
        zf.writestr("res/values/strings.xml", b"placeholder")
        zf.writestr("META-INF/CERT.RSA", b"\x30\x82fake-cert")
    return buf.getvalue()
