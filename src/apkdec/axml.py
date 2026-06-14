"""Pure-Python decoder for Android binary XML (AXML).

Android stores ``AndroidManifest.xml`` (and other XML files inside an APK) in a
compiled binary form. This module turns that binary form back into readable
text XML without requiring ``aapt``, ``apktool`` or a JVM.

The format is documented indirectly through the AOSP source
(``ResourceTypes.h``). The implementation below follows that layout and is
deliberately defensive: a malformed chunk is skipped rather than aborting the
whole decode, because real-world APKs frequently contain quirks.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Chunk type identifiers (see AOSP ResourceTypes.h ResChunk_header.type)
# ---------------------------------------------------------------------------
_CHUNK_AXML_FILE = 0x0003
_CHUNK_STRING_POOL = 0x0001
_CHUNK_RESOURCE_MAP = 0x0180
_CHUNK_XML_START_NS = 0x0100
_CHUNK_XML_END_NS = 0x0101
_CHUNK_XML_START_ELEMENT = 0x0102
_CHUNK_XML_END_ELEMENT = 0x0103
_CHUNK_XML_CDATA = 0x0104

# String pool flags
_FLAG_UTF8 = 1 << 8

# Typed value data types (see Res_value::dataType)
_TYPE_NULL = 0x00
_TYPE_REFERENCE = 0x01
_TYPE_ATTRIBUTE = 0x02
_TYPE_STRING = 0x03
_TYPE_FLOAT = 0x04
_TYPE_DIMENSION = 0x05
_TYPE_FRACTION = 0x06
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12
_TYPE_INT_COLOR_ARGB8 = 0x1C
_TYPE_INT_COLOR_RGB8 = 0x1D
_TYPE_INT_COLOR_ARGB4 = 0x1E
_TYPE_INT_COLOR_RGB4 = 0x1F

_NO_ENTRY = 0xFFFFFFFF

# Complex (dimension / fraction) helpers, mirroring android.util.TypedValue.
_RADIX_MULTS = (0.00390625, 3.051758e-05, 1.192093e-07, 4.656613e-10)
_DIMENSION_UNITS = ("px", "dip", "sp", "pt", "in", "mm", "", "")
_FRACTION_UNITS = ("%", "%p", "", "", "", "", "", "")

# A small, stable subset of framework attribute resource IDs. Modern manifests
# embed attribute names directly, but some store an empty name and rely on the
# resource map. These IDs have been fixed in the Android framework for years.
_KNOWN_ATTR_IDS: Dict[int, str] = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010018: "authorities",
    0x0101001E: "enabled",
    0x01010020: "process",
    0x010100D0: "id",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
}

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AXMLError(Exception):
    """Raised when a buffer cannot be parsed as Android binary XML."""


class _StringPool:
    """Decoded representation of a string pool chunk."""

    def __init__(self, strings: List[str]):
        self._strings = strings

    def get(self, index: int) -> str:
        if index == _NO_ENTRY or index < 0 or index >= len(self._strings):
            return ""
        return self._strings[index]

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._strings)


def _read_utf8_len(data: bytes, off: int) -> Tuple[int, int]:
    """Read an AXML UTF-8 length prefix, returning (length, new_offset)."""
    val = data[off]
    off += 1
    if val & 0x80:
        val = ((val & 0x7F) << 8) | data[off]
        off += 1
    return val, off


def _read_utf16_len(data: bytes, off: int) -> Tuple[int, int]:
    """Read an AXML UTF-16 length prefix, returning (length, new_offset)."""
    val = struct.unpack_from("<H", data, off)[0]
    off += 2
    if val & 0x8000:
        low = struct.unpack_from("<H", data, off)[0]
        off += 2
        val = ((val & 0x7FFF) << 16) | low
    return val, off


def _parse_string_pool(data: bytes, base: int) -> _StringPool:
    """Parse a string pool chunk that begins at ``base``."""
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, base)
    if chunk_type != _CHUNK_STRING_POOL:
        raise AXMLError("expected string pool chunk")
    string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", data, base + 8
    )
    is_utf8 = bool(flags & _FLAG_UTF8)
    offsets_base = base + header_size
    data_base = base + strings_start

    strings: List[str] = []
    for i in range(string_count):
        str_off = struct.unpack_from("<I", data, offsets_base + i * 4)[0]
        pos = data_base + str_off
        try:
            if is_utf8:
                _char_len, pos = _read_utf8_len(data, pos)
                byte_len, pos = _read_utf8_len(data, pos)
                raw = data[pos : pos + byte_len]
                strings.append(raw.decode("utf-8", errors="replace"))
            else:
                char_len, pos = _read_utf16_len(data, pos)
                raw = data[pos : pos + char_len * 2]
                strings.append(raw.decode("utf-16-le", errors="replace"))
        except (IndexError, struct.error):
            strings.append("")
    return _StringPool(strings)


def _parse_resource_map(data: bytes, base: int) -> List[int]:
    """Parse a resource map chunk into a list of resource IDs."""
    _chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, base)
    count = (chunk_size - header_size) // 4
    ids: List[int] = []
    for i in range(count):
        ids.append(struct.unpack_from("<I", data, base + header_size + i * 4)[0])
    return ids


def _complex_to_float(complex_val: int) -> float:
    mantissa = complex_val & (0xFFFFFF << 8)
    radix = (complex_val >> 4) & 0x3
    return mantissa * _RADIX_MULTS[radix]


def _format_float(value: float) -> str:
    text = ("%g" % value)
    return text


def _format_typed_value(
    data_type: int,
    data_val: int,
    raw_index: int,
    pool: _StringPool,
) -> str:
    """Render a Res_value into a human-readable attribute string."""
    if data_type == _TYPE_STRING:
        return pool.get(raw_index if raw_index != _NO_ENTRY else data_val)
    if data_type == _TYPE_NULL:
        return ""
    if data_type == _TYPE_REFERENCE:
        prefix = "@android:" if (data_val >> 24) == 0x01 else "@"
        return "%sref/0x%08x" % (prefix, data_val) if prefix == "@" else "%s0x%08x" % (prefix, data_val)
    if data_type == _TYPE_ATTRIBUTE:
        return "?0x%08x" % data_val
    if data_type == _TYPE_FLOAT:
        return _format_float(struct.unpack("<f", struct.pack("<I", data_val))[0])
    if data_type == _TYPE_DIMENSION:
        unit = _DIMENSION_UNITS[data_val & 0xF]
        return _format_float(_complex_to_float(data_val)) + unit
    if data_type == _TYPE_FRACTION:
        unit = _FRACTION_UNITS[data_val & 0xF]
        return _format_float(_complex_to_float(data_val) * 100) + unit
    if data_type == _TYPE_INT_HEX:
        return "0x%x" % data_val
    if data_type == _TYPE_INT_BOOLEAN:
        return "true" if data_val != 0 else "false"
    if data_type == _TYPE_INT_COLOR_ARGB8:
        return "#%08x" % data_val
    if data_type == _TYPE_INT_COLOR_RGB8:
        return "#%06x" % (data_val & 0xFFFFFF)
    if data_type == _TYPE_INT_COLOR_ARGB4:
        return "#%04x" % (data_val & 0xFFFF)
    if data_type == _TYPE_INT_COLOR_RGB4:
        return "#%03x" % (data_val & 0xFFF)
    if data_type == _TYPE_INT_DEC:
        # Interpret as signed 32-bit.
        return str(data_val - 0x100000000 if data_val & 0x80000000 else data_val)
    return "0x%08x" % data_val


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class _Element:
    __slots__ = ("name", "attrs")

    def __init__(self, name: str):
        self.name = name
        self.attrs: List[Tuple[str, str]] = []


def _format_start_tag(indent: str, element: "_Element", decls: List[str]) -> str:
    """Render an opening tag (without the trailing ``>``), aligning attributes."""
    opening = "%s<%s" % (indent, element.name)
    parts = list(decls)
    parts.extend('%s="%s"' % (n, _xml_escape(v)) for n, v in element.attrs)
    if not parts:
        return opening
    align = "\n" + " " * (len(opening) + 1)
    return opening + " " + align.join(parts)


def decode(data: bytes) -> str:
    """Decode an Android binary XML buffer into pretty-printed text XML.

    Args:
        data: The raw bytes of a compiled XML resource (e.g. the contents of
            ``AndroidManifest.xml`` inside an APK).

    Returns:
        A unicode string containing the reconstructed XML document.

    Raises:
        AXMLError: If the buffer is not recognisable as Android binary XML.
    """
    if len(data) < 8:
        raise AXMLError("buffer too small to be AXML")
    file_type, _header_size, _file_size = struct.unpack_from("<HHI", data, 0)
    if file_type != _CHUNK_AXML_FILE:
        raise AXMLError(
            "not Android binary XML (magic=0x%04x); is this already text XML?" % file_type
        )

    pool: Optional[_StringPool] = None
    resource_map: List[int] = []
    namespaces: Dict[str, str] = {}  # uri -> prefix
    pending_ns: List[Tuple[str, str]] = []  # declarations awaiting an element

    out: List[str] = ['<?xml version="1.0" encoding="utf-8"?>']
    depth = 0
    pending = False  # True when out[-1] is an unclosed start tag (no '>' yet)

    def flush_open() -> None:
        nonlocal pending
        if pending:
            out[-1] += ">"
            pending = False

    offset = 8
    total = len(data)
    while offset + 8 <= total:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        if chunk_size < 8 or offset + chunk_size > total:
            break  # corrupt or trailing data; stop gracefully

        try:
            if chunk_type == _CHUNK_STRING_POOL:
                pool = _parse_string_pool(data, offset)
            elif chunk_type == _CHUNK_RESOURCE_MAP:
                resource_map = _parse_resource_map(data, offset)
            elif chunk_type == _CHUNK_XML_START_NS:
                prefix_idx, uri_idx = struct.unpack_from(
                    "<II", data, offset + header_size
                )
                if pool is not None:
                    uri = pool.get(uri_idx)
                    prefix = pool.get(prefix_idx)
                    namespaces[uri] = prefix
                    pending_ns.append((prefix, uri))
            elif chunk_type == _CHUNK_XML_END_NS:
                pass
            elif chunk_type == _CHUNK_XML_START_ELEMENT and pool is not None:
                flush_open()  # the parent had children, so close its tag
                element, decls = _read_start_element(
                    data, offset, header_size, pool, resource_map, namespaces, pending_ns
                )
                pending_ns = []
                out.append(_format_start_tag("  " * depth, element, decls))
                pending = True
                depth += 1
            elif chunk_type == _CHUNK_XML_END_ELEMENT and pool is not None:
                depth = max(0, depth - 1)
                if pending:
                    out[-1] += " />"  # empty element -> self-closing
                    pending = False
                else:
                    name = _resolve_name(
                        *struct.unpack_from("<II", data, offset + header_size),
                        pool=pool,
                        resource_map=resource_map,
                        namespaces=namespaces,
                    )
                    out.append("%s</%s>" % ("  " * depth, name))
            elif chunk_type == _CHUNK_XML_CDATA and pool is not None:
                cdata_idx = struct.unpack_from("<I", data, offset + header_size)[0]
                text = pool.get(cdata_idx).strip()
                if text:
                    flush_open()
                    out.append("%s%s" % ("  " * depth, _xml_escape(text)))
        except (struct.error, IndexError):
            # Skip the malformed chunk but keep decoding the rest.
            pass

        offset += chunk_size

    return "\n".join(out) + "\n"


def _resolve_name(ns_idx, name_idx, pool, resource_map, namespaces):
    """Resolve an element/attribute name including its namespace prefix."""
    name = pool.get(name_idx)
    if not name and 0 <= name_idx < len(resource_map):
        res_id = resource_map[name_idx]
        name = _KNOWN_ATTR_IDS.get(res_id, "attr_0x%08x" % res_id)
        # Resource-map names are framework (android) attributes.
        return "android:" + name
    if ns_idx != _NO_ENTRY:
        uri = pool.get(ns_idx)
        prefix = namespaces.get(uri)
        if prefix:
            return "%s:%s" % (prefix, name)
    return name


def _read_start_element(
    data, offset, header_size, pool, resource_map, namespaces, pending_ns
):
    ns_idx, name_idx = struct.unpack_from("<II", data, offset + header_size)
    element = _Element(_resolve_name(ns_idx, name_idx, pool, resource_map, namespaces))

    attr_start, _attr_size, attr_count = struct.unpack_from(
        "<HHH", data, offset + header_size + 8
    )
    attr_base = offset + header_size + attr_start
    for i in range(attr_count):
        a = attr_base + i * 20
        a_ns, a_name, a_raw = struct.unpack_from("<III", data, a)
        _vsize, _res0, a_type, a_data = struct.unpack_from("<HBBI", data, a + 12)
        attr_name = _resolve_name(a_ns, a_name, pool, resource_map, namespaces)
        attr_value = _format_typed_value(a_type, a_data, a_raw, pool)
        element.attrs.append((attr_name, attr_value))

    decls = ['xmlns:%s="%s"' % (prefix, uri) for prefix, uri in pending_ns if prefix]
    return element, decls
