"""Lightweight pure-Python reader for Dalvik executable (``.dex``) files.

This does not disassemble bytecode (use ``jadx``/``baksmali`` for that). It
parses the DEX header and id tables so the CLI can report useful statistics and
list class / string entries without a JVM.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List

_DEX_MAGIC = b"dex\n"
_HEADER_SIZE = 0x70


class DexError(Exception):
    """Raised when a buffer is not a valid DEX file."""


@dataclass
class DexInfo:
    """Summary statistics for a single DEX file."""

    version: str
    string_count: int
    type_count: int
    proto_count: int
    field_count: int
    method_count: int
    class_count: int
    _string_ids_off: int = 0
    _type_ids_off: int = 0
    _class_defs_off: int = 0
    _data: bytes = field(default=b"", repr=False)


def _read_uleb128(data: bytes, off: int):
    """Decode an unsigned LEB128 value, returning (value, new_offset)."""
    result = 0
    shift = 0
    while True:
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return result, off


def _decode_mutf8(data: bytes, off: int) -> str:
    """Decode a length-prefixed MUTF-8 string starting at ``off``."""
    _utf16_len, off = _read_uleb128(data, off)
    end = data.index(0, off)
    raw = data[off:end]
    # MUTF-8 encodes embedded NULs as 0xC0 0x80; replace for plain UTF-8 decode.
    raw = raw.replace(b"\xc0\x80", b"\x00")
    return raw.decode("utf-8", errors="replace")


def parse(data: bytes) -> DexInfo:
    """Parse the header and id-table sizes of a DEX buffer."""
    if len(data) < _HEADER_SIZE or data[:4] != _DEX_MAGIC:
        raise DexError("not a DEX file (bad magic)")
    version = data[4:7].decode("ascii", errors="replace")

    (
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        _proto_ids_off,
        field_ids_size,
        _field_ids_off,
        method_ids_size,
        _method_ids_off,
        class_defs_size,
        class_defs_off,
    ) = struct.unpack_from("<12I", data, 0x38)

    return DexInfo(
        version=version,
        string_count=string_ids_size,
        type_count=type_ids_size,
        proto_count=proto_ids_size,
        field_count=field_ids_size,
        method_count=method_ids_size,
        class_count=class_defs_size,
        _string_ids_off=string_ids_off,
        _type_ids_off=type_ids_off,
        _class_defs_off=class_defs_off,
        _data=data,
    )


def iter_strings(info: DexInfo) -> List[str]:
    """Return all strings referenced by the DEX string id table."""
    data = info._data
    strings: List[str] = []
    for i in range(info.string_count):
        str_data_off = struct.unpack_from("<I", data, info._string_ids_off + i * 4)[0]
        try:
            strings.append(_decode_mutf8(data, str_data_off))
        except (IndexError, ValueError):
            strings.append("")
    return strings


def iter_class_names(info: DexInfo) -> List[str]:
    """Return fully-qualified class names defined in this DEX file.

    Names are converted from the JVM descriptor form ``Lcom/example/Foo;`` to
    the dotted form ``com.example.Foo``.
    """
    data = info._data
    # Build the string-offset lookup once, then resolve type descriptors.
    names: List[str] = []
    for i in range(info.class_count):
        class_def = info._class_defs_off + i * 32
        type_idx = struct.unpack_from("<I", data, class_def)[0]
        descriptor_str_idx = struct.unpack_from(
            "<I", data, info._type_ids_off + type_idx * 4
        )[0]
        str_data_off = struct.unpack_from(
            "<I", data, info._string_ids_off + descriptor_str_idx * 4
        )[0]
        try:
            descriptor = _decode_mutf8(data, str_data_off)
        except (IndexError, ValueError):
            continue
        names.append(_descriptor_to_name(descriptor))
    return names


def _descriptor_to_name(descriptor: str) -> str:
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1].replace("/", ".")
    return descriptor
