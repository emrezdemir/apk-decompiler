import pytest

from apkdec import axml

from .fixtures import (
    build_manifest_axml,
    build_manifest_axml_utf16,
    build_resmap_axml,
)


def test_decode_produces_text_xml():
    xml = axml.decode(build_manifest_axml())
    assert xml.startswith('<?xml version="1.0" encoding="utf-8"?>')
    assert "<manifest" in xml
    assert 'package="com.example.app"' in xml
    assert 'android:versionCode="42"' in xml
    assert 'android:versionName="1.0"' in xml
    assert 'xmlns:android="%s"' % axml.ANDROID_NS in xml
    assert "android.permission.INTERNET" in xml
    assert "</manifest>" in xml
    # empty element should be self-closed
    assert "<uses-permission" in xml and "/>" in xml


def test_decode_utf16_string_pool():
    xml = axml.decode(build_manifest_axml_utf16())
    assert 'package="com.example.app"' in xml
    assert 'android:versionName="1.0"' in xml


def test_decode_resolves_name_from_resource_map():
    xml = axml.decode(build_resmap_axml())
    assert 'android:versionCode="5"' in xml


def test_decode_rejects_text_xml():
    with pytest.raises(axml.AXMLError):
        axml.decode(b"<?xml version='1.0'?><manifest/>")


def test_decode_rejects_tiny_buffer():
    with pytest.raises(axml.AXMLError):
        axml.decode(b"\x00\x00")


def test_typed_value_formatting():
    # boolean true (0xFFFFFFFF) and false (0)
    from apkdec.axml import _format_typed_value, _StringPool

    pool = _StringPool(["x"])
    assert _format_typed_value(0x12, 0xFFFFFFFF, axml._NO_ENTRY, pool) == "true"
    assert _format_typed_value(0x12, 0, axml._NO_ENTRY, pool) == "false"
    assert _format_typed_value(0x11, 0x7F, axml._NO_ENTRY, pool) == "0x7f"
    assert _format_typed_value(0x10, 0xFFFFFFFF, axml._NO_ENTRY, pool) == "-1"
    assert _format_typed_value(0x1C, 0xAABBCCDD, axml._NO_ENTRY, pool) == "#aabbccdd"
