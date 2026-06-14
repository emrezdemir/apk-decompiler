import pytest

from apkdec import dex

from .fixtures import build_dex


def test_parse_header():
    data = build_dex(["alpha", "beta"], ["Lcom/example/Foo;", "Lcom/example/Bar;"])
    info = dex.parse(data)
    assert info.version == "035"
    assert info.class_count == 2
    # "alpha", "beta", plus the two descriptors that get appended
    assert info.string_count == 4
    assert info.type_count == 2


def test_parse_rejects_non_dex():
    with pytest.raises(dex.DexError):
        dex.parse(b"not a dex file at all, padding............................")


def test_iter_strings():
    data = build_dex(["hello", "world"], ["Lcom/example/Foo;"])
    info = dex.parse(data)
    strings = dex.iter_strings(info)
    assert "hello" in strings
    assert "world" in strings


def test_iter_class_names_dotted():
    data = build_dex(["s"], ["Lcom/example/app/MainActivity;"])
    info = dex.parse(data)
    names = dex.iter_class_names(info)
    assert "com.example.app.MainActivity" in names
