import pytest

from apkdec import apk, cli

from .fixtures import build_apk


@pytest.fixture()
def apk_path(tmp_path):
    p = tmp_path / "sample.apk"
    p.write_bytes(build_apk())
    return str(p)


def test_get_info(apk_path):
    info = apk.get_info(apk_path)
    assert info.package == "com.example.app"
    assert info.version_code == "42"
    assert info.version_name == "1.0"
    assert "android.permission.INTERNET" in info.permissions
    assert info.dex_files == ["classes.dex"]
    assert info.total_classes == 1
    assert "v1 (JAR)" in info.signature_schemes


def test_decode_manifest(apk_path):
    xml = apk.decode_manifest(apk_path)
    assert "com.example.app" in xml


def test_extract(apk_path, tmp_path):
    out = tmp_path / "out"
    apk.extract(apk_path, str(out))
    assert (out / "AndroidManifest.xml").exists()
    assert (out / "AndroidManifest.decoded.xml").exists()
    assert (out / "classes.dex").exists()
    decoded = (out / "AndroidManifest.decoded.xml").read_text(encoding="utf-8")
    assert "com.example.app" in decoded


def test_dex_summary(apk_path):
    summary = apk.dex_summary(apk_path, list_classes=True)
    assert summary["dex"][0]["classes"] == 1
    assert "com.example.app.MainActivity" in summary["classes"]


def test_dump_strings(apk_path):
    strings = apk.dump_strings(apk_path)
    assert "hello" in strings


def test_bad_apk(tmp_path):
    p = tmp_path / "broken.apk"
    p.write_bytes(b"this is not a zip")
    with pytest.raises(apk.ApkError):
        apk.get_info(str(p))


def test_cli_info(apk_path, capsys):
    rc = cli.main(["info", apk_path])
    assert rc == 0
    out = capsys.readouterr().out
    assert "com.example.app" in out


def test_cli_info_json(apk_path, capsys):
    rc = cli.main(["info", "--json", apk_path])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"package": "com.example.app"' in out


def test_cli_no_command(capsys):
    rc = cli.main([])
    assert rc == 1


def test_cli_doctor(capsys):
    rc = cli.main(["doctor"])
    assert rc == 0
    assert "apkdec" in capsys.readouterr().out


def test_wizard_info_then_quit(apk_path, monkeypatch, capsys):
    # Feed: APK path -> menu choice 1 (info) -> quit
    answers = iter([apk_path, "1", "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))
    rc = cli.run_wizard()
    assert rc == 0
    out = capsys.readouterr().out
    assert "interactive mode" in out
    assert "com.example.app" in out


def test_wizard_quit_immediately(apk_path, monkeypatch, capsys):
    answers = iter([apk_path, "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))
    assert cli.run_wizard() == 0


def test_wizard_blank_path_exits(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda *a, **k: "")
    assert cli.run_wizard() == 0
    assert "Goodbye" in capsys.readouterr().out
