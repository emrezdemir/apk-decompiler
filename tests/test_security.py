import pytest

from apkdec import apk, cli, security

from .fixtures import build_risky_apk


@pytest.fixture()
def risky_apk(tmp_path):
    p = tmp_path / "risky.apk"
    p.write_bytes(build_risky_apk())
    return str(p)


def _titles(findings):
    return [f.title for f in findings]


def test_detects_debuggable(risky_apk):
    findings = security.analyze(risky_apk)
    assert any("debuggable" in t.lower() for t in _titles(findings))
    assert any(f.severity == "high" for f in findings)


def test_detects_exported_component(risky_apk):
    findings = security.analyze(risky_apk)
    assert any("exported component" in t for t in _titles(findings))


def test_detects_dangerous_permission(risky_apk):
    findings = security.analyze(risky_apk)
    assert any("sensitive permission" in t for t in _titles(findings))


def test_detects_hardcoded_secret(risky_apk):
    findings = security.analyze(risky_apk)
    assert any("Google API key" in t for t in _titles(findings))


def test_secret_is_redacted(risky_apk):
    findings = security.analyze(risky_apk)
    secret_findings = [f for f in findings if "Google API key" in f.title]
    assert secret_findings
    # The full 39-char key must not be printed verbatim.
    assert "AIzaSyA1234567890abcdefghijklmnopqrstuvw" not in secret_findings[0].detail


def test_native_libs_detected(risky_apk):
    info = apk.get_info(risky_apk)
    assert "arm64-v8a" in info.abis
    assert any(lib.endswith("libnative.so") for lib in info.native_libs)


def test_cli_scan_returns_nonzero_on_high(risky_apk, capsys):
    rc = cli.main(["scan", risky_apk])
    out = capsys.readouterr().out
    assert "[HIGH]" in out
    assert rc == 1


def test_cli_scan_json(risky_apk, capsys):
    rc = cli.main(["scan", "--json", risky_apk])
    out = capsys.readouterr().out
    assert '"severity"' in out
    assert rc == 0
