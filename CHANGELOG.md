# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-06-14

### Added
- Pure-Python, dependency-free core (no JVM required):
  - `info` — package, versions, SDK levels, permissions, components, launcher
    activity, native ABIs/libraries, and signing scheme (v1 / v2-v3 detection).
  - `scan` — static security review: manifest hardening (debuggable, backups,
    cleartext, testOnly), exported attack surface, sensitive permissions, weak
    signing, and redacted hardcoded-secret detection. Exits non-zero on a
    high-severity finding (CI-friendly).
  - `manifest` — decode binary `AndroidManifest.xml` to readable, well-formed
    text XML (UTF-8 & UTF-16 string pools, resource-map attribute resolution,
    typed-value formatting, self-closing empty elements).
  - `extract` — unzip an APK and write a decoded manifest alongside.
  - `dex` — DEX header / table statistics and optional class listing.
  - `strings` — dump strings from all DEX files.
- Optional full decompilation via auto-managed JVM engines:
  - `decompile` — Java source (jadx) or smali + resources (apktool).
  - `setup` — download engines and check the Java runtime.
  - `doctor` — report the environment and installed tools.
- Easy, zero-install usage:
  - `wizard` — interactive guided menu (also launched by running with no
    sub-command on a terminal); drag-and-drop friendly.
  - Bundled launchers `apkdec`, `apkdec.bat`, `apkdec.ps1` that run straight from
    a clone with no `pip install` (double-click `apkdec.bat` on Windows).
  - First-run installer scripts: `scripts/install.sh` (macOS/Linux) and
    `scripts/install.ps1` + `scripts/install.bat` (Windows). They verify Python,
    install the `apkdec` command (venv/pipx/pip-user aware) and run a health
    check; the Windows installer can create a Desktop shortcut to the wizard.
- UTF-8 stdout/stderr handling and broken-pipe safety for cross-platform CLIs.
- Cross-platform CI (Linux / macOS / Windows) and a self-contained test suite
  built on synthesized binary fixtures.
- Legal/ethical documentation: `DISCLAIMER.md` (terms of use, acceptable use,
  limitation of liability — EN + TR) and `SECURITY.md` (responsible disclosure).

[Unreleased]: https://github.com/emrezdemir/apk-decompiler/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/emrezdemir/apk-decompiler/releases/tag/v0.1.0
