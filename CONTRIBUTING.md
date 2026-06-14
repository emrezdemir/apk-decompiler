# Contributing

Thanks for your interest in improving **apkdec**!

## Development setup

```bash
git clone https://github.com/emrezdemir/apk-decompiler.git
cd apk-decompiler
pip install -e ".[dev]"
pytest
```

## Guidelines

- **Keep the core dependency-free.** Modules under `src/apkdec/` that parse APK,
  AXML or DEX data must use only the Python standard library. JVM tooling stays
  isolated in `tools.py` / `decompile.py`.
- **No binary test assets.** The test-suite synthesizes valid AXML / DEX / APK
  byte streams in `tests/fixtures.py`. Add to those builders instead of checking
  in real APKs.
- **Cross-platform first.** Avoid POSIX-only or Windows-only assumptions; the CI
  matrix runs on Linux, macOS and Windows.
- Run `pytest` before opening a pull request.

## Reporting issues

Please include: your OS, Python version (`apkdec doctor` output is ideal), the
exact command you ran, and the full output. If it concerns a specific APK, note
that we generally cannot accept copyrighted binaries in the tracker — a minimal
description of the manifest/structure is usually enough.
