# Security Policy

## Scope

This policy concerns vulnerabilities **in `apkdec` itself** (this tool), not in
applications you analyze with it.

If you find a vulnerability in a **third-party application** using `apkdec`,
report it to that application's vendor following coordinated/responsible
disclosure — not here. Only test applications you are authorized to test (see
[DISCLAIMER.md](DISCLAIMER.md)).

## Reporting a vulnerability in apkdec

Please **do not** open a public issue for security problems.

Instead, use **GitHub Security Advisories**:
"Security" tab → "Report a vulnerability" (GitHub Private Vulnerability
Reporting). Include:

- A description of the issue and its impact.
- Steps to reproduce (a minimal proof of concept if possible).
- The version / commit and your environment (`apkdec doctor` output helps).

We aim to acknowledge reports within a reasonable timeframe and to coordinate a
fix and disclosure with you.

## Supported versions

This project is in early development (`0.x`). Security fixes are applied to the
latest release / `main` branch only.
