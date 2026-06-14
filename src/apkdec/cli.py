"""Command-line interface for apkdec."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, apk, decompile, security, tools

_PROG = "apkdec"


def _print_info(info: apk.ApkInfo) -> None:
    def line(label, value):
        if value:
            print("  %-18s %s" % (label + ":", value))

    print("APK: %s" % info.path)
    line("Package", info.package)
    line("Version name", info.version_name)
    line("Version code", info.version_code)
    line("Min SDK", info.min_sdk)
    line("Target SDK", info.target_sdk)
    line("Compile SDK", info.compile_sdk)
    line("Debuggable", "yes" if info.debuggable else "")
    line("Launcher", info.launchable_activity)
    line("Signing", ", ".join(info.signature_schemes) or "none detected")
    line("Files", str(info.file_count))
    line("DEX files", "%d (%s)" % (len(info.dex_files), ", ".join(info.dex_files)) if info.dex_files else "0")
    line("Classes", str(info.total_classes) if info.total_classes else "")
    line("Methods", str(info.total_methods) if info.total_methods else "")
    line("Native ABIs", ", ".join(info.abis))
    line("Native libs", str(len(info.native_libs)) if info.native_libs else "")

    def block(title, items):
        if items:
            print("\n%s (%d):" % (title, len(items)))
            for item in items:
                print("  - %s" % item)

    block("Permissions", info.permissions)
    block("Activities", info.activities)
    block("Services", info.services)
    block("Receivers", info.receivers)
    block("Providers", info.providers)
    block("Features", info.features)


def _cmd_info(args) -> int:
    info = apk.get_info(args.apk)
    if args.json:
        import json
        from dataclasses import asdict

        print(json.dumps(asdict(info), indent=2, ensure_ascii=False))
    else:
        _print_info(info)
    return 0


def _cmd_manifest(args) -> int:
    xml = apk.decode_manifest(args.apk)
    if args.output:
        Path(args.output).write_text(xml, encoding="utf-8")
        print("Wrote %s" % args.output)
    else:
        sys.stdout.write(xml)
    return 0


def _cmd_extract(args) -> int:
    out = args.output or (Path(args.apk).stem + "_extracted")
    apk.extract(args.apk, out)
    print("Extracted to %s/" % out)
    print("Decoded manifest: %s/AndroidManifest.decoded.xml" % out)
    return 0


def _cmd_dex(args) -> int:
    summary = apk.dex_summary(args.apk, list_classes=args.classes)
    for d in summary["dex"]:
        print(
            "%s  v%s  classes=%d methods=%d fields=%d strings=%d"
            % (d["name"], d["version"], d["classes"], d["methods"], d["fields"], d["strings"])
        )
    if args.classes:
        classes = summary["classes"]
        print("\n%d classes:" % len(classes))
        for name in classes:
            print("  %s" % name)
    return 0


def _cmd_strings(args) -> int:
    for s in apk.dump_strings(args.apk, min_len=args.min_len):
        print(s)
    return 0


_SEV_TAG = {"high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]", "info": "[INFO]"}


def _cmd_scan(args) -> int:
    findings = security.analyze(args.apk)
    if args.json:
        import json
        from dataclasses import asdict

        print(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False))
        return 0

    print("Security scan: %s\n" % args.apk)
    if not findings:
        print("No obvious issues found by the heuristic checks.")
        print("(Absence of findings is not proof of security — review manually.)")
        return 0

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    for f in findings:
        print("%s %s" % (_SEV_TAG.get(f.severity, "[????]"), f.title))
        if f.detail:
            for line in f.detail.splitlines():
                print("       %s" % line if not line.startswith("    ") else line)
        print()

    summary = ", ".join(
        "%d %s" % (counts[s], s) for s in ("high", "medium", "low", "info") if s in counts
    )
    print("Summary: %s. Findings are leads for manual review, not confirmed issues." % summary)
    return 1 if counts.get("high") else 0


def _cmd_decompile(args) -> int:
    out = args.output or (Path(args.apk).stem + ("_smali" if args.engine == "apktool" else "_src"))
    try:
        if args.engine == "apktool":
            code = decompile.run_apktool(args.apk, out)
        else:
            code = decompile.run_jadx(args.apk, out)
    except decompile.DecompileError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if code == 0:
        print("\nDone. Output: %s/" % out)
    else:
        print("\nEngine exited with code %d." % code, file=sys.stderr)
    return code


def _cmd_setup(args) -> int:
    java = tools.find_java()
    if java:
        print("Java: %s (%s)" % (java, tools.java_version(java)))
    else:
        print("Java: NOT FOUND")
        print(tools.java_install_hint())

    which = args.tool
    if which in ("jadx", "all"):
        print("Ensuring jadx ...")
        print("  jadx: %s" % tools.ensure_jadx())
    if which in ("apktool", "all"):
        print("Ensuring apktool ...")
        print("  apktool: %s" % tools.ensure_apktool())
    return 0


def _cmd_doctor(args) -> int:
    print("apkdec %s" % __version__)
    print("python: %s" % sys.version.split()[0])
    print("cache:  %s" % tools.cache_dir())
    java = tools.find_java()
    if java:
        print("java:   %s (%s)" % (java, tools.java_version(java)))
    else:
        print("java:   NOT FOUND  -- needed for `decompile`")
    jadx = tools.jadx_executable()
    print("jadx:   %s" % (jadx if jadx else "not installed (run `apkdec setup --tool jadx`)"))
    apktool = tools.apktool_jar()
    print("apktool:%s" % (" " + str(apktool) if apktool else " not installed (run `apkdec setup --tool apktool`)"))
    return 0


# ---------------------------------------------------------------------------
# Interactive wizard ("easy mode") - runs when invoked with no command on a
# TTY, or explicitly via `apkdec wizard`. Designed for one-off / drag-and-drop
# use without memorising sub-commands.
# ---------------------------------------------------------------------------
class _Args:
    """Tiny stand-in for argparse.Namespace used to reuse command handlers."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def _prompt(message: str) -> str:
    try:
        return input(message).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def _clean_path(text: str) -> str:
    # Terminals/Explorer often wrap drag-and-dropped paths in quotes.
    return text.strip().strip('"').strip("'").strip()


def _wizard_manifest(apk_path: str) -> None:
    out = _clean_path(_prompt("Save to file (blank = print to screen): "))
    xml = apk.decode_manifest(apk_path)
    if out:
        Path(out).write_text(xml, encoding="utf-8")
        print("Wrote %s" % out)
    else:
        print(xml)


def _wizard_extract(apk_path: str) -> None:
    default = Path(apk_path).stem + "_extracted"
    out = _clean_path(_prompt("Output directory [%s]: " % default)) or default
    apk.extract(apk_path, out)
    print("Extracted to %s/" % out)


def _wizard_dex(apk_path: str, classes: bool) -> None:
    summary = apk.dex_summary(apk_path, list_classes=classes)
    for d in summary["dex"]:
        print("%s  v%s  classes=%d methods=%d" % (d["name"], d["version"], d["classes"], d["methods"]))
    if classes:
        for name in summary["classes"]:
            print("  %s" % name)


def _wizard_strings(apk_path: str) -> None:
    raw = _prompt("Minimum string length [4]: ") or "4"
    try:
        min_len = int(raw)
    except ValueError:
        min_len = 4
    for s in apk.dump_strings(apk_path, min_len=min_len):
        print(s)


def _wizard_decompile(apk_path: str, engine: str) -> None:
    default = Path(apk_path).stem + ("_smali" if engine == "apktool" else "_src")
    out = _clean_path(_prompt("Output directory [%s]: " % default)) or default
    runner = decompile.run_apktool if engine == "apktool" else decompile.run_jadx
    code = runner(apk_path, out)
    print(("Done. Output: %s/" % out) if code == 0 else ("Engine exited with code %d." % code))


def run_wizard(apk_path=None) -> int:
    """Run the interactive menu. Returns a process exit code."""
    print("=" * 54)
    print("  apkdec %s - interactive mode" % __version__)
    print("=" * 54)

    while not apk_path or not Path(apk_path).is_file():
        if apk_path:
            print("  ! Not a file: %s" % apk_path)
        apk_path = _clean_path(_prompt("APK path (or drag & drop the file here): "))
        if not apk_path:
            print("Goodbye.")
            return 0

    menu = [
        ("Show APK info", lambda p: _print_info(apk.get_info(p))),
        ("Security scan", lambda p: _cmd_scan(_Args(apk=p, json=False))),
        ("Decode AndroidManifest.xml", _wizard_manifest),
        ("Extract APK contents", _wizard_extract),
        ("DEX statistics", lambda p: _wizard_dex(p, False)),
        ("List all classes", lambda p: _wizard_dex(p, True)),
        ("Dump DEX strings", _wizard_strings),
        ("Decompile to Java source (jadx, needs Java)", lambda p: _wizard_decompile(p, "jadx")),
        ("Decompile to smali (apktool, needs Java)", lambda p: _wizard_decompile(p, "apktool")),
        ("Environment check (doctor)", lambda p: _cmd_doctor(None)),
    ]

    while True:
        print("\nFile: %s" % apk_path)
        for i, (label, _) in enumerate(menu, 1):
            print("  %d) %s" % (i, label))
        print("  c) Choose a different APK")
        print("  q) Quit")
        choice = _prompt("Select: ").lower()

        if choice in ("q", "0", ""):
            print("Goodbye.")
            return 0
        if choice == "c":
            apk_path = None
            return run_wizard(None)
        if choice.isdigit() and 1 <= int(choice) <= len(menu):
            print()
            try:
                menu[int(choice) - 1][1](apk_path)
            except (apk.ApkError, decompile.DecompileError) as exc:
                print("error: %s" % exc, file=sys.stderr)
        else:
            print("  ? Invalid choice, try again.")


def _cmd_wizard(args) -> int:
    return run_wizard(args.apk)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_PROG,
        description="Cross-platform CLI APK decompiler / inspector.",
        epilog="Run '%s <command> -h' for command-specific help." % _PROG,
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser("info", help="Show package, version, SDKs, permissions, components")
    p.add_argument("apk")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p.set_defaults(func=_cmd_info)

    p = sub.add_parser("manifest", help="Decode AndroidManifest.xml to text XML")
    p.add_argument("apk")
    p.add_argument("-o", "--output", help="Write to file instead of stdout")
    p.set_defaults(func=_cmd_manifest)

    p = sub.add_parser("extract", help="Unzip the APK and decode its manifest")
    p.add_argument("apk")
    p.add_argument("-o", "--output", help="Output directory")
    p.set_defaults(func=_cmd_extract)

    p = sub.add_parser(
        "scan", help="Static security review: manifest, attack surface, secrets"
    )
    p.add_argument("apk")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("dex", help="Show DEX statistics (and optionally class names)")
    p.add_argument("apk")
    p.add_argument("--classes", action="store_true", help="List all class names")
    p.set_defaults(func=_cmd_dex)

    p = sub.add_parser("strings", help="Dump strings from all DEX files")
    p.add_argument("apk")
    p.add_argument("--min-len", type=int, default=1, help="Minimum string length")
    p.set_defaults(func=_cmd_strings)

    p = sub.add_parser(
        "decompile",
        help="Full decompile to Java (jadx) or smali+resources (apktool); needs Java",
    )
    p.add_argument("apk")
    p.add_argument("-o", "--output", help="Output directory")
    p.add_argument(
        "-e",
        "--engine",
        choices=["jadx", "apktool"],
        default="jadx",
        help="Decompilation engine (default: jadx)",
    )
    p.set_defaults(func=_cmd_decompile)

    p = sub.add_parser("setup", help="Download tools and check the Java runtime")
    p.add_argument(
        "--tool", choices=["jadx", "apktool", "all"], default="all", help="Which tool(s)"
    )
    p.set_defaults(func=_cmd_setup)

    p = sub.add_parser("doctor", help="Report environment and installed tools")
    p.set_defaults(func=_cmd_doctor)

    p = sub.add_parser(
        "wizard", help="Interactive guided mode (no flags to remember)"
    )
    p.add_argument("apk", nargs="?", help="APK to start with (optional)")
    p.set_defaults(func=_cmd_wizard)

    return parser


def _configure_stdio() -> None:
    """Force UTF-8 output so non-ASCII strings never crash on consoles whose
    native code page can't represent them (common on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):  # replaced/!TextIOWrapper streams
            pass


def main(argv=None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        # No sub-command: drop into the wizard if a human is at the keyboard,
        # otherwise show help (keeps scripts/CI predictable).
        if sys.stdin.isatty() and sys.stdout.isatty():
            return run_wizard()
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except apk.ApkError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except BrokenPipeError:  # pragma: no cover - e.g. piping into `head`
        # Redirect stdout to devnull so the interpreter's final flush does not
        # re-raise on the closed pipe (the documented Python idiom).
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 0
    except KeyboardInterrupt:  # pragma: no cover
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
