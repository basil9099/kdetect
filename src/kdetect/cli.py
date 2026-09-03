"""Command-line interface for kdetect."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from kdetect import __version__, hostfacts
from kdetect.analysis.scoring import analyze
from kdetect.collectors.kernel_hooks import KernelHookCollector
from kdetect.collectors.modules import ModuleEvidenceCollector, ProcfsModuleCollector
from kdetect.collectors.procfs import ProcfsProcessCollector
from kdetect.collectors.sockets import SocketCollector
from kdetect.collectors.sources import (
    LiveKernelHookSource,
    LiveModuleSource,
    LiveProcSource,
    LiveSignalSource,
    LiveSocketSource,
)
from kdetect.collectors.syscall_sweep import SweepProcessCollector
from kdetect.models import (
    SCHEMA_VERSION,
    CaptureMeta,
    IncompatibleSnapshot,
    Snapshot,
)

#: Exit codes. 3 means "analyze produced at least one finding" (any
#: confidence) - distinct from 1 (error) so scripts can branch on detection
#: vs. failure. `report` shares this convention (spec §8): 3 on findings,
#: 0 on none, 1 on error.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def _iso_millis(now: datetime) -> str:
    """UTC ISO-8601 with millisecond precision and a Z suffix.

    isoformat() gives microseconds, which is more precision than /proc can
    justify, and varies in width. Fixing the format keeps captured_at
    comparable across snapshots.
    """
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def cmd_capture(args) -> int:
    host = hostfacts.gather()
    euid = os.geteuid()

    if euid != 0:
        # Warn, do not refuse. The snapshot records euid and lets analysis
        # decide what it means (principle P1). This goes to stderr because
        # --out - writes the snapshot to stdout, and a warning there would
        # corrupt a piped capture.
        print(
            f"warning: running as euid {euid}, not root. Kernel addresses in "
            "/proc/modules and /proc/kallsyms will read as zero, and some "
            "per-process reads will be denied. See docs/limitations.md L4.",
            file=sys.stderr,
        )

    procs, signals, mods = LiveProcSource(), LiveSignalSource(), LiveModuleSource()
    hooks = LiveKernelHookSource()
    observations = [
        ProcfsProcessCollector(pass_label="A").collect(procs),   # bread
        SweepProcessCollector().collect(signals),                # filling
        ProcfsProcessCollector(pass_label="B").collect(procs),   # bread
        ProcfsModuleCollector().collect(mods),
        ModuleEvidenceCollector().collect(mods),
        KernelHookCollector().collect(hooks),
    ]
    pids = set(observations[0].entity_ids) | set(observations[1].entity_ids)
    observations.append(SocketCollector(pids).collect(LiveSocketSource()))

    now = datetime.now(timezone.utc)
    snapshot = Snapshot(
        schema_version=SCHEMA_VERSION,
        snapshot_id=str(uuid.uuid4()),
        captured_at=_iso_millis(now),
        host=host,
        capture=CaptureMeta(tool_version=__version__, euid=euid),
        observations=observations,
    )

    payload = snapshot.to_json(pretty=args.pretty)

    if args.out == "-":
        print(payload)
        return EXIT_OK

    if args.out:
        path = Path(args.out)
    else:
        # No ':' - illegal in Windows filenames, and these files get copied to
        # the Windows host as fixtures. Sortable, and the boot_id prefix makes
        # it visible at a glance which captures share a boot.
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        path = Path("captures") / f"{stamp}_{host.hostname}_{host.boot_id[:8]}.json"

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload + "\n", encoding="utf-8")
    print(path)
    return EXIT_OK


def cmd_baseline(args) -> int:
    from kdetect.baseline.store import load_private_key, write_baseline
    try:
        raw = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        snapshot = Snapshot.from_dict(raw)
    except (OSError, json.JSONDecodeError, IncompatibleSnapshot) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        write_baseline(snapshot, Path(args.out), load_private_key(Path(args.sign_key)))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"{args.out}\n{args.out}.sig")
    return EXIT_OK


def cmd_analyze(args) -> int:
    loaded = _load_snapshot(args.snapshot)
    if loaded is None:
        return EXIT_ERROR
    snapshot, _raw = loaded
    path = Path(args.snapshot)

    if not getattr(args, "json", False):
        host = snapshot.host
        print(f"snapshot:  {path}")
        print(f"schema:    {snapshot.schema_version}")
        print(f"host:      {host.hostname}  {host.kernel_release}  {host.arch}")
        print(f"captured:  {snapshot.captured_at}   boot {host.boot_id[:8]}")
        print(f"euid:      {snapshot.capture.euid}")
        print()
        print("collectors:")
        for obs in snapshot.observations:
            print(
                f"  {obs.collector}   trust={obs.trust_level.value}   "
                f"status={obs.status.value}   {len(obs.entity_ids)} entities   "
                f"{obs.duration_ms}ms"
            )
            stats = "  ".join(f"{k}={v}" for k, v in sorted(obs.stats.items()))
            print(f"{' ' * 21}{stats}")

    try:
        baseline = _load_verified_baseline(args)
    except _BaselineLoadError:
        return EXIT_ERROR

    findings = analyze(snapshot, baseline)

    if getattr(args, "json", False):
        print(json.dumps([f.to_dict() for f in findings], indent=2, sort_keys=True))
        return 3 if findings else EXIT_OK

    print()
    if not findings:
        print("findings:  none")
        return EXIT_OK

    print("findings:")
    for f in findings:
        print(f"  [{f.confidence.value}]   {f.kind.value}   {f.subject}")
        print(f"           seen by: {', '.join(f.channels_agree)}")
        print(f"           denied by: {', '.join(f.channels_dissent)}")
    return 3


def _load_snapshot(path_str: str) -> tuple[Snapshot, dict] | None:
    """Load and validate a snapshot, or print an error and return None.

    Returns both the validated Snapshot and the raw parsed dict, so callers
    that need to mutate the raw JSON (redact) don't have to re-read and
    re-parse the same file a second time.
    """
    path = Path(path_str)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return None
    except json.JSONDecodeError as exc:
        print(f"error: {path} is not valid JSON: {exc}", file=sys.stderr)
        return None
    except UnicodeDecodeError as exc:
        # A ValueError subclass, not an OSError -- read_text() raises this
        # for non-UTF-8 input, distinctly from the two cases above.
        print(f"error: {path} is not valid UTF-8: {exc}", file=sys.stderr)
        return None
    try:
        snapshot = Snapshot.from_dict(raw)
    except IncompatibleSnapshot as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None
    return snapshot, raw


class _BaselineLoadError(Exception):
    """Marks that _load_verified_baseline already printed its error.

    The caller's only job on catching this is `return EXIT_ERROR` -- the
    message is already on stderr.
    """


def _load_verified_baseline(args):
    """Load and signature-verify --baseline/--verify-key, shared by
    `analyze` and `report` so the two commands can't drift on this
    security-relevant check (they must accept/reject the same baselines).

    Returns None if --baseline was not given at all (baseline diffing is
    optional). Raises _BaselineLoadError, having already printed an
    `error: ...` line to stderr, on any failure -- a missing --verify-key,
    a tampered signature, or an I/O/parse problem loading either file.
    """
    if not getattr(args, "baseline", None):
        return None
    from kdetect.baseline.store import BaselineTampered, load_baseline, load_public_key
    if not args.verify_key:
        print("error: --baseline requires --verify-key", file=sys.stderr)
        raise _BaselineLoadError
    try:
        return load_baseline(Path(args.baseline), load_public_key(Path(args.verify_key)))
    except BaselineTampered as exc:
        print(f"error: baseline verification failed: {exc}", file=sys.stderr)
        raise _BaselineLoadError
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise _BaselineLoadError


def cmd_report(args) -> int:
    from kdetect.reporting import report as report_mod
    from kdetect.reporting.iocs import extract

    loaded = _load_snapshot(args.snapshot)
    if loaded is None:
        return EXIT_ERROR
    snapshot, _raw = loaded

    try:
        baseline = _load_verified_baseline(args)
    except _BaselineLoadError:
        return EXIT_ERROR
    baseline_name = Path(args.baseline).name if getattr(args, "baseline", None) else None

    findings = analyze(snapshot, baseline)
    iocs = extract(findings)
    if args.format == "json":
        text = report_mod.render_json(snapshot, findings, iocs, baseline_name)
    else:
        text = report_mod.render_markdown(snapshot, findings, iocs, baseline_name)

    # The two sinks must emit identical bytes, so settle the trailing newline
    # here rather than letting them disagree: render_markdown already ends in
    # one (its final out.append("")), render_json does not, and print() adds
    # its own. Normalise once, then neither branch appends anything.
    if not text.endswith("\n"):
        text += "\n"

    if args.out:
        try:
            Path(args.out).write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {args.out}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(args.out)
    else:
        print(text, end="")
    return 3 if findings else EXIT_OK


def cmd_redact(args) -> int:
    from kdetect.reporting.redact import redact_snapshot

    loaded = _load_snapshot(args.infile)
    if loaded is None:
        return EXIT_ERROR
    _snapshot, raw = loaded

    out = Snapshot.from_dict(redact_snapshot(raw))
    try:
        Path(args.outfile).write_text(out.to_json(pretty=True) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot write {args.outfile}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(args.outfile)
    return EXIT_OK


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="kdetect",
        description="Linux kernel rootkit detection via cross-view comparison.",
    )

    subparsers = parser.add_subparsers(dest="command")

    capture = subparsers.add_parser("capture", help="Snapshot the live system.")
    capture.add_argument(
        "--out",
        default=None,
        help="Output path. Use '-' for stdout. Default: a generated name in captures/.",
    )
    capture.add_argument(
        "--pretty", action="store_true", help="Indent the JSON output."
    )

    analyze = subparsers.add_parser("analyze", help="Summarise a snapshot file.")
    analyze.add_argument("snapshot", help="Path to a snapshot JSON file.")
    analyze.add_argument("--json", action="store_true",
                         help="Emit findings as JSON; suppress the summary.")
    analyze.add_argument("--baseline", help="Signed baseline to diff against.")
    analyze.add_argument("--verify-key", help="ed25519 public key (PEM) for --baseline.")

    baseline = subparsers.add_parser("baseline", help="Sign a snapshot as a baseline.")
    baseline.add_argument("snapshot")
    baseline.add_argument("--out", required=True)
    baseline.add_argument("--sign-key", required=True)

    report_p = subparsers.add_parser("report", help="Render a shareable report.")
    report_p.add_argument("snapshot")
    report_p.add_argument("--format", choices=["md", "json"], default="md")
    report_p.add_argument("--out", help="Write to a file instead of stdout.")
    report_p.add_argument("--baseline", help="Signed baseline to diff against.")
    report_p.add_argument("--verify-key", help="ed25519 public key (PEM) for --baseline.")

    redact_p = subparsers.add_parser(
        "redact", help="Replace every process cmdline with a placeholder (L13)."
    )
    redact_p.add_argument("infile")
    redact_p.add_argument("outfile")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_USAGE

    if args.command == "capture":
        return cmd_capture(args)

    if args.command == "analyze":
        return cmd_analyze(args)

    if args.command == "baseline":
        return cmd_baseline(args)

    if args.command == "report":
        return cmd_report(args)

    if args.command == "redact":
        return cmd_redact(args)

    return EXIT_USAGE


def cli_entry() -> None:
    """Console-script entry point named in pyproject.toml."""
    raise SystemExit(main())


if __name__ == "__main__":
    raise SystemExit(main())
