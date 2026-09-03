# kdetect

Linux kernel rootkit detection via cross-view comparison. See
[`docs/architecture.md`](docs/architecture.md) for how it's put together and
[`docs/detection-methods.md`](docs/detection-methods.md) for what it detects
and why.

## Commands

- `kdetect capture [--out PATH] [--pretty]` — snapshot the live system to a
  JSON file (default: a generated name under `captures/`).
- `kdetect analyze <snapshot> [--json] [--baseline PATH --verify-key PATH]` —
  summarise a snapshot's findings on the terminal; exits 3 if any are present.
- `kdetect baseline <snapshot> --out PATH --sign-key PATH` — sign a clean
  snapshot as a baseline for future drift detection.
- `kdetect report <snapshot> [--format md|json] [--out PATH] [--baseline PATH --verify-key PATH]` —
  render a shareable Markdown or JSON report of a snapshot's findings and
  indicators of compromise; exits 3 if any findings are present.
- `kdetect redact <in.json> <out.json>` — scrub a snapshot's process command
  lines before sharing it.
