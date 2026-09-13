# Security policy

## Supported versions

Only the latest release, currently 1.0.x, receives security fixes.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the
[Security tab](https://github.com/basil9099/kdetect/security) and choose
"Report a vulnerability". Please don't open a public issue.

Include the kdetect version, the distribution and kernel version, and the steps
or input that reproduce the problem. If you attach a snapshot, run
`kdetect redact` on it first and check what is left: it scrubs process command
lines only, not `exe` paths, hostnames, or socket addresses.

Don't attach rootkit binaries or other live malware. Name the sample, its version,
and where it came from instead.

kdetect is maintained by one person. I will acknowledge a report within 7 days
and keep you updated while it is investigated. How long a fix takes depends on
the problem. Reporters are credited in the release notes unless they would rather
not be.

## What counts as a vulnerability

kdetect runs as root and parses input that any process on the host can influence
([threat model §6](docs/threat-model.md#6-risks-the-tool-itself-introduces)).
In scope:

- A crash, hang, or code execution triggered by crafted `/proc` content, or by a
  crafted snapshot or baseline passed to `analyze`, `report`, `baseline`, or
  `redact`.
- A modified baseline that passes signature verification, or any baseline content
  parsed before its signature is checked.
- `kdetect redact` leaving a process command line in its output.

## What does not

- Evasion that [`docs/limitations.md`](docs/limitations.md) already records, such
  as a rootkit that lies consistently to every channel or runs below the kernel.
  A new way to hide from a channel kdetect claims to cover is welcome as a regular
  issue.
- False findings caused by containers or PID namespaces, a known gap listed in
  [threat model §7](docs/threat-model.md#7-out-of-scope).
- Attacks that assume the attacker can already modify kdetect itself or obtain
  the baseline signing key (limitation L18).
