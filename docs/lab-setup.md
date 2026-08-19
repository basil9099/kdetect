# Lab setup

How to build the kdetect lab VM from scratch, and why it is built this way.

The phase 1 lab was a third-party prebuilt image (limitation L1). That was
acceptable for phase 1, which performs no detection. **Phase 2 onwards requires
a baseline whose provenance you can attest**, because every finding kdetect
produces is ultimately a claim about how the machine differs from clean.

Do not delete the old VM until the new one is working.

## 1. Get the installer, and verify it

Download from <https://www.debian.org/CD/http-ftp/>:

- `debian-12.X.0-amd64-netinst.iso` (~630 MB)
- `SHA256SUMS`
- `SHA256SUMS.sign`

**Netinst rather than the full DVD** deliberately: it installs only what you ask
for, so the resulting system is small enough that you can plausibly account for
every package on it. That is the whole point of rebuilding.

### Minimum: check the hash

On Windows, in PowerShell:

```powershell
Get-FileHash -Algorithm SHA256 .\debian-12.X.0-amd64-netinst.iso
```

Compare against the matching line in `SHA256SUMS`. This proves the download was
not corrupted or substituted **provided debian.org's TLS was not compromised**.

### Better: check the signature on the hash file

The hash file itself is only as trustworthy as the connection that fetched it.
`SHA256SUMS.sign` is a detached OpenPGP signature over it. On the old VM, before
you retire it:

```bash
sudo apt install -y debian-keyring gnupg
gpg --keyring /usr/share/keyrings/debian-role-keys.gpg --verify SHA256SUMS.sign SHA256SUMS
sha256sum -c SHA256SUMS 2>&1 | grep netinst
```

A `Good signature` line means the hashes were published by the Debian CD signing
key, not merely served over HTTPS. That is the difference between trusting a
certificate authority and trusting Debian.

Record the verified hash in your notes. It is the provenance claim that L1 said
the previous image could not make.

### Verification record — 2026-08-19

The installer used to build the current lab VM:

```
file        debian-12.12.0-amd64-netinst.iso   (704643072 bytes)
sha256      dfc30e04fd095ac2c07e998f145e94bb8f7d3a8eca3a631d2eb012398deae531
signed by   Debian CD signing key <debian-cd@lists.debian.org>
key         DF9B 9C49 EAA9 2984 3258  9D76 DA87 E80D 6294 BE9B
verified    gpg --keyring /usr/share/keyrings/debian-role-keys.gpg \n                --no-default-keyring --verify SHA256SUMS.sign SHA256SUMS
result      Good signature
```

Debian 12 is oldstable as of this date (current stable is 13.6.0). It was chosen
deliberately: the phase 1 fixture, the Step 0 evidence and the phase 2 rootkit
references all target the 6.1 kernel line, and changing the kernel at the same
time as introducing the differ would confound two variables at once.

Note `curl` is not installed on a minimal Debian; use `wget`.

## 2. Create the VM

VMware Workstation, new virtual machine:

| Setting | Value | Why |
|---|---|---|
| Guest OS | Debian 12 64-bit | |
| Disk | 40 GB, **not** preallocated, single file | Thin: consumes only what is used |
| Processors | 1 socket x 2 cores | Real concurrency, so vanished-process races occur naturally |
| Memory | 4 GB | Also the size of the `.vmem` for phase 5 Volatility work |
| Network | NAT | Needed for `apt`. Switch to Host-only before running live rootkits |
| Sound card | **remove** | Loads `snd_*` modules you did not ask for |
| Printer | **remove** | Adds a virtual port |

Removing devices is not tuning. You are going to spend phase 2 reading
`/proc/modules` looking for the one entry that should not be there, and every
device removed is several modules that never clutter the baseline.

Attach the verified ISO to the CD/DVD drive and boot.

## 3. Installer choices

Most screens are defaults. These are not:

- **Hostname:** `kdetect-lab`. Captures then identify themselves.
- **Domain:** leave blank.
- **Root password: leave empty.** Debian then adds your first user to `sudo`
  and disables direct root login. One fewer credential, and it matches how the
  tool is meant to be run — `sudo kdetect capture`, not a root shell.
- **Username:** `debian`, to keep the existing `~/.ssh/config` entry working.
  Any other name means updating `User` in that file.
- **Partitioning:** Guided, use entire disk, all files in one partition. No LVM
  or encryption — this VM holds nothing worth protecting, and both add moving
  parts to reason about.
- **Popularity contest:** No.
- **Software selection (`tasksel`):** uncheck everything except
  - [x] SSH server
  - [x] standard system utilities

  Especially **no desktop environment**. You drive this over Remote-SSH.
- **GRUB:** install to the primary disk (`/dev/sda`).

A netinst with this selection produces roughly 400 packages, versus several
thousand for a desktop install.

## 4. First boot

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3-venv python3-pip build-essential linux-headers-$(uname -r)
```

`build-essential` and `linux-headers` are needed to compile an out-of-tree
kernel module in phase 2. Installing them now means the baseline includes them —
a toolchain that appears *after* your baseline is itself an anomaly you would
have to explain.

Note the kernel and record it:

```bash
uname -r; cat /proc/sys/kernel/kptr_restrict /proc/sys/kernel/perf_event_paranoid
```

Both sysctls matter (limitation L4). Expect `kptr_restrict=0` and
`perf_event_paranoid` above 1, meaning kernel addresses require `CAP_SYSLOG`.

## 5. Reconnect from Windows

Find the new IP:

```bash
ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v 127.0.0.1
```

Push your key across from Windows PowerShell (prompts for the password once):

```powershell
type $env:USERPROFILE\.ssh\kdetect_vm.pub | ssh debian@NEW_IP "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

Update `HostName` in `C:\Users\angus\.ssh\config`, then confirm key auth works
without falling back to a password:

```powershell
ssh -o BatchMode=yes kdetect "uname -r"
```

The NAT lease can move across reboots. If it does, either set a static address
in the guest or add a DHCP reservation in **Edit → Virtual Network Editor → NAT
settings**.

## 6. Snapshots

Take these in order. The names matter because you will revert to them often.

| Snapshot | When | Purpose |
|---|---|---|
| `pristine` | Immediately after first boot, before any package | Untouched, as installed |
| `clean-baseline` | After tooling, VS Code Remote-SSH first connect, and repo clone | **The one you revert to.** Matches the machine as it is when kdetect runs |
| `infected-<name>` | After installing a rootkit | Throwaway, per experiment |

`clean-baseline` must be taken **after** VS Code has connected once, because
Remote-SSH installs a server into `~/.vscode-server` that runs several Node
processes permanently. A baseline without them does not match the machine you
actually test on (limitation L6).

## 7. Repository and git access

```bash
mkdir -p ~/projects && git clone git@github.com:basil9099/kdetect.git ~/projects/kdetect
cd ~/projects/kdetect && git config user.name "Angus Dawson" && git config user.email "angus.dawson@hotmail.com"
python3 -m venv .venv && . .venv/bin/activate && pip install -e . pytest && python -m pytest -q
```

The suite should pass in full. If the integration tier fails on the new host,
that is a real finding about a difference between the two installs, not a
flaky test.

**Generate a new deploy key** on this VM rather than reusing the old one, and
remove the old key from the repository's Deploy keys page (limitation L2):

```bash
ssh-keygen -t ed25519 -C "kdetect-lab" -f ~/.ssh/github_kdetect -N ""
cat ~/.ssh/github_kdetect.pub
```

Add it at **repo → Settings → Deploy keys → Add deploy key**, with write access.
Repository-scoped, not account-scoped: this machine will run hostile code, and
the blast radius should be one public repo you can re-clone.

## 8. Working safely once rootkits are involved

The key that lets you push is on a machine you are about to compromise on
purpose. The mitigation is procedure rather than cryptography:

1. Commit and push **from `clean-baseline`**, before infecting.
2. Snapshot as `infected-<name>`, install the rootkit, run captures.
3. **Revert to `clean-baseline`.** Never push from an infected snapshot.
4. Switch the adapter to **Host-only** for infected runs, so the VM cannot reach
   the internet regardless of what is running on it.

Treat anything produced in an infected snapshot as data to be copied out and
inspected, not as a working tree to commit from.
