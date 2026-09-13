#!/usr/bin/env bash
# Scripted run for the README demo GIF: a clean capture, then a module that hides
# itself, then the capture that catches it.
#
# Run as root under asciinema on a throwaway VM snapshot, from the repo root, with
# the test module built in hidden mode (cd kmod && make clean && make hidden; not
# make -C, because the Makefile's M=$(PWD) would point at the repo root). A hidden
# module cannot be unloaded, so revert the snapshot afterwards
# (docs/lab-setup.md §8).
#
#   sudo KDETECT_BIN="$PWD/.venv/bin" \
#     asciinema rec --idle-time-limit 2 --command "bash tools/demo.sh" demo.cast
#
# KDETECT_BIN is the directory holding the kdetect executable. sudo resets PATH,
# which would otherwise lose a kdetect installed in a virtualenv.

set -uo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run as root: capture needs it, and so does loading the module" >&2
  exit 1
fi
if [[ -n "${KDETECT_BIN:-}" ]]; then
  export PATH="$KDETECT_BIN:$PATH"
fi
cd "$(dirname "$0")/.." || exit 1

# kbuild records each compile command in a .cmd file, so this tells a hidden build
# from a visible one, which would load without hiding and give a dull demo.
if [[ ! -f kmod/kdetect_hooktest.ko ]] ||
   ! grep -qs KDETECT_HIDDEN kmod/.kdetect_hooktest.o.cmd; then
  echo "build the hidden module first: (cd kmod && make clean && make hidden)" >&2
  exit 1
fi
if grep -q '^kdetect_hooktest ' /proc/modules; then
  echo "kdetect_hooktest is already loaded; revert the snapshot first" >&2
  exit 1
fi

# Print a command as if typed, then run it.
run() {
  local i
  printf '\033[1;32mlab#\033[0m '
  for ((i = 0; i < ${#1}; i++)); do
    printf '%s' "${1:i:1}"
    sleep 0.03
  done
  printf '\n'
  sleep 0.5
  eval "$1"
  sleep 2
}

# A narration line, dimmed so it reads as commentary rather than output.
say() {
  printf '\033[2m%s\033[0m\n' "$1"
  sleep 1.5
}

rm -f /tmp/clean.json /tmp/infected.json
clear

say "A clean host first."
run "kdetect capture --out /tmp/clean.json"
run "kdetect analyze /tmp/clean.json"

say "Load a module that hooks uname and unlinks itself from the module list."
run "insmod kmod/kdetect_hooktest.ko"
run "lsmod | grep kdetect_hooktest || echo 'not in lsmod'"

say "Capture again."
run "kdetect capture --out /tmp/infected.json"
run "kdetect analyze /tmp/infected.json"
sleep 3
