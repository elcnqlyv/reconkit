#!/usr/bin/env bash
# reconkit bootstrap: check the OS and install required/optional tools (with consent).
# This is a thin wrapper around `recon.py deps`; pass flags through, e.g.
#   ./install.sh --check      # report only
#   ./install.sh --print      # print commands, don't run
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/recon.py" deps "$@"
