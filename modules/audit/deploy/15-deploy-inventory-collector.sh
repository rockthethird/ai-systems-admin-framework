#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SOURCE="$SCRIPT_DIR/../collect/ai-auditor-inventory.py"
readonly DESTINATION="/usr/local/libexec/ai-auditor-inventory"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

python3 -c 'import pathlib, sys; source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"); compile(source, sys.argv[1], "exec")' "$SOURCE"
install -d -o root -g root -m 0755 "$(dirname "$DESTINATION")"
temporary="$(mktemp /usr/local/libexec/.ai-auditor-inventory.XXXXXX)"
trap 'rm -f "$temporary"' EXIT
install -o root -g root -m 0755 "$SOURCE" "$temporary"
mv -f "$temporary" "$DESTINATION"
trap - EXIT
echo "Installed inventory collector at $DESTINATION"
