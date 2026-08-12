#!/bin/bash
set -euo pipefail

readonly USERS=("ai-auditor-cloud" "ai-auditor-local")

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

for user in "${USERS[@]}"; do
    home="/opt/$user"
    if ! id "$user" >/dev/null 2>&1; then
        useradd --system --create-home --home-dir "$home" --shell /bin/bash \
            --comment "AI Auditor report identity" "$user"
    fi
    passwd -l "$user" >/dev/null 2>&1 || true
    install -d -o "$user" -g "$user" -m 0750 "$home"
    install -d -o "$user" -g "$user" -m 0700 "$home/.ssh"
    actual_home="$(getent passwd "$user" | cut -d: -f6)"
    actual_shell="$(getent passwd "$user" | cut -d: -f7)"
    if [ "$actual_home" != "$home" ] || [ "$actual_shell" != "/bin/bash" ]; then
        echo "ERROR: Existing identity $user has unexpected home or shell" >&2
        exit 1
    fi
    echo "Prepared locked report identity: $user"
done

echo "SSH keys are intentionally not configured by this step"
