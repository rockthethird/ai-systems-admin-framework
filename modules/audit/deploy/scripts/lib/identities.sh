# Identity preflight and deployment stage. Sourced by deploy.sh.

readonly IDENTITY_MANIFEST="$ARTIFACTS_DIR/rootfs/opt/ai-auditor/policy/manifest.json"
declare -a AUDITOR_USERS=()

load_auditor_users() {
    local identity_output
    ((${#AUDITOR_USERS[@]} == 0)) || return
    identity_output="$(python3 - "$IDENTITY_MANIFEST" <<'PY'
import json
import re
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if manifest.get("version") != "ai-auditor-policy-manifest/v1":
    raise SystemExit("compiled identity manifest has an unsupported version")
identities = manifest.get("identities", {}).get("identities")
if not isinstance(identities, list) or not identities:
    raise SystemExit("compiled identity manifest has no identities")
users = [identity.get("user") for identity in identities
         if isinstance(identity, dict)]
if len(users) != len(identities) or any(
        not isinstance(user, str)
        or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user) is None
        for user in users):
    raise SystemExit("compiled identity manifest contains an invalid user")
if len(users) != len(set(users)):
    raise SystemExit("compiled identity manifest contains duplicate users")
print("\n".join(sorted(users)))
PY
    )" || fail "could not load identities from the verified policy manifest"
    mapfile -t AUDITOR_USERS <<< "$identity_output"
    readonly -a AUDITOR_USERS
}

preflight_identities() {
    local user home actual_home actual_shell
    load_auditor_users
    for command in getent id install passwd useradd; do
        command -v "$command" >/dev/null || fail "required identity tool is missing: $command"
    done
    for user in "${AUDITOR_USERS[@]}"; do
        home="/opt/$user"
        if id "$user" >/dev/null 2>&1; then
            actual_home="$(getent passwd "$user" | cut -d: -f6)"
            actual_shell="$(getent passwd "$user" | cut -d: -f7)"
            [[ "$actual_home" == "$home" && "$actual_shell" == /bin/bash ]] \
                || fail "existing identity $user has unexpected home or shell"
        fi
    done
}

deploy_identities() {
    local user home
    echo "Deploying report identities"
    for user in "${AUDITOR_USERS[@]}"; do
        home="/opt/$user"
        if ! id "$user" >/dev/null 2>&1; then
            useradd --system --create-home --home-dir "$home" --shell /bin/bash \
                --comment "AI Auditor report identity" "$user"
        fi
        passwd -l "$user" >/dev/null 2>&1 || true
        install -d -o "$user" -g "$user" -m 0750 "$home"
        install -d -o "$user" -g "$user" -m 0700 "$home/.ssh"
    done
}
