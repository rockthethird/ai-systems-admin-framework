# Identity preflight and deployment stage. Sourced by deploy.sh.

readonly AUDITOR_USERS=("ai-auditor-cloud" "ai-auditor-local")

preflight_identities() {
    local user home actual_home actual_shell
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
