#!/bin/bash

################################################################################
# Phase 1.5: Harden SSH Configuration
#
# Purpose: Add security hardening for ai-auditor SSH access
# Idempotent: Safe to run multiple times (creates backup)
# Dependencies: 20-setup-ssh-keys.sh must have run first
#
# Usage: sudo bash ./25-harden-ssh-config.sh [-v|--verbose] [-h|--help]
#
# OPTIONS
#   -v, --verbose   Display detailed output for debugging
#   -h, --help      Display this help message
#
# Examples:
#   sudo bash ./25-harden-ssh-config.sh
#   sudo bash ./25-harden-ssh-config.sh -v
#
################################################################################

set -euo pipefail

################################################################################
# Script Setup
################################################################################

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)"
readonly DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common library for logging functions
if [ ! -f "$SCRIPT_DIR/lib/common.sh" ]; then
    echo "ERROR: lib/common.sh not found at $SCRIPT_DIR/lib/common.sh"
    echo "This script must be run from the repository"
    exit 1
fi

source "$SCRIPT_DIR/lib/common.sh"

# Configuration
AI_AUDITOR_USER="ai-auditor"
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_D="/etc/ssh/sshd_config.d"
SSH_HARDENING_FILE="$SSHD_CONFIG_D/50-ai-auditor-hardening.conf"
SSH_HARDENING_BACKUP="$SSH_HARDENING_FILE.backup.$(date +%Y%m%d-%H%M%S)"

################################################################################
# Help and Parameter Parsing
################################################################################

VERBOSE=false

show_help() {
    cat << 'EOF'
Phase 1.5: Harden SSH Configuration

SYNOPSIS
    sudo bash ./25-harden-ssh-config.sh [-v|--verbose] [-h|--help]

OPTIONS
    -v, --verbose   Display detailed output for debugging
    -h, --help      Display this help message

EXAMPLES
    sudo bash ./25-harden-ssh-config.sh
    sudo bash ./25-harden-ssh-config.sh -v

DESCRIPTION
    Hardens SSH daemon configuration for ai-auditor service account:
    - Disables password authentication (key-only)
    - Restricts auth attempts
    - Limits login grace time
    - Enables pubkey authentication only

    Uses /etc/ssh/sshd_config.d/50-ai-auditor-hardening.conf for portability
    across different SSH versions and distros.

WORKFLOW
    1. Create ai-auditor user: bash ../configure/10-create-user.sh
    2. Setup SSH keys: bash ../configure/20-setup-ssh-keys.sh
    3. Harden SSH config: sudo bash ./25-harden-ssh-config.sh
    4. Configure sudoers: sudo bash ./30-configure-sudoers.sh
    5. Verify: ssh -i key ai-auditor@localhost "sudo /usr/bin/uname -a"

PREREQUISITES
    - Must run with sudo or as root
    - SSH daemon must be running
    - ai-auditor user must exist

SECURITY SETTINGS
    - PasswordAuthentication: no (disable password login)
    - PubkeyAuthentication: yes (enable key-based auth)
    - MaxAuthTries: 2 (limit password attempt brute force)
    - LoginGraceTime: 20s (disconnect idle sessions quickly)

EOF
}

parse_parameters() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

parse_parameters "$@"

if [ "$VERBOSE" = true ]; then
    log_info "Verbose mode enabled"
    log_info "SSH hardening file: $SSH_HARDENING_FILE"
fi

################################################################################
# Check for Required Tools
################################################################################

require_root "This script must run with sudo or as root"
require_command "sshd" "SSH daemon (openssh-server package)"

################################################################################
# Step 1: Verify Prerequisites
################################################################################

verify_prerequisites() {
    log_info "Step 1: Verifying prerequisites"
    
    # Check if ai-auditor user exists
    if ! id "$AI_AUDITOR_USER" &>/dev/null; then
        log_error "User '$AI_AUDITOR_USER' does not exist"
        log_error "Please run ../configure/10-create-user.sh first"
        return 1
    fi
    
    log_info "✓ User '$AI_AUDITOR_USER' exists"
    
    # Check if sshd_config.d directory exists
    if [ ! -d "$SSHD_CONFIG_D" ]; then
        log_error "SSH config directory not found: $SSHD_CONFIG_D"
        return 1
    fi
    
    log_info "✓ SSH config directory exists"
}

################################################################################
# Step 2: Backup Existing Hardening Config
################################################################################

backup_existing_hardening() {
    log_info "Step 2: Backing up existing hardening configuration"
    
    if [ -f "$SSH_HARDENING_FILE" ]; then
        backup_file "$SSH_HARDENING_FILE" "$SSH_HARDENING_BACKUP"
        log_info "✓ Backup created: $SSH_HARDENING_BACKUP"
    else
        log_info "No existing hardening config to backup"
    fi
}

################################################################################
# Step 3: Generate SSH Hardening Configuration
################################################################################

generate_ssh_hardening() {
    log_info "Step 3: Generating SSH hardening configuration"
    
    cat > "$SSH_HARDENING_FILE" << 'SSHEOF'
################################################################################
# AI Auditor SSH Hardening
# 
# This file applies security hardening specifically for ai-auditor user.
# Uses sshd_config.d drop-in format for portability and clarity.
#
# Generated by: 25-harden-ssh-config.sh
# WARNING: Do not edit manually - changes will be lost on script re-run
################################################################################

# Restrict configuration to ai-auditor user
Match User ai-auditor
    # Authentication
    PasswordAuthentication no
    PubkeyAuthentication yes
    
    # Limit authentication attempts and time
    MaxAuthTries 2
    LoginGraceTime 20
    
    # Disable interactive login shell (key-only, automated commands)
    # Note: This does NOT prevent sudo commands via SSH
    
    # Log authentication attempts for audit
    LogLevel VERBOSE

SSHEOF
    
    chmod 644 "$SSH_HARDENING_FILE"
    log_info "✓ SSH hardening config created"
}

################################################################################
# Step 4: Validate SSH Configuration Syntax
################################################################################

validate_ssh_syntax() {
    log_info "Step 4: Validating SSH configuration syntax"
    
    # Use sshd -t to test configuration
    if sshd -t &>/dev/null; then
        log_info "✓ SSH configuration syntax is valid"
        return 0
    else
        log_error "SSH configuration syntax validation failed!"
        log_error "Rolling back to previous configuration..."
        
        # Rollback on syntax error
        if [ -f "$SSH_HARDENING_BACKUP" ]; then
            cp "$SSH_HARDENING_BACKUP" "$SSH_HARDENING_FILE"
            log_error "Restored from backup: $SSH_HARDENING_BACKUP"
        else
            rm "$SSH_HARDENING_FILE"
            log_error "Removed invalid hardening config"
        fi
        
        return 1
    fi
}

################################################################################
# Step 5: Reload SSH Configuration
################################################################################

reload_ssh_daemon() {
    log_info "Step 5: Reloading SSH daemon configuration"
    
    if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
        log_info "✓ SSH daemon reloaded (new connections use hardening)"
    else
        log_warn "SSH daemon not running (active connections won't be affected)"
        log_info "Hardening will take effect on next SSH daemon start"
    fi
}

################################################################################
# Step 6: Verify Hardening Configuration
################################################################################

verify_hardening() {
    log_info "Step 6: Verifying hardening configuration"
    
    # Check file exists and is readable
    if [ ! -f "$SSH_HARDENING_FILE" ]; then
        log_error "Hardening config file not found: $SSH_HARDENING_FILE"
        return 1
    fi
    
    log_info "✓ Hardening config file exists"
    
    # Check file permissions
    local perms=$(stat -c %a "$SSH_HARDENING_FILE" 2>/dev/null || stat -f %OLp "$SSH_HARDENING_FILE" 2>/dev/null)
    if [ "$perms" = "644" ]; then
        log_info "✓ Permissions correct (644)"
    else
        log_warn "Permissions are $perms (expected 644)"
    fi
    
    # Show what was configured
    log_info "Hardening settings applied:"
    grep "^[[:space:]]*[A-Z]" "$SSH_HARDENING_FILE" | sed 's/^/  /'
}

################################################################################
# Main Execution
################################################################################

main() {
    log_info ""
    log_info "========================================"
    log_info "Phase 1.5: Harden SSH Configuration"
    log_info "========================================"
    log_info ""
    
    verify_prerequisites || exit 1
    backup_existing_hardening
    generate_ssh_hardening || exit 1
    validate_ssh_syntax || exit 1
    reload_ssh_daemon
    verify_hardening || exit 1
    
    log_info ""
    log_info "========================================"
    log_success "SSH hardening completed successfully"
    log_info "========================================"
    log_info ""
    log_info "NEXT STEPS:"
    log_info "1. Test SSH access: ssh -i ~/.ssh/ai-auditor-ai-agent-server ai-auditor@localhost"
    log_info "2. Verify key-only auth works (password should be rejected)"
    log_info "3. Continue with: sudo bash ./30-configure-sudoers.sh"
    log_info ""
}

main
