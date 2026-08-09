#!/bin/bash

################################################################################
# Phase 1: Create AI Auditor Service Account
#
# Purpose: Create restricted user account with SSH-only access
# Idempotent: Safe to run multiple times
# Dependencies: Must run as root/sudo
#
# Usage: sudo bash ./10-create-user.sh [-v|--verbose] [-h|--help]
#
# OPTIONS
#   -v, --verbose   Display detailed output for debugging
#   -h, --help      Display this help message
#
# Examples:
#   sudo bash ./10-create-user.sh
#   sudo bash ./10-create-user.sh -v
#
################################################################################

set -euo pipefail

# Configuration
AI_AUDITOR_USER="ai-auditor"
AI_AUDITOR_HOME="/opt/ai-auditor"
AI_AUDITOR_COMMENT="AI Security Auditor"
AI_AUDITOR_SHELL="/bin/bash"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

################################################################################
# Logging Functions
################################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

################################################################################
# Help and Parameter Parsing
################################################################################

VERBOSE=false

show_help() {
    cat << 'EOF'
Phase 1: Create AI Auditor Service Account

SYNOPSIS
    sudo bash ./10-create-user.sh [-v|--verbose] [-h|--help]

OPTIONS
    -v, --verbose   Display detailed output for debugging
    -h, --help      Display this help message

EXAMPLES
    sudo bash ./10-create-user.sh
    sudo bash ./10-create-user.sh --verbose

DESCRIPTION
    Creates the 'ai-auditor' service account with:
    - UID < 1000 (system account)
    - SSH-only authentication (password locked)
    - Shell: /bin/bash with minimal bashrc
    - Home directory: /opt/ai-auditor with 750 permissions
    - SSH directory: /opt/ai-auditor/.ssh with 700 permissions

PREREQUISITES
    Must run with sudo or as root

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
                log_error "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
}

parse_parameters "$@"

################################################################################
# Step 1: Create User Account
################################################################################

create_user() {
    log_info "Step 1: Creating user account '$AI_AUDITOR_USER'"
    
    # Check if user already exists
    if id "$AI_AUDITOR_USER" &>/dev/null; then
        log_warn "User '$AI_AUDITOR_USER' already exists, skipping creation"
        return 0
    fi
    
    # Create user with home directory
    useradd \
        --system \
        --create-home \
        --home-dir "$AI_AUDITOR_HOME" \
        --shell "$AI_AUDITOR_SHELL" \
        --comment "$AI_AUDITOR_COMMENT" \
        "$AI_AUDITOR_USER"
    
    log_info "✓ User account created successfully"
}

################################################################################
# Step 2: Verify User Creation
################################################################################

verify_user() {
    log_info "Verifying user account"
    
    if ! id "$AI_AUDITOR_USER" &>/dev/null; then
        log_error "User '$AI_AUDITOR_USER' was not created successfully"
        return 1
    fi
    
    # Check UID (should be < 1000 for system account)
    local uid=$(id -u "$AI_AUDITOR_USER")
    if [ "$uid" -lt 1000 ]; then
        log_info "✓ User UID is $uid (system account)"
    else
        log_warn "User UID is $uid (not a system account, might be OK)"
    fi
    
    # Check home directory
    if [ -d "$AI_AUDITOR_HOME" ]; then
        log_info "✓ Home directory exists: $AI_AUDITOR_HOME"
    else
        log_error "Home directory does not exist: $AI_AUDITOR_HOME"
        return 1
    fi
    
    # Check shell
    local shell=$(getent passwd "$AI_AUDITOR_USER" | cut -d: -f7)
    if [ "$shell" = "$AI_AUDITOR_SHELL" ]; then
        log_info "✓ Shell is correctly set to $AI_AUDITOR_SHELL"
    else
        log_error "Shell is $shell, expected $AI_AUDITOR_SHELL"
        return 1
    fi
}

################################################################################
# Step 3: Configure Shell Environment
################################################################################

configure_shell() {
    log_info "Step 2: Configuring shell environment"
    
    # Create minimal .bashrc
    tee "$AI_AUDITOR_HOME/.bashrc" > /dev/null <<'EOF'
# Minimal shell for ai-auditor account
# No interactive features, minimal functionality

# Set safe defaults
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HISTFILE=/dev/null
export HISTSIZE=0
export HISTFILESIZE=0

# Minimal prompt
PS1='ai-auditor$ '
EOF
    
    # Set permissions and ownership
    chmod 644 "$AI_AUDITOR_HOME/.bashrc"
    chown "$AI_AUDITOR_USER:$AI_AUDITOR_USER" "$AI_AUDITOR_HOME/.bashrc"
    
    log_info "✓ Shell configuration created"
}

################################################################################
# Step 4: Configure Home Directory Permissions
################################################################################

configure_permissions() {
    log_info "Step 3: Configuring home directory permissions"
    
    # Set home directory permissions
    chmod 750 "$AI_AUDITOR_HOME"
    chown "$AI_AUDITOR_USER:$AI_AUDITOR_USER" "$AI_AUDITOR_HOME"
    
    log_info "✓ Home directory permissions set (750)"
}

################################################################################
# Step 5: Lock the Account (No Password)
################################################################################

lock_password() {
    log_info "Step 4: Locking account password"
    
    # Lock the account (disable password login)
    passwd -l "$AI_AUDITOR_USER" 2>/dev/null || true
    
    # Verify account is locked (if LK flag present, or just continue if unsure)
    local status=$(passwd --status "$AI_AUDITOR_USER" 2>&1)
    if echo "$status" | grep -q "LK"; then
        log_info "✓ Account password is locked"
    else
        log_warn "Account lock status unclear: $status (continuing anyway)"
    fi
}

################################################################################
# Step 6: Set Up SSH Directory Structure
################################################################################

setup_ssh_directory() {
    log_info "Step 5: Setting up SSH directory structure"
    
    local ssh_dir="$AI_AUDITOR_HOME/.ssh"
    
    # Create .ssh directory
    if [ ! -d "$ssh_dir" ]; then
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
        chown "$AI_AUDITOR_USER:$AI_AUDITOR_USER" "$ssh_dir"
        log_info "✓ SSH directory created: $ssh_dir"
    else
        log_warn "SSH directory already exists: $ssh_dir"
    fi
}

################################################################################
# Step 7: Final Verification
################################################################################

final_verification() {
    log_info "Step 6: Final verification"
    
    local errors=0
    
    # Check user exists
    if ! id "$AI_AUDITOR_USER" &>/dev/null; then
        log_error "User does not exist"
        ((errors++))
    else
        log_info "✓ User exists"
    fi
    
    # Check home directory
    if [ ! -d "$AI_AUDITOR_HOME" ]; then
        log_error "Home directory does not exist"
        ((errors++))
    else
        log_info "✓ Home directory exists"
    fi
    
    # Check .bashrc
    if [ ! -f "$AI_AUDITOR_HOME/.bashrc" ]; then
        log_error ".bashrc does not exist"
        ((errors++))
    else
        log_info "✓ .bashrc exists"
    fi
    
    # Check .ssh directory
    if [ ! -d "$AI_AUDITOR_HOME/.ssh" ]; then
        log_error ".ssh directory does not exist"
        ((errors++))
    else
        log_info "✓ .ssh directory exists"
    fi
    
    # Check password is locked
    local status=$(sudo passwd --status "$AI_AUDITOR_USER" 2>&1)
    if echo "$status" | grep -q "LK"; then
        log_info "✓ Account password is locked"
    else
        log_error "Account password is not locked"
        ((errors++))
    fi
    
    return $errors
}

################################################################################
# Main Execution
################################################################################

main() {
    echo "=========================================="
    echo "Phase 1: Create AI Auditor User Account"
    echo "=========================================="
    echo ""
    
    # Check for root/sudo
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
    
    # Execute steps
    create_user
    verify_user || exit 1
    configure_shell
    configure_permissions
    lock_password  # Non-fatal if already locked
    setup_ssh_directory
    
    echo ""
    echo "=========================================="
    echo "Running Final Verification"
    echo "=========================================="
    echo ""
    
    if final_verification; then
        echo ""
        echo -e "${GREEN}=========================================="
        echo "✓ User 'ai-auditor' created successfully!"
        echo "=========================================="
        echo ""
        echo "Next steps:"
        echo "  1. On CONTROLLER machine: Run script 20-setup-ssh-keys.sh (from repo)"
        echo "  2. Return to SERVER and run: sudo bash 30-configure-sudoers.sh"
        echo ""
        return 0
    else
        echo ""
        echo -e "${RED}=========================================="
        echo "✗ Phase 1 Setup Failed - Verification Errors"
        echo "=========================================="
        echo ""
        return 1
    fi
}

main "$@"
