#!/bin/bash

################################################################################
# Phase 1: Configure Sudoers
#
# Purpose: Deploy and validate sudoers configuration for ai-auditor
# Idempotent: Safe to run multiple times (creates backup)
# Dependencies: 10-create-user.sh and 20-setup-ssh-keys.sh must have run first
#
# Usage: sudo bash ./30-configure-sudoers.sh [-v|--verbose] [-h|--help]
#
# OPTIONS
#   -v, --verbose   Display detailed output for debugging
#   -h, --help      Display this help message
#
# Examples:
#   sudo bash ./30-configure-sudoers.sh
#   sudo bash ./30-configure-sudoers.sh -v
#
################################################################################

set -euo pipefail

# Configuration
AI_AUDITOR_USER="ai-auditor"
SUDOERS_DIR="/etc/sudoers.d"
SUDOERS_FILE="$SUDOERS_DIR/$AI_AUDITOR_USER"
SUDOERS_TEMPLATE="../../../../config/sudoers-ai-auditor-template"
SUDOERS_BACKUP="$SUDOERS_FILE.backup.$(date +%Y%m%d-%H%M%S)"

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
Phase 1: Configure Sudoers

SYNOPSIS
    sudo bash ./30-configure-sudoers.sh [-v|--verbose] [-h|--help]

OPTIONS
    -v, --verbose   Display detailed output for debugging
    -h, --help      Display this help message

EXAMPLES
    sudo bash ./30-configure-sudoers.sh
    sudo bash ./30-configure-sudoers.sh --verbose

DESCRIPTION
    Deploys Phase 1 sudoers configuration for ai-auditor with:
    - Single command: /usr/bin/uname -a
    - Environment: env_reset with explicit safe variables
    - Security: SSH-only (!requiretty), no password (NOPASSWD), secure_path
    - Logging: All commands logged to /var/log/sudo-ai-auditor.log
    - Fail-secure: Explicit DENY: ALL at end

PREREQUISITES
    - Must run with sudo or as root
    - 10-create-user.sh must have run first

DEPENDENCIES
    - Requires config/sudoers-ai-auditor-template file (from repo root)

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
# Step 1: Verify Prerequisites
################################################################################

verify_prerequisites() {
    log_info "Step 1: Verifying prerequisites"
    
    # Check if ai-auditor user exists
    if ! id "$AI_AUDITOR_USER" &>/dev/null; then
        log_error "User '$AI_AUDITOR_USER' does not exist"
        log_error "Please run 10-create-user.sh first"
        return 1
    fi
    
    log_info "✓ User '$AI_AUDITOR_USER' exists"
    
    # Check if sudoers template exists
    if [ ! -f "$SUDOERS_TEMPLATE" ]; then
        log_error "Sudoers template not found: $SUDOERS_TEMPLATE"
        log_error "Must be in same directory as this script"
        return 1
    fi
    
    log_info "✓ Sudoers template found"
    
    # Check if sudoers.d directory exists
    if [ ! -d "$SUDOERS_DIR" ]; then
        log_error "Sudoers.d directory not found: $SUDOERS_DIR"
        return 1
    fi
    
    log_info "✓ /etc/sudoers.d directory exists"
}

################################################################################
# Step 2: Backup Existing Sudoers (if exists)
################################################################################

backup_existing_sudoers() {
    log_info "Step 2: Backing up existing sudoers configuration"
    
    if [ -f "$SUDOERS_FILE" ]; then
        cp "$SUDOERS_FILE" "$SUDOERS_BACKUP"
        log_info "✓ Backup created: $SUDOERS_BACKUP"
    else
        log_info "No existing sudoers file to backup"
    fi
}

################################################################################
# Step 3: Deploy Sudoers Template
################################################################################

deploy_sudoers() {
    log_info "Step 3: Deploying sudoers configuration"
    
    # Copy template to sudoers.d
    cp "$SUDOERS_TEMPLATE" "$SUDOERS_FILE"
    
    log_info "✓ Sudoers file deployed to $SUDOERS_FILE"
}

################################################################################
# Step 4: Validate Sudoers Syntax
################################################################################

validate_sudoers_syntax() {
    log_info "Step 4: Validating sudoers syntax"
    
    # Use visudo to check syntax
    if visudo -c -f "$SUDOERS_FILE" &>/dev/null; then
        log_info "✓ Sudoers syntax is valid"
        return 0
    else
        log_error "Sudoers syntax validation failed!"
        log_error "Rolling back to previous configuration..."
        
        # Rollback on syntax error
        if [ -f "$SUDOERS_BACKUP" ]; then
            cp "$SUDOERS_BACKUP" "$SUDOERS_FILE"
            log_error "Restored from backup: $SUDOERS_BACKUP"
        else
            log_error "No backup available, removing invalid file"
            rm "$SUDOERS_FILE"
        fi
        
        return 1
    fi
}

################################################################################
# Step 5: Set Sudoers File Permissions
################################################################################

set_sudoers_permissions() {
    log_info "Step 5: Setting sudoers file permissions"
    
    # Sudoers files should be 0440 (r--r-----)
    chmod 440 "$SUDOERS_FILE"
    
    log_info "✓ Sudoers file permissions set to 440"
}

################################################################################
# Step 6: Verify Deployment
################################################################################

verify_deployment() {
    log_info "Step 6: Verifying deployment"
    
    local errors=0
    
    # Check file exists
    if [ ! -f "$SUDOERS_FILE" ]; then
        log_error "Sudoers file not found: $SUDOERS_FILE"
        ((errors++))
    else
        log_info "✓ Sudoers file exists"
    fi
    
    # Check file permissions
    local perms=$(stat -c %a "$SUDOERS_FILE" 2>/dev/null || stat -f %OLp "$SUDOERS_FILE" 2>/dev/null)
    if [ "$perms" = "440" ]; then
        log_info "✓ Permissions correct (440)"
    else
        log_warn "Permissions are $perms (expected 440)"
    fi
    
    # Check file content contains ai-auditor
    if grep -q "ai-auditor" "$SUDOERS_FILE"; then
        log_info "✓ File contains ai-auditor configuration"
    else
        log_error "File does not contain ai-auditor configuration"
        ((errors++))
    fi
    
    # Check for uname command
    if grep -q "/usr/bin/uname" "$SUDOERS_FILE"; then
        log_info "✓ File contains uname command"
    else
        log_error "File does not contain uname command"
        ((errors++))
    fi
    
    # Validate syntax one more time
    if visudo -c -f "$SUDOERS_FILE" &>/dev/null; then
        log_info "✓ Sudoers syntax valid"
    else
        log_error "Sudoers syntax invalid"
        ((errors++))
    fi
    
    return $errors
}

################################################################################
# Step 7: Display Test Instructions
################################################################################

display_test_instructions() {
    log_info "Step 7: Test instructions"
    
    echo ""
    echo "To test Phase 1 sudoers configuration:"
    echo ""
    echo "  # Test uname command (should work):"
    echo "  sudo -u ai-auditor sudo /usr/bin/uname -a"
    echo ""
    echo "  # Expected output: Linux [hostname] [version] ..."
    echo ""
    echo "  # Test denied command (should fail):"
    echo "  sudo -u ai-auditor sudo /bin/ls /root"
    echo ""
    echo "  # Expected output: ai-auditor is not allowed to run /bin/ls /root"
    echo ""
    echo "Phase 1 deployment complete. Proceed to Phase 2 when ready."
    echo ""
}

################################################################################
# Main Execution
################################################################################

main() {
    echo "=========================================="
    echo "Phase 1: Configure Sudoers"
    echo "=========================================="
    echo ""
    
    # Check for root/sudo
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run with sudo"
        exit 1
    fi
    
    # Execute steps
    verify_prerequisites || exit 1
    backup_existing_sudoers
    deploy_sudoers
    validate_sudoers_syntax || exit 1
    set_sudoers_permissions
    
    echo ""
    echo "=========================================="
    echo "Running Deployment Verification"
    echo "=========================================="
    echo ""
    
    if verify_deployment; then
        echo ""
        echo -e "${GREEN}=========================================="
        echo "✓ Phase 1 Sudoers Configuration Complete!"
        echo "=========================================="
        echo ""
        echo "Deployment details:"
        echo "  User: $AI_AUDITOR_USER"
        echo "  Sudoers file: $SUDOERS_FILE"
        echo "  Permissions: 440"
        echo ""
        display_test_instructions
        return 0
    else
        echo ""
        echo -e "${RED}=========================================="
        echo "✗ Phase 1 Sudoers Configuration Failed"
        echo "=========================================="
        echo ""
        return 1
    fi
}

main "$@"
