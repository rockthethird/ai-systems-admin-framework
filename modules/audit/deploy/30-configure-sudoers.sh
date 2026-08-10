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
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AI_AUDITOR_USER="ai-auditor"
SUDOERS_DIR="/etc/sudoers.d"
SUDOERS_FILE="$SUDOERS_DIR/$AI_AUDITOR_USER"
SUDOERS_DEFAULT="$SCRIPT_DIR/../build/sudoers-ai-auditor-generated"
SUDOERS_BACKUP="$SUDOERS_FILE.backup.$(date +%Y%m%d-%H%M%S)"
SUDOERS_SOURCE=""  # Set by parameter parsing or default
SUDOERS_CANDIDATE=""

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
    sudo bash ./30-configure-sudoers.sh [-f FILE] [-v|--verbose] [-h|--help]

OPTIONS
    -f, --file FILE File to deploy (default: build/sudoers-ai-auditor-generated)
    -v, --verbose   Display detailed output for debugging
    -h, --help      Display this help message

EXAMPLES
    sudo bash ./30-configure-sudoers.sh
    sudo bash ./30-configure-sudoers.sh --file /tmp/sudoers-custom
    sudo bash ./30-configure-sudoers.sh -f ../build/sudoers-ai-auditor-generated -v

DESCRIPTION
    Deploys sudoers configuration for ai-auditor with:
    - Environment: env_reset with explicit safe variables
    - Security: SSH-only (!requiretty), no password (NOPASSWD), secure_path
    - Logging: All commands logged to /var/log/sudo-ai-auditor.log

    By default uses:
    - Generated sudoers: build/sudoers-ai-auditor-generated (from build script)

PREREQUISITES
    - Must run with sudo or as root
    - 10-create-user.sh must have run first

WORKFLOW
    1. Generate artifact: bash ../build/10-generate-sudoers-from-yaml.sh
    2. Deploy generated: sudo bash ./30-configure-sudoers.sh
    3. Or deploy custom: sudo bash ./30-configure-sudoers.sh -f /custom/sudoers
    4. Verify: sudo -l -U ai-auditor

EOF
}

parse_parameters() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -f|--file)
                SUDOERS_SOURCE="$2"
                shift 2
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
# Check for Required Tools
################################################################################

# Check if visudo is available (optional)
HAVE_VISUDO=false
if command -v visudo &>/dev/null; then
    HAVE_VISUDO=true
fi

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

    if [ "$HAVE_VISUDO" = false ]; then
        log_error "visudo is required; refusing to deploy an unvalidated policy"
        return 1
    fi
    
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
    log_info "Step 3: Preparing sudoers configuration"
    
    # Use specified file, default, or fallback
    local sudoers_file=""
    
    if [ -n "$SUDOERS_SOURCE" ]; then
        # User specified with -f flag
        sudoers_file="$SUDOERS_SOURCE"
        log_info "Using specified sudoers file: $sudoers_file"
    elif [ -f "$SUDOERS_DEFAULT" ]; then
        # Use generated sudoers
        sudoers_file="$SUDOERS_DEFAULT"
        log_info "Using generated sudoers: $sudoers_file"
    else
        log_error "No sudoers file found:"
        log_error "  Generated: $SUDOERS_DEFAULT"
        log_error "Run build script first: bash ../build/10-generate-sudoers-from-yaml.sh"
        return 1
    fi
    
    # Verify file exists
    if [ ! -f "$sudoers_file" ]; then
        log_error "Sudoers file not found: $sudoers_file"
        return 1
    fi
    
    SUDOERS_CANDIDATE=$(mktemp "$SUDOERS_DIR/.ai-auditor.XXXXXX")
    install -o root -g root -m 0440 "$sudoers_file" "$SUDOERS_CANDIDATE"
    log_info "✓ Root-owned candidate prepared"
}

################################################################################
# Step 4: Validate Sudoers Syntax
################################################################################

validate_sudoers_syntax() {
    log_info "Step 4: Validating sudoers syntax"
    
    # Skip validation if visudo not available
    if [ "$HAVE_VISUDO" = false ]; then
        log_warn "visudo not available - skipping syntax validation"
        log_warn "(Install 'sudo' package for syntax validation)"
        return 0
    fi
    
    # Use visudo to check syntax
    if visudo -c -f "$SUDOERS_CANDIDATE" &>/dev/null; then
        log_info "✓ Sudoers syntax is valid"
        mv -f "$SUDOERS_CANDIDATE" "$SUDOERS_FILE"
        SUDOERS_CANDIDATE=""
        log_info "✓ Sudoers configuration activated atomically"
        return 0
    else
        log_error "Sudoers syntax validation failed!"
        rm -f "$SUDOERS_CANDIDATE"
        SUDOERS_CANDIDATE=""
        log_error "Existing configuration was left unchanged"
        return 1
    fi
}

################################################################################
# Step 5: Set Sudoers File Permissions
################################################################################

set_sudoers_permissions() {
    log_info "Step 5: Setting sudoers file permissions"
    
    # Sudoers files should be 0440 (r--r-----)
    chown root:root "$SUDOERS_FILE"
    chmod 0440 "$SUDOERS_FILE"
    
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
        errors=$((errors + 1))
    else
        log_info "✓ Sudoers file exists"
    fi
    
    # Check file permissions
    local perms=$(stat -c %a "$SUDOERS_FILE" 2>/dev/null || stat -f %OLp "$SUDOERS_FILE" 2>/dev/null)
    if [ "$perms" = "440" ]; then
        log_info "✓ Permissions correct (440)"
    else
        log_error "Permissions are $perms (expected 440)"
        errors=$((errors + 1))
    fi
    
    # Check file content contains ai-auditor
    if grep -q "ai-auditor" "$SUDOERS_FILE"; then
        log_info "✓ File contains ai-auditor configuration"
    else
        log_error "File does not contain ai-auditor configuration"
        errors=$((errors + 1))
    fi
    
    if grep -q "/usr/local/libexec/ai-auditor-report" "$SUDOERS_FILE"; then
        log_info "✓ File contains sanitized report endpoint"
    else
        log_error "File does not contain sanitized report endpoint"
        errors=$((errors + 1))
    fi

    if grep -q "/usr/local/libexec/ai-auditor-inventory" "$SUDOERS_FILE"; then
        log_error "File unexpectedly exposes the raw inventory collector"
        errors=$((errors + 1))
    else
        log_info "✓ Raw inventory collector is not exposed through sudo"
    fi

    local owner
    owner=$(stat -c %U:%G "$SUDOERS_FILE")
    if [ "$owner" = "root:root" ]; then
        log_info "✓ Ownership correct (root:root)"
    else
        log_error "Ownership is $owner (expected root:root)"
        errors=$((errors + 1))
    fi
    
    if visudo -c -f "$SUDOERS_FILE" &>/dev/null; then
        log_info "✓ Sudoers syntax valid"
    else
        log_error "Sudoers syntax invalid"
        errors=$((errors + 1))
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
    echo "  # Test sanitized report endpoint (should emit JSON):"
    echo "  sudo -u ai-auditor sudo -n /usr/local/libexec/ai-auditor-report"
    echo ""
    echo "  # Expected output: one external-safe findings document"
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
