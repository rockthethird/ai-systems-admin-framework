#!/bin/bash

################################################################################
# Phase 1: Set Up SSH Key Authentication (Controller-side)
#
# Purpose: Generate SSH keypair on controller and deploy public key to server
# Idempotent: Safe to run multiple times
# Dependencies: 
#   - Must run ON CONTROLLER (not on server)
#   - Requires lib/common.sh (acts as safety guard if accidentally copied to server)
#   - SSH access to target server required
#
# Usage: bash ./20-setup-ssh-keys.sh -s <server-address> [-c <controller-name>] [-h]
#
# Examples:
#   # Use current machine's hostname as controller name (simplest)
#   bash ./20-setup-ssh-keys.sh -s user@192.168.1.100
#   
#   # Specify custom controller name
#   bash ./20-setup-ssh-keys.sh -s user@192.168.1.100 -c laptop-dev
#   bash ./20-setup-ssh-keys.sh -c controller-prod-01 -s ubuntu@prod-server.example.com
#
# If controller name (-c) is omitted, uses current machine's hostname:
#   CONTROLLER_NAME=$(hostname | cut -d. -f1)
#
# Result:
#   - Private key generated on controller at: ~/.ssh/ai-auditor-<controller-name>
#   - Public key deployed to server: /opt/ai-auditor/.ssh/authorized_keys
#   - Public key comment includes controller name for easy identification
#   - Private key never leaves controller machine
#
# Prerequisites:
#   1. 10-create-user.sh must have been run on server first
#   2. SSH access to server required (for deploying public key)
#   3. This script must be run FROM THE REPO (requires lib/common.sh)
#      If copied to server, it will fail with "common.sh not found" (intentional safety)
#
################################################################################

set -euo pipefail

################################################################################
# Source Common Library (REQUIRED - safety guard if copied to server)
################################################################################

# Get script directory and source common.sh from repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_LIB="$SCRIPT_DIR/../../../lib/common.sh"

if [ ! -f "$COMMON_LIB" ]; then
    echo "ERROR: common.sh not found at: $COMMON_LIB"
    echo ""
    echo "=========================================="
    echo "SCRIPT LOCATION CHECK"
    echo "=========================================="
    echo ""
    echo "This script is designed to run on the CONTROLLER/CLIENT machine,"
    echo "not on the server. The lib/common.sh dependency acts as an intentional"
    echo "safety guard to prevent accidental execution in the wrong location."
    echo ""
    echo "Script 20 (20-setup-ssh-keys.sh) runs on:  CONTROLLER/CLIENT (your machine)"
    echo "Scripts 10 & 30 run on:                    SERVER (target machine)"
    echo ""
    echo "If you accidentally copied this script to the server, please:"
    echo "  1. Delete it from the server: rm 20-setup-ssh-keys.sh"
    echo "  2. Run this script from the CONTROLLER only"
    echo ""
    echo "Proper usage on CONTROLLER:"
    echo "  cd /path/to/ai-systems-admin-framework"
    echo "  bash modules/audit/deploy/20-setup-ssh-keys.sh -s user@server"
    echo ""
    echo "Copy ONLY scripts 10 and 30 to server:"
    echo "  scp modules/audit/deploy/{10-create-user.sh,30-configure-sudoers.sh,...} user@server:/tmp/"
    echo ""
    exit 1
fi

source "$COMMON_LIB"

################################################################################
# Initialize Variables
################################################################################

CONTROLLER_MACHINE=""
SERVER_ADDRESS=""

################################################################################
# Script-Specific Functions
# (These override/extend the common library functions)
################################################################################

show_help() {
    cat << 'EOF'
Phase 1: Set Up SSH Key Authentication (Controller-side)

SYNOPSIS
    bash ./20-setup-ssh-keys.sh -s <server-address> [-c <controller-name>] [-h]

OPTIONS
    -s, --server <address>      Server address (user@host or IP) [REQUIRED]
                                Examples: user@192.168.1.100, ubuntu@prod-server.example.com
    
    -c, --controller <name>     Controller machine name for identification [OPTIONAL]
                                Defaults to current machine hostname if not specified
                                Examples: laptop-dev, controller-prod-01, ci-pipeline-jenkins
    
    -h, --help                  Display this help message

EXAMPLES
    # Use current hostname as controller name (simplest)
    bash ./20-setup-ssh-keys.sh -s user@192.168.1.100

    # Specify custom controller name
    bash ./20-setup-ssh-keys.sh -s user@192.168.1.100 -c laptop-dev

    # Parameters can be in any order
    bash ./20-setup-ssh-keys.sh -c prod-01 -s ubuntu@prod-server.example.com

RESULT
    - Private key generated on controller at: ~/.ssh/ai-auditor-<controller-name>
    - Public key deployed to server: /opt/ai-auditor/.ssh/authorized_keys
    - Public key comment includes controller name for easy identification
    - Private key never leaves controller machine

PREREQUISITES
    1. 10-create-user.sh must have been run on server first
    2. SSH access to server required for deploying public key

EOF
}

parse_parameters() {
    # Step 1: Parse standard flags from common.sh (-h, --help, -v, --verbose)
    # Uses nameref pattern for cleaner API (Bash 4.3+)
    local consumed=0
    parse_standard_flags_nameref "$@" consumed
    shift $consumed
    
    # Step 2: Parse script-specific flags (-s, -c)
    # Now $@ contains remaining arguments (custom flags)
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--server)
                if [ -z "${2:-}" ]; then
                    log_error "Server address required for -s/--server"
                    exit 1
                fi
                SERVER_ADDRESS="$2"
                shift 2
                ;;
            -c|--controller)
                if [ -z "${2:-}" ]; then
                    log_error "Controller name required for -c/--controller"
                    exit 1
                fi
                CONTROLLER_MACHINE="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                log_error "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Step 3: Check if help was requested (set by parse_standard_flags)
    if [[ "${HELP_REQUESTED:-false}" == "true" ]]; then
        show_help
        exit 0
    fi
}

# Parse command line parameters
parse_parameters "$@"

# Set default controller machine name if not provided
if [ -z "$CONTROLLER_MACHINE" ]; then
    # Use current machine hostname (remove domain if present)
    CONTROLLER_MACHINE=$(hostname | cut -d. -f1)
fi

# Configuration
AI_AUDITOR_USER="ai-auditor"
SSH_DIR="$HOME/.ssh"
PRIVATE_KEY_PATH="$SSH_DIR/ai-auditor-$CONTROLLER_MACHINE"
PUBLIC_KEY_PATH="$PRIVATE_KEY_PATH.pub"

# Key settings
KEY_TYPE="ed25519"
KEY_COMMENT="${CONTROLLER_MACHINE}@auditing-framework"
KEY_PASSPHRASE=""  # No passphrase for automation

################################################################################
# Step 1: Verify Parameters
################################################################################

verify_parameters() {
    log_info "Step 1: Verifying parameters"
    
    # Check if server address was provided
    if [ -z "$SERVER_ADDRESS" ]; then
        log_error "Server address not provided"
        log_error "Use -h or --help for usage information"
        return 1
    fi
    
    log_info "✓ Controller machine: $CONTROLLER_MACHINE"
    log_info "✓ Server address: $SERVER_ADDRESS"
}

################################################################################
# Step 2: Verify SSH Access to Server
################################################################################

verify_ssh_access() {
    log_info "Step 2: Verifying SSH access to server"
    
    if ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$SERVER_ADDRESS" "echo 'SSH connection successful'" &>/dev/null; then
        log_error "Cannot SSH to server: $SERVER_ADDRESS"
        log_error "Please verify:"
        log_error "  1. Server address is correct"
        log_error "  2. SSH access is available"
        log_error "  3. SSH key is configured (if needed)"
        return 1
    fi
    
    log_info "✓ SSH access to server verified"
}

################################################################################
# Step 3: Verify ai-auditor User Exists on Server
################################################################################

verify_server_setup() {
    log_info "Step 3: Verifying ai-auditor account exists on server"
    
    if ! ssh "$SERVER_ADDRESS" "id $AI_AUDITOR_USER &>/dev/null" 2>/dev/null; then
        log_error "User '$AI_AUDITOR_USER' does not exist on server"
        log_error "Please run 10-create-user.sh on the server first"
        return 1
    fi
    
    log_info "✓ User '$AI_AUDITOR_USER' exists on server"
    
    # Note: .ssh directory existence will be verified during key deployment
    # If it doesn't exist, deployment will fail anyway
}

################################################################################
# Step 4: Generate SSH Key Pair (on controller)
################################################################################

generate_ssh_keys() {
    log_info "Step 4: Generating SSH key pair on controller"
    
    # Ensure .ssh directory exists on controller
    if [ ! -d "$SSH_DIR" ]; then
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
        log_info "✓ Created ~/.ssh directory on controller"
    fi
    
    # Check if keys already exist
    if [ -f "$PRIVATE_KEY_PATH" ] && [ -f "$PUBLIC_KEY_PATH" ]; then
        log_warn "SSH keys already exist for controller '$CONTROLLER_MACHINE'"
        log_warn "Keys at: $PRIVATE_KEY_PATH"
        log_warn "Skipping key generation"
        return 0
    fi
    
    log_info "Generating $KEY_TYPE key pair..."
    log_info "Key comment: $KEY_COMMENT"
    
    # Generate key without passphrase
    ssh-keygen -t "$KEY_TYPE" \
        -f "$PRIVATE_KEY_PATH" \
        -C "$KEY_COMMENT" \
        -N "$KEY_PASSPHRASE" \
        -q
    
    log_info "✓ SSH key pair generated on controller"
    log_info "  Private key: $PRIVATE_KEY_PATH"
    log_info "  Public key:  $PUBLIC_KEY_PATH"
}

################################################################################
# Step 5: Deploy Public Key to Server
################################################################################

deploy_public_key() {
    log_info "Step 5: Deploying public key to server"
    
    if [ ! -f "$PUBLIC_KEY_PATH" ]; then
        log_error "Public key not found: $PUBLIC_KEY_PATH"
        return 1
    fi
    
    # Read public key
    local pubkey_content=$(cat "$PUBLIC_KEY_PATH")
    
    # Deploy public key using ssh-copy-id (handles .ssh directory and permissions)
    # First, add to rock's .ssh/authorized_keys to establish trust
    if ssh-copy-id -i "$PUBLIC_KEY_PATH" "$SERVER_ADDRESS" > /dev/null 2>&1; then
        log_info "✓ Public key deployed successfully"
        log_info "  Location: ~/.ssh/authorized_keys on $SERVER_ADDRESS"
        log_info "  Controller: $CONTROLLER_MACHINE"
        log_info "  Comment: $KEY_COMMENT"
    else
        log_error "Failed to deploy public key"
        log_error "Ensure SSH access is available and password authentication works"
        return 1
    fi
}

################################################################################
# Step 6: Verify Configuration
################################################################################

verify_deployment() {
    log_info "Step 6: Verifying SSH configuration"
    
    local errors=0
    
    # Check private key exists on controller
    if [ ! -f "$PRIVATE_KEY_PATH" ]; then
        log_error "Private key missing on controller"
        ((errors++))
    else
        log_info "✓ Private key exists on controller"
    fi
    
    # Check public key exists on server
    if ! ssh "$SERVER_ADDRESS" "grep -q '$KEY_COMMENT' ~/.ssh/authorized_keys" 2>/dev/null; then
        log_error "Public key not found on server"
        ((errors++))
    else
        log_info "✓ Public key deployed to server with correct identifier"
    fi
    
    # List all authorized keys on server
    log_info "Authorized keys on server:"
    ssh "$SERVER_ADDRESS" "grep @ ~/.ssh/authorized_keys 2>/dev/null | sed 's/^/  - /'" || log_info "  (none found)"
    
    return $errors
}

################################################################################
# Step 7: Test SSH Access
################################################################################

test_ssh_connection() {
    log_info "Step 7: Testing SSH connection with generated key"
    
    if ssh -i "$PRIVATE_KEY_PATH" -o ConnectTimeout=5 "$SERVER_ADDRESS" "whoami" &>/dev/null; then
        log_info "✓ SSH connection with new key works"
    else
        log_warn "Could not verify SSH connection with new key"
        log_warn "You may need to accept host key or configure SSH further"
    fi
}

################################################################################
# Main Execution
################################################################################

main() {
    echo "=========================================="
    echo "Phase 1: Set Up SSH Key Authentication"
    echo "=========================================="
    echo ""
    
    # Execute steps
    verify_parameters || exit 1
    verify_ssh_access || exit 1
    verify_server_setup || exit 1
    generate_ssh_keys
    deploy_public_key || exit 1
    
    echo ""
    echo "=========================================="
    echo "Running SSH Configuration Verification"
    echo "=========================================="
    echo ""
    
    if verify_deployment; then
        test_ssh_connection
        
        echo ""
        echo -e "${GREEN}=========================================="
        echo "✓ Phase 1 SSH Setup Complete!"
        echo "=========================================="
        echo ""
        echo "Key Details:"
        echo "  Controller: $CONTROLLER_MACHINE"
        echo "  Server: $SERVER_ADDRESS"
        echo "  Comment: $KEY_COMMENT"
        echo "  Private key: $PRIVATE_KEY_PATH"
        echo "  Public key deployed to: /opt/$AI_AUDITOR_USER/.ssh/authorized_keys"
        echo ""
        echo "You can now SSH to the server as ai-auditor:"
        echo "  ssh -i $PRIVATE_KEY_PATH $AI_AUDITOR_USER@<server>"
        echo ""
        echo "Next steps:"
        echo "  1. On SERVER: Run sudo bash 30-configure-sudoers.sh to complete Phase 1"
        echo ""
        return 0
    else
        echo ""
        echo -e "${RED}=========================================="
        echo "✗ Phase 1 SSH Setup Failed - Verification Errors"
        echo "=========================================="
        echo ""
        return 1
    fi
}

main "$@"
