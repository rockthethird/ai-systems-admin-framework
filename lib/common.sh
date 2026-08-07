#!/bin/bash

################################################################################
# Common Utilities Library
#
# Purpose: Reusable functions for scripts that run on the controller
#          (validation, testing, management scripts)
#
# Note: For setup scripts (10, 20, 30) that may be copied remotely,
#       do NOT source this file. Keep them self-contained.
#
# Usage in scripts:
#   source "$(dirname "$0")/../../lib/common.sh"  # Adjust path as needed
#
# Or from repo root:
#   source ./lib/common.sh
#
# Then use:
#   log_info "Message"
#   log_warn "Warning"
#   log_error "Error"
#   show_help
#   parse_parameters "$@"
#
################################################################################

################################################################################
# Color Codes and Output
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

log_debug() {
    if [[ "${VERBOSE:-false}" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $*"
    fi
}

log_success() {
    echo -e "${GREEN}✓${NC} $*"
}

log_failure() {
    echo -e "${RED}✗${NC} $*"
}

################################################################################
# Section Headers (for output formatting)
################################################################################

section_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$*${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

section_end() {
    echo ""
}

################################################################################
# Nameref-based Parameter Parsing (Bash 4.3+)
# Cleaner API for controller-side scripts
################################################################################

# Parse standard flags with nameref output
# Usage: parse_standard_flags_nameref "$@" consumed_var
#
# Sets: 
#   - HELP_REQUESTED=true, VERBOSE=true (if flags present)
#   - consumed_var set to number of arguments consumed
#
# Parameters:
#   $1..n-1: Arguments to parse
#   $n:      NAME of variable to receive consumed count
#
# Requires: Bash 4.3+ (nameref support)
#
parse_standard_flags_nameref() {
    # Extract the variable name (last argument)
    local var_name="${@: -1}"
    local -n consumed_ref="$var_name"
    consumed_ref=0
    
    # Parse first through next-to-last arguments
    local i=1
    local argc=$#
    while (( i < argc )); do
        case "${@:i:1}" in
            -h|--help)
                HELP_REQUESTED=true
                consumed_ref=$((consumed_ref + 1))
                ;;
            -v|--verbose)
                VERBOSE=true
                consumed_ref=$((consumed_ref + 1))
                ;;
            *)
                # Not a standard flag, stop parsing
                break
                ;;
        esac
        ((i++))
    done
}

################################################################################
# Configuration Validation
################################################################################

# Check if required command exists
require_command() {
    local cmd="$1"
    
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Required command not found: $cmd"
        return 1
    fi
    return 0
}

# Check if required file exists
require_file() {
    local file="$1"
    local description="${2:-}"
    
    if [ ! -f "$file" ]; then
        log_error "Required file not found: $file"
        if [ -n "$description" ]; then
            log_error "  Description: $description"
        fi
        return 1
    fi
    return 0
}

# Check if user is root
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        return 1
    fi
    return 0
}

# Check if running on specific machine (by hostname)
require_host() {
    local expected_host="$1"
    local actual_host=$(hostname)
    
    if [ "$actual_host" != "$expected_host" ]; then
        log_error "This script must run on host: $expected_host"
        log_error "Currently running on: $actual_host"
        return 1
    fi
    return 0
}

################################################################################
# File Operations
################################################################################

# Safely backup a file with timestamp
backup_file() {
    local file="$1"
    
    if [ ! -f "$file" ]; then
        log_error "Cannot backup non-existent file: $file"
        return 1
    fi
    
    local backup="${file}.backup.$(date +%Y%m%d-%H%M%S)"
    cp "$file" "$backup"
    log_info "Backed up: $file → $backup"
    echo "$backup"  # Return backup path
}

# Restore file from backup
restore_file() {
    local backup="$1"
    local original="${backup%.backup.*}"
    
    if [ ! -f "$backup" ]; then
        log_error "Backup file not found: $backup"
        return 1
    fi
    
    cp "$backup" "$original"
    log_info "Restored: $backup → $original"
}

################################################################################
# Test Result Tracking
################################################################################

# Initialize test counter
TEST_PASSED=0
TEST_FAILED=0
TEST_SKIPPED=0

# Record a passed test
test_pass() {
    local description="$1"
    ((TEST_PASSED++))
    log_success "$description"
}

# Record a failed test
test_fail() {
    local description="$1"
    ((TEST_FAILED++))
    log_failure "$description"
}

# Record a skipped test
test_skip() {
    local description="$1"
    ((TEST_SKIPPED++))
    log_warn "SKIPPED: $description"
}

# Display test summary
test_summary() {
    echo ""
    section_header "Test Summary"
    log_info "Passed:  $TEST_PASSED"
    log_info "Failed:  $TEST_FAILED"
    log_info "Skipped: $TEST_SKIPPED"
    echo ""
    
    if [ $TEST_FAILED -eq 0 ]; then
        log_success "All tests completed successfully"
        return 0
    else
        log_error "$TEST_FAILED test(s) failed"
        return 1
    fi
}

################################################################################
# Verification Counters
################################################################################

# Initialize verification counter
VERIFY_PASSED=0
VERIFY_FAILED=0

# Record verification pass
verify_pass() {
    local check="$1"
    ((VERIFY_PASSED++))
    log_success "$check"
}

# Record verification fail
verify_fail() {
    local check="$1"
    ((VERIFY_FAILED++))
    log_failure "$check"
}

# Display verification summary
verify_summary() {
    echo ""
    section_header "Verification Summary"
    log_info "Passed: $VERIFY_PASSED"
    log_info "Failed: $VERIFY_FAILED"
    echo ""
    
    if [ $VERIFY_FAILED -eq 0 ]; then
        log_success "All verifications passed"
        return 0
    else
        log_error "$VERIFY_FAILED verification(s) failed"
        return 1
    fi
}

################################################################################
# Common Checks
################################################################################

# Check if ai-auditor user exists
check_ai_auditor_user() {
    if id "ai-auditor" &>/dev/null; then
        return 0
    else
        log_error "User 'ai-auditor' does not exist"
        return 1
    fi
}

# Check if ai-auditor home exists
check_ai_auditor_home() {
    if [ -d "/opt/ai-auditor" ]; then
        return 0
    else
        log_error "Directory '/opt/ai-auditor' does not exist"
        return 1
    fi
}

# Check if ai-auditor sudoers config exists
check_ai_auditor_sudoers() {
    if [ -f "/etc/sudoers.d/ai-auditor" ]; then
        return 0
    else
        log_error "Sudoers file '/etc/sudoers.d/ai-auditor' does not exist"
        return 1
    fi
}

# Check SSH key deployment to server
check_ssh_key_deployed() {
    local server_address="$1"
    local controller_name="$2"
    
    if ssh -o ConnectTimeout=5 "$server_address" "grep -q '$controller_name' /opt/ai-auditor/.ssh/authorized_keys" 2>/dev/null; then
        return 0
    else
        log_error "SSH key for '$controller_name' not found on server"
        return 1
    fi
}

################################################################################
# Utility Functions
################################################################################

# Check if array contains element
array_contains() {
    local element="$1"
    shift
    local array=("$@")
    
    for item in "${array[@]}"; do
        [[ "$item" == "$element" ]] && return 0
    done
    return 1
}

# Get script directory (works with sourced scripts)
get_script_dir() {
    local source="${BASH_SOURCE[0]}"
    while [ -h "$source" ]; do
        local dir=$( cd -P "$( dirname "$source" )" && pwd )
        source=$( readlink "$source" )
        [[ $source != /* ]] && source="$dir/$source"
    done
    cd -P "$( dirname "$source" )" && pwd
}

# Get module root directory
get_module_root() {
    local script_dir=$(get_script_dir)
    # Navigate up from lib or scripts to root of modules/audit
    echo "$(cd "$script_dir/../.." && pwd)"
}

################################################################################
# Exit Handlers
################################################################################

# Set trap for cleanup on exit
cleanup_on_exit() {
    local cleanup_func="$1"
    trap "$cleanup_func" EXIT
}

# Standard exit with summary
exit_with_summary() {
    local status=$1
    
    if [ $status -eq 0 ]; then
        log_success "Script completed successfully"
    else
        log_error "Script completed with errors"
    fi
    
    exit $status
}

################################################################################
# Confirmation Prompts
################################################################################

# Ask for yes/no confirmation
confirm() {
    local prompt="$1"
    local response
    
    read -p "$prompt (y/n): " response
    [[ "$response" =~ ^[Yy]$ ]] && return 0 || return 1
}

# Require explicit confirmation
require_confirmation() {
    local prompt="$1"
    local expected="$2"
    local response
    
    read -p "$prompt: " response
    [ "$response" = "$expected" ] && return 0 || return 1
}

################################################################################
# Load Optional Modules
################################################################################

# Source YAML parsing module if available
if [ -f "$(dirname "${BASH_SOURCE[0]}")/yaml.sh" ]; then
    source "$(dirname "${BASH_SOURCE[0]}")/yaml.sh"
fi

# Source sudoers generation module if available
if [ -f "$(dirname "${BASH_SOURCE[0]}")/sudoers.sh" ]; then
    source "$(dirname "${BASH_SOURCE[0]}")/sudoers.sh"
fi

################################################################################
# Export Core Functions for use in sourcing scripts
################################################################################

export -f log_info
export -f log_warn
export -f log_error
export -f log_debug
export -f log_success
export -f log_failure
export -f section_header
export -f section_end
export -f parse_standard_flags_nameref
export -f require_command
export -f require_file
export -f require_root
export -f require_host
export -f backup_file
export -f restore_file
export -f test_pass
export -f test_fail
export -f test_skip
export -f test_summary
export -f verify_pass
export -f verify_fail
export -f verify_summary
export -f check_ai_auditor_user
export -f check_ai_auditor_home
export -f check_ai_auditor_sudoers
export -f check_ssh_key_deployed
export -f array_contains
export -f get_script_dir
export -f get_module_root
export -f cleanup_on_exit
export -f exit_with_summary
export -f confirm
export -f require_confirmation
