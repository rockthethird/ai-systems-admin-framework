#!/bin/bash

################################################################################
# Sudoers Generation and Validation
#
# Purpose: Generate sudoers files from YAML config with rich documentation
#          Validate syntax without executing commands
#
# Usage: Source from lib/common.sh (auto-sourced)
#
# Functions:
#   generate_sudoers_from_yaml <yaml_file> <template_file>
#   validate_sudoers_syntax_visudo <sudoers_file>
#
# Security Philosophy:
#   - Only perform SAFE operations: generate and syntax-check
#   - NO automatic command execution or verification
#   - Admin manually reviews and approves before deployment
#   - Capability field documented in YAML for future workflow stages
#
# Note: Requires lib/yaml.sh functions to be available
#
################################################################################

# Generate sudoers file from YAML config with rich documentation
# Output: Generated sudoers content (printed to stdout)
#
# Parameters:
#   $1: Path to YAML config file
#
# Returns: 0 on success, 1 on error
#
# The function:
#   1. Reads commands from YAML
#   2. Generates sudoers rules with audit trail
#   3. Appends hardened security configuration
#
generate_sudoers_from_yaml() {
    local yaml_file=$1
    
    require_file "$yaml_file" || return 1
    
    local timestamp=$(date -u +'%Y-%m-%d %H:%M:%S UTC')
    
    # Generate header section
    cat << EOF
# This file is auto-generated - DO NOT EDIT DIRECTLY
# Generated at: $timestamp
# Modify the YAML config and regenerate to update
#

EOF

    # Parse commands from YAML and generate sudoers rules
    local commands_array=()
    parse_yaml_commands "$yaml_file" commands_array || return 1
    
    if [ ${#commands_array[@]} -eq 0 ]; then
        log_error "No commands found in $yaml_file"
        return 1
    fi
    
    # Generate a rule for each command
    local auditor_users=()
    for cmd_name in "${commands_array[@]}"; do
        local cmd_user=$(get_yaml_field "$yaml_file" "$cmd_name" "user")
        local cmd_path=$(get_yaml_field "$yaml_file" "$cmd_name" "path")
        local cmd_args=$(get_yaml_field "$yaml_file" "$cmd_name" "args")
        local cmd_desc=$(get_yaml_field "$yaml_file" "$cmd_name" "description")
        
        if [[ ! "$cmd_user" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
            log_error "Command '$cmd_name' has an invalid or missing user"
            return 1
        fi
        if [[ ! "$cmd_path" =~ ^/[A-Za-z0-9_./-]+$ ]]; then
            log_error "Command '$cmd_name' has an invalid or missing absolute path"
            return 1
        fi
        auditor_users+=("$cmd_user")
        
        # Build the sudoers rule
        local rule="$cmd_user ALL=(root:root) NOPASSWD: $cmd_path"
        if [ -n "$cmd_args" ]; then
            rule="$rule $cmd_args"
        else
            # In sudoers, an omitted argument expression permits any arguments.
            # An explicit empty string matches only a no-argument invocation.
            rule="$rule \"\""
        fi
        
        # Add comment with description
        if [ -n "$cmd_desc" ]; then
            rule="$rule  # $cmd_desc"
        fi
        
        echo "$rule"
    done
    
    # Append security hardening footer for every configured identity.
    cat << 'EOF'

################################################################################
# Environment Hardening
################################################################################
EOF

    local seen_users=" "
    for audit_user in "${auditor_users[@]}"; do
        if [[ "$seen_users" == *" $audit_user "* ]]; then
            continue
        fi
        seen_users+="$audit_user "
        cat << EOF
# Harden and log $audit_user independently.
Defaults:$audit_user env_reset
Defaults:$audit_user secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults:$audit_user env_delete="LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PATH_ORIG LD_AUDIT LD_DEBUG"
Defaults:$audit_user env_keep="LANGUAGE LANG LC_*"
Defaults:$audit_user logfile="/var/log/sudo-$audit_user.log"
Defaults:$audit_user !requiretty
EOF
    done
    
    return 0
}

# Validate sudoers syntax using visudo (if available)
#
# Parameters:
#   $1: Path to sudoers file to validate
#
# Returns:
#   0: If valid (or visudo not available)
#   1: If syntax invalid
#
# Behavior:
#   - If visudo available: Performs full syntax validation
#   - If visudo not available: Logs warning but returns 0 (continues)
#   - Errors displayed with line numbers
#
validate_sudoers_syntax_visudo() {
    local sudoers_file=$1
    
    require_file "$sudoers_file" || return 1
    
    # Check if visudo is available
    if ! command -v visudo &>/dev/null; then
        log_warn "visudo not available - skipping syntax validation"
        log_warn "(Install sudo package to enable syntax validation)"
        return 0  # Don't fail, just warn
    fi
    
    # Validate syntax
    if visudo -c -f "$sudoers_file" &>/dev/null; then
        log_success "Sudoers syntax valid"
        return 0
    else
        log_error "Sudoers syntax validation failed"
        visudo -c -f "$sudoers_file" 2>&1 | sed 's/^/  /'
        return 1
    fi
}

################################################################################
# Export sudoers functions
################################################################################

export -f generate_sudoers_from_yaml
export -f validate_sudoers_syntax_visudo
