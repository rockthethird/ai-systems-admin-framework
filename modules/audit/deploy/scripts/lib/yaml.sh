#!/bin/bash

################################################################################
# YAML Parsing Utilities
#
# Purpose: Pure Bash YAML parsing for configuration files
#          Specifically designed for enabled-commands.yaml
#
# Usage: Source from lib/common.sh (auto-sourced)
#
# Functions:
#   parse_yaml_commands <yaml_file> <commands_array_nameref>
#   get_yaml_field <yaml_file> <command_name> <field_name>
#
# Note: Requires Bash 4.3+ for nameref support
#
################################################################################

# Parse YAML file and extract command entries
# Returns array of command names that can be iterated
#
# Parameters:
#   $1: Path to YAML file
#   $2: Name of array variable to populate with command names
#
parse_yaml_commands() {
    local yaml_file=$1
    local -n commands_ref=$2
    
    require_file "$yaml_file" || return 1
    
    # Parse lines that start with "  - name: " and extract the quoted name
    local cmd_count=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*-[[:space:]]+name:[[:space:]]*\"([^\"]+)\" ]]; then
            commands_ref[cmd_count]="${BASH_REMATCH[1]}"
            ((cmd_count++))
        fi
    done < "$yaml_file"
    
    return 0
}

# Extract a specific command field from YAML
#
# Parameters:
#   $1: Path to YAML file
#   $2: Command name to find
#   $3: Field name to extract (path, args, description, etc.)
#
# Returns: The field value (printed to stdout)
# Exit code: 0 if found, 1 if not found
#
get_yaml_field() {
    local yaml_file=$1
    local cmd_name=$2
    local field_name=$3
    
    require_file "$yaml_file" || return 1
    
    local in_command=false
    local field_value=""
    
    while IFS= read -r line; do
        # Check if we're entering the command block
        if [[ "$line" =~ ^[[:space:]]*-[[:space:]]+name:[[:space:]]*\"$cmd_name\" ]]; then
            in_command=true
            continue
        fi
        
        # Exit command block when we hit the next command or non-indented line
        if $in_command && [[ "$line" =~ ^[[:space:]]*-[[:space:]]+ ]]; then
            break
        fi
        
        # Extract field value if we're in the right command
        if $in_command && [[ "$line" =~ ^[[:space:]]*$field_name:[[:space:]]*\"([^\"]*)\" ]]; then
            echo "${BASH_REMATCH[1]}"
            return 0
        elif $in_command && [[ "$line" =~ ^[[:space:]]*$field_name:[[:space:]]*\"([^\"]*) ]]; then
            # Handle multi-line or complex values
            field_value="${BASH_REMATCH[1]}"
        elif $in_command && [[ -n "$field_value" && "$line" =~ ([^\"]*)\" ]]; then
            field_value="$field_value ${BASH_REMATCH[1]}"
            echo "$field_value"
            return 0
        fi
    done < "$yaml_file"
    
    return 1
}

################################################################################
# Export YAML functions
################################################################################

export -f parse_yaml_commands
export -f get_yaml_field
