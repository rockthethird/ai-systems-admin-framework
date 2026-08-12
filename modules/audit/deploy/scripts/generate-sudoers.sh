#!/bin/bash

################################################################################
# Generate Sudoers from YAML Configuration
#
# Purpose: Generate sudoers file from YAML config and validate syntax with visudo
#          on the CONTROLLER before deployment to server
#
# Location: CONTROLLER (admin machine)
# Usage: bash ./generate-sudoers.sh [-o|--output FILE] [-h|--help]
#
# Workflow:
#   1. Parse enabled-commands.yaml
#   2. Generate sudoers file with documentation
#   3. Validate syntax with visudo
#   4. Display to admin for review (stdout or file)
#   5. Admin manually approves and deploys
#
# Exit Codes:
#   0: Generation successful, ready for review
#   1: Generation failed, DO NOT deploy
#
# Output:
#   Generated sudoers file to stdout or --output FILE
#   Validation report to stderr
#
# SECURITY NOTE:
#   No automatic command execution or verification performed.
#   Admin is responsible for reviewing generated sudoers before deployment.
#
################################################################################

set -euo pipefail

################################################################################
# Script Setup
################################################################################

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source common library
if [ ! -f "$SCRIPT_DIR/lib/common.sh" ]; then
    echo "ERROR: lib/common.sh not found at $SCRIPT_DIR/lib/common.sh"
    echo "This script must be run from the repository"
    exit 1
fi

source "$SCRIPT_DIR/lib/common.sh"

################################################################################
# Parse Parameters
################################################################################

HELP_REQUESTED=false
VERBOSE=false
OUTPUT_FILE=""
TEMP_SUDOERS=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            HELP_REQUESTED=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ "$HELP_REQUESTED" = "true" ]; then
    cat << 'EOF'
Generate Sudoers from YAML Configuration

SYNOPSIS
    bash ./generate-sudoers.sh [-o|--output FILE] [-v|--verbose] [-h|--help]

OPTIONS
    -o, --output FILE  Write generated sudoers to FILE (default: stdout)
    -v, --verbose      Display detailed output for debugging
    -h, --help         Display this help message

DESCRIPTION
    Controller-side generation and validation of sudoers file. This script:
    1. Parses ../policy/enabled-commands.yaml
    2. Generates sudoers file with full audit trail
    3. Validates syntax using visudo
    4. Displays output for admin review

    NO automatic command execution or verification is performed.
    Admin is responsible for reviewing the generated sudoers carefully.

WORKFLOW
    1. Edit ../policy/enabled-commands.yaml with desired commands
    2. Run this generation script
    3. Review the generated sudoers carefully (especially commands!)
    4. If correct, copy to server and run install-sudoers.sh
    5. On server, manually test commands to verify they work as expected

EXAMPLES
    # Display generated sudoers to stdout
    bash ./generate-sudoers.sh

    # Save to file for review
    bash ./generate-sudoers.sh --output /tmp/sudoers-new

    # Verbose output for debugging
    bash ./generate-sudoers.sh --verbose

PREREQUISITES
    - ../policy/enabled-commands.yaml must exist (YAML configuration)
    - Local sudoers template (sudoers-ai-auditor-template in this directory)
    - Recommended: visudo available for syntax validation
    - Bash 4.3+ (for nameref support)

OUTPUT
    Generation report: Printed to stderr
    Generated sudoers: To --output FILE or stdout
    Status: Exit code (0 = success, 1 = failure)

NEXT STEPS (on success)
    1. REVIEW the generated sudoers carefully
    2. Copy content to server via secure channel (SSH, etc.)
    3. On SERVER: sudo bash deploy/scripts/install-sudoers.sh
    4. On SERVER: Manually test each command to verify functionality

SECURITY NOTE
    This script performs only SAFE operations (generation and syntax checking).
    Command verification must be done manually on the actual server.
    Never trust automated command execution - always test manually first.

EOF
    exit 0
fi

################################################################################
# Load Configuration Files
################################################################################

readonly YAML_CONFIG="$DEPLOY_DIR/policy/enabled-commands.yaml"
readonly SUDOERS_GENERATED="$DEPLOY_DIR/generated/sudoers-ai-auditor"

require_file "$YAML_CONFIG" "YAML command configuration" || exit 1

################################################################################
# Counters
################################################################################

TOTAL_COMMANDS=0

################################################################################
# Main Generation Flow
################################################################################

section_header "Generate Sudoers from YAML"

log_info "Step 1: Parse configuration"
log_info "  YAML config: $YAML_CONFIG"
log_info "  Output: $SUDOERS_GENERATED"

# Parse commands
commands_array=()
parse_yaml_commands "$YAML_CONFIG" commands_array || {
    log_error "Failed to parse YAML configuration"
    exit 1
}

TOTAL_COMMANDS=${#commands_array[@]}
log_success "Found $TOTAL_COMMANDS command(s)"
echo ""

# Generate sudoers file
log_info "Step 2: Generate sudoers file"
TEMP_SUDOERS=$(mktemp)
trap "rm -f $TEMP_SUDOERS" EXIT

if generate_sudoers_from_yaml "$YAML_CONFIG" > "$TEMP_SUDOERS" 2>/dev/null; then
    log_success "Sudoers file generated"
else
    log_error "Failed to generate sudoers file"
    exit 1
fi

log_debug "Generated sudoers size: $(wc -c < "$TEMP_SUDOERS") bytes"
echo ""

# Validate syntax
log_info "Step 3: Validate sudoers syntax"
if validate_sudoers_syntax_visudo "$TEMP_SUDOERS"; then
    log_success "Syntax validation passed"
else
    log_error "Syntax validation failed - DO NOT deploy"
    exit 1
fi
echo ""

# Summary
section_header "Commands in Configuration"

log_info "Found $TOTAL_COMMANDS command(s):"
for cmd_name in "${commands_array[@]}"; do
    cmd_path=$(get_yaml_field "$YAML_CONFIG" "$cmd_name" "path")
    cmd_args=$(get_yaml_field "$YAML_CONFIG" "$cmd_name" "args")
    cmd_desc=$(get_yaml_field "$YAML_CONFIG" "$cmd_name" "description")
    
    log_info "  - $cmd_name"
    log_info "    Path: $cmd_path"
    if [ -n "$cmd_args" ]; then
        log_info "    Args: $cmd_args"
    fi
    if [ -n "$cmd_desc" ]; then
        log_info "    Desc: $cmd_desc"
    fi
done

echo ""

################################################################################
# Output Generated Sudoers
################################################################################

section_header "Generated Sudoers File"

# If output file specified, write only there (skip generated)
if [ -n "$OUTPUT_FILE" ]; then
    cp "$TEMP_SUDOERS" "$OUTPUT_FILE"
    log_success "Sudoers written to: $OUTPUT_FILE"
    log_info "Preview (first 20 lines):"
    head -20 "$OUTPUT_FILE" | sed 's/^/  /'
else
    # No output file: backup and update generated
    if [ -f "$SUDOERS_GENERATED" ]; then
        cp "$SUDOERS_GENERATED" "$SUDOERS_GENERATED.backup.$(date +%Y%m%d-%H%M%S)"
        log_info "Backed up previous version: sudoers-ai-auditor.backup.*"
    fi
    
    cp "$TEMP_SUDOERS" "$SUDOERS_GENERATED"
    log_success "Sudoers generated: $SUDOERS_GENERATED"
    log_info "Ready for deployment via: deploy/scripts/install-sudoers.sh"
    echo ""
    log_info "Preview (first 20 lines):"
    head -20 "$SUDOERS_GENERATED" | sed 's/^/  /'
fi

################################################################################
# Deployment Instructions
################################################################################

section_header "Deployment Instructions"

log_success "Generation complete"
log_warn "IMPORTANT: Review the generated sudoers above carefully!"
log_warn "No automatic command execution or verification was performed."
log_info ""

if [ -n "$OUTPUT_FILE" ]; then
    log_info "Sudoers written to custom file: $OUTPUT_FILE"
    log_info "Next steps:"
    log_info "  1. CAREFULLY review the sudoers file"
    log_info "  2. Transfer to server: scp $OUTPUT_FILE user@server:/tmp/"
    log_info "  3. On SERVER: sudo bash deploy/scripts/install-sudoers.sh -f /tmp/$(basename $OUTPUT_FILE)"
    log_info "  4. On SERVER: Manually test each command"
else
    log_info "Sudoers generated and ready to deploy"
    log_info "Next steps:"
    log_info "  1. CAREFULLY review the generated sudoers above"
    log_info "  2. Verify all commands and arguments are correct"
    log_info "  3. Check for any unintended or dangerous commands"
    log_info "  4. On SERVER: sudo bash deploy/scripts/install-sudoers.sh"
    log_info "     (Automatically uses: sudoers-ai-auditor)"
    log_info "  5. On SERVER: Manually test each command"
fi

log_info ""
log_warn "Always test commands manually on the actual server"
log_warn "before trusting them in production."

echo ""
section_end

exit 0
