# Build Sudoers Configuration

## Compile audit policy

The declarative audit policy is compiled separately from sudoers:

```bash
python3 modules/audit/build/compile-policy.py
python3 modules/audit/build/compile-policy.py --check
```

The first command validates `modules/audit/policy/*.yaml` and updates the
checked-in `modules/audit/generated/policy-manifest.json`. The second command is
read-only and fails when the generated manifest is stale. Policy compilation
also enforces cross-file references and external-safe disclosure requirements.

Target reporting helpers read only the compiled JSON manifest; YAML and JSON
Schema libraries are not part of the privileged runtime dependency set.

## Purpose

Generate and validate sudoers file from YAML command definitions.

This script:
1. Parses `../configure/enabled-commands.yaml` 
2. Generates sudoers file with full audit trail
3. Validates syntax with visudo (if available)
4. Displays output for admin review

**No automatic command execution or verification is performed.**

---

## Quick Start

### Generate and Display

```bash
bash ./10-generate-sudoers-from-yaml.sh
```

### Generate and Save

```bash
bash ./10-generate-sudoers-from-yaml.sh --output /tmp/sudoers-new
```

### With Verbose Output

```bash
bash ./10-generate-sudoers-from-yaml.sh --verbose
```

---

## Workflow

### 1. Generate and Validate

```bash
# Generate sudoers and validate syntax
bash ./10-generate-sudoers-from-yaml.sh
```

### 2. Review Output

```bash
# Carefully review the generated sudoers
# Look for:
# - Correct command paths
# - Correct arguments
# - No unexpected commands
```

### 3. Deploy to Server

```bash
# Save to file for secure transfer
bash ./10-generate-sudoers-from-yaml.sh -o /tmp/sudoers-new
scp /tmp/sudoers-new user@server:/tmp/

# On server: deploy sudoers
ssh user@server sudo bash ../deploy/30-configure-sudoers.sh
```

### 4. Manual Testing

```bash
# On server: test each command
ssh ai-auditor@server "sudo /usr/bin/uname -a"
ssh ai-auditor@server "sudo /path/to/other/command"
```

---

## Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Display help message |
| `-v, --verbose` | Verbose output for debugging |
| `-o, --output FILE` | Write generated sudoers to file |

---

## Prerequisites

- `../configure/enabled-commands.yaml` (YAML command configuration)
- `sudoers-ai-auditor-template` (template in this directory)
- Bash 4.3+
- Recommended: `visudo` for syntax validation

---

## Security Notes

- **Review carefully:** Examine generated sudoers before deployment
- **Manual testing:** Always test commands on actual server
- **No automation:** This script does not execute commands
- **Syntax only:** Visudo validates format, not safety

---

## Troubleshooting

**Script not found:**
```bash
# Run from the build directory
bash ./10-generate-sudoers-from-yaml.sh
```

**Syntax validation fails:**
```bash
# visudo not available on this system
# Script will warn and continue with basic checks
# Syntax validation performed on server (if visudo available)
```

**YAML parsing error:**
```bash
# Check YAML syntax in ../configure/enabled-commands.yaml
# Ensure proper indentation (2 spaces)
# Verify all required fields present
```

---

## See Also

- [Configure Commands](../configure/README.md) — Edit YAML configuration
- [Deploy to Server](../deploy/README.md) — Install sudoers on server
- [Verification Roadmap](../verify/ROADMAP.md) — Future testing phases
