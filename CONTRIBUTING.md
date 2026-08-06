# Contributing to AI Systems Admin Framework

Welcome! This document explains how to contribute to this project, whether it's through:

- Adding new modules (new AI roles/capabilities)
- Improving documentation
- Reporting security issues
- Submitting bug fixes or features
- Providing feedback and ideas

---

## 🎯 Core Principles

Before contributing, understand our core principles:

1. **Security First** — Every contribution must be security-reviewed
2. **Least Privilege** — Only grant permissions necessary for the function
3. **Validation** — All permissions must be tested automatically
4. **Auditability** — Every action must be logged and reviewable
5. **Documentation** — All decisions must be documented

---

## 🚀 Getting Started

### 1. Fork & Clone

```bash
git clone https://github.com/yourusername/ai-systems-admin-framework.git
cd ai-systems-admin-framework
```

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or for bug fixes
git checkout -b bugfix/issue-description
# or for new modules
git checkout -b module/new-module-name
```

### 3. Make Your Changes

Follow the guidelines below based on your contribution type.

---

## 📝 Contribution Types

### A. Adding a New Module

This is the primary way to extend the framework with new AI roles.

#### Module Structure

Each module must follow this structure:

```
modules/your-module/
├── README.md                          (Module overview)
├── docs/
│   ├── 00-PROJECT-PLAN.md            (Strategic plan)
│   ├── 01-SETUP.md                   (Setup instructions)
│   ├── 02-CONFIGURATION.md           (Configuration guide)
│   ├── 03-VALIDATION.md              (Testing framework)
│   └── 04-RISK-ASSESSMENT.md         (Threat model)
├── templates/
│   └── sudoers-template              (Sudo config)
├── scripts/
│   ├── setup/
│   │   ├── 10-create-user.sh
│   │   └── 20-configure-permissions.sh
│   └── validate/
│       ├── validate-static.sh
│       ├── validate-dynamic.sh
│       └── validate-all.sh
└── tests/
    ├── test-denied-commands.sh
    ├── test-escape-attempts.sh
    └── test-logging.sh
```

#### Module Requirements

Every new module **must include:**

1. **Documentation** (docs/ directory)
   - Overview of module purpose and capabilities
   - Step-by-step setup procedures
   - Configuration guide with justifications
   - Comprehensive validation framework
   - Risk assessment and threat model

2. **Configuration Templates** (templates/ directory)
   - Sudoers configuration template
   - SSH configuration snippets
   - Shell environment setup
   - All defaults documented

3. **Setup Scripts** (scripts/setup/)
   - User account creation
   - SSH key configuration
   - Permissions setup
   - All with error handling and validation

4. **Validation Scripts** (scripts/validate/)
   - Static validation (40+ configuration checks)
   - Dynamic validation (20+ permission tests)
   - Security validation (shell escapes, escalations)
   - Master validation orchestrator

5. **Test Suite** (tests/)
   - Attack vector simulations
   - Permission enforcement tests
   - Logging verification
   - All edge cases covered

#### Module Checklist

Before submitting a new module:

- [ ] Module structure follows template above
- [ ] All documentation complete
- [ ] Setup scripts tested on clean system
- [ ] Validation framework 100% passing
- [ ] All attack vectors tested and blocked
- [ ] Permissions documented with justifications
- [ ] Risk assessment completed
- [ ] Security review completed
- [ ] Examples provided
- [ ] README links to all documentation

---

### B. Improving Documentation

Documentation improvements are always welcome!

#### Guidelines

1. **Clarity** — Write for users with varying expertise levels
2. **Completeness** — Include examples and expected outputs
3. **Accuracy** — Verify all commands and configurations work
4. **Structure** — Use clear headings and organization
5. **Links** — Cross-reference related documentation

#### Documentation Checklist

- [ ] Grammar and spelling reviewed
- [ ] Technical accuracy verified
- [ ] Examples tested and working
- [ ] Links to related docs included
- [ ] Follows existing documentation style

---

### C. Reporting Security Issues

**IMPORTANT:** Do not open public issues for security vulnerabilities.

See [SECURITY.md](SECURITY.md) for responsible disclosure procedure.

---

### D. Bug Fixes & Features

### Guidelines

1. **Test First** — Include test case showing the bug
2. **Minimal Changes** — Only change what's necessary
3. **Documentation** — Update docs if changing behavior
4. **Backward Compatibility** — Don't break existing setups

#### Checklist

- [ ] Bug is reproducible
- [ ] Test case added
- [ ] Fix validated
- [ ] Documentation updated
- [ ] No breaking changes
- [ ] Passes validation suite

---

## 🧪 Testing Requirements

### All Contributions Must Include:

1. **Static Validation**
   - Configuration file syntax
   - File permissions and ownership
   - Expected directory structure

2. **Dynamic Validation**
   - Expected functionality works
   - Denied operations are blocked
   - Commands produce correct output

3. **Security Validation**
   - Attack vectors are tested and blocked
   - Escape attempts fail
   - Escalation attempts blocked

### Running Tests

```bash
# For auditing module
cd modules/audit
bash scripts/validate/validate-all.sh

# For your new module
cd modules/your-module
bash scripts/validate/validate-all.sh
```

All tests **must pass** before submitting PR.

---

## 📋 Code Style & Standards

### Shell Scripts

1. **Use bash** (specify `#!/bin/bash`)
2. **License** — Add SPDX header on line 2: `# SPDX-License-Identifier: AGPL-3.0-or-later`
3. **Error handling** — `set -e` at top
4. **Comments** — Explain the why, not just the what
5. **Functions** — Break into reusable functions
6. **Variables** — Use UPPERCASE for constants, lowercase for locals
7. **Quotes** — Always quote variables ("$var" not $var)

#### Example Template

```bash
#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Brief description of what this script does
# Usage: ./script-name.sh [options]

set -e  # Exit on error

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Constants
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${1:-.}/config.txt"

# Functions
log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
    exit 1
}

# Main execution
log_success "Starting script"
# ... rest of script
```

### Documentation (Markdown)

1. **Headings** — Use `#` for main, `##` for sections, etc.
2. **Code** — Use ` ``` ` fences with language specified
3. **Links** — Use relative paths for internal docs
4. **Tables** — Use markdown table syntax
5. **Lists** — Use `-` for bullets, numbers for ordered

### Configuration Files

1. **Comments** — Explain each section and option
2. **Defaults** — Show default values
3. **Examples** — Include usage examples
4. **Security** — Highlight security implications

---

## 🔐 Security Considerations

### Every Contribution Must Address:

1. **Least Privilege** — Does it grant only necessary permissions?
2. **Attack Surface** — Could this be exploited? How?
3. **Logging** — Are all actions logged?
4. **Validation** — Are restrictions tested?
5. **Documentation** — Is the security model explained?

### Security Review Process

All PRs will be reviewed for:

- Permission restrictions (no unnecessary access)
- Attack vector coverage (tested and blocked)
- Audit logging (actions are recorded)
- Compliance with framework principles
- Threat model completeness

---

## 📤 Submitting a Pull Request

### PR Title Format

```
[TYPE] Brief description

Types: feat, fix, docs, module, refactor, test, chore, security
```

### PR Description Template

```markdown
## Description
Brief summary of changes

## Type
- [ ] New Module
- [ ] Bug Fix
- [ ] Documentation
- [ ] Feature
- [ ] Security Improvement

## Module Affected
If applicable, which module(s)?

## Changes
- Change 1
- Change 2
- etc.

## Testing
What testing was performed?

## Security
- [ ] Least privilege verified
- [ ] Attack vectors tested
- [ ] Logging implemented
- [ ] Documentation updated

## Checklist
- [ ] Code follows style guidelines
- [ ] All tests passing
- [ ] Documentation updated
- [ ] No breaking changes
- [ ] Security review complete
```

---

## 🚀 Becoming a Maintainer

Regular, high-quality contributors may be invited to become maintainers. This includes:

- Reviewing and merging PRs
- Releasing new versions
- Managing issues and discussions
- Maintaining documentation

We look for contributors who:

1. Understand the security-first philosophy
2. Provide high-quality, well-tested contributions
3. Help review others' contributions
4. Document decisions and rationale
5. Stay engaged with the community

---

## 📚 Resources

- [README.md](README.md) — Project overview
- [architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md) — System design
- [security/SECURITY-POLICY.md](security/SECURITY-POLICY.md) — Security policies
- [SECURITY.md](SECURITY.md) — Security issue reporting

---

## ❓ Questions?

- **Discussion:** Open a GitHub Discussion
- **Issue:** Open a GitHub Issue (if not security-related)
- **Security:** See [SECURITY.md](SECURITY.md)

---

## Thank You!

Contributors are the heart of this project. Your improvements make it safer and more useful for everyone.

Happy contributing! 🎉
