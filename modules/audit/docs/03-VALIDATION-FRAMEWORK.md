# Phase 3: Validation Framework & Automated Testing

## Overview
This document describes the comprehensive testing and validation framework to verify that `ai-auditor` permissions are correctly restricted to read-only operations and cannot be exploited.

**Core Principle:** Every permission must be tested automatically to verify:
1. Allowed commands work correctly
2. Denied commands are blocked
3. Privilege escalation is prevented
4. Shell escapes cannot be exploited

---

## Testing Categories

### 1. **Static Validation** — Configuration Verification
- Sudoers file syntax
- File ownership and permissions
- User account status
- SSH key configuration

### 2. **Dynamic Validation** — Permission Testing
- Allowed commands execute successfully
- Denied commands are blocked
- Commands produce expected output
- Command arguments are validated

### 3. **Security Testing** — Attack Vectors
- Shell escape attempts
- Wildcard expansion exploitation
- Environment variable injection
- Symlink attacks
- SUID/Capability abuse

### 4. **Audit Testing** — Logging Verification
- Commands are logged
- Failed attempts are logged
- Log format is consistent
- Log rotation works

---

## Test Suite 1: Static Validation

### File 1.1: Static Sudoers Validation

```bash
#!/bin/bash
# scripts/40-validate-static.sh
# Static validation of sudoers configuration

set -e

echo "===== STATIC VALIDATION ====="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FAIL_COUNT=0
PASS_COUNT=0

# Helper function
test_check() {
    local name="$1"
    local command="$2"
    
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $name"
        ((PASS_COUNT++))
    else
        echo -e "${RED}✗${NC} $name"
        ((FAIL_COUNT++))
    fi
}

# ==========================================
# SUDOERS FILE CHECKS
# ==========================================
echo "[1] Sudoers File Validation"
echo "---"

test_check "Sudoers file exists" "test -f /etc/sudoers.d/ai-auditor"
test_check "Sudoers file readable" "sudo test -r /etc/sudoers.d/ai-auditor"
test_check "Sudoers file owned by root" \
    "test $(sudo stat -c '%U:%G' /etc/sudoers.d/ai-auditor) = 'root:root'"
test_check "Sudoers file permissions 440" \
    "test $(sudo stat -c '%a' /etc/sudoers.d/ai-auditor) = '440'"
test_check "Sudoers syntax valid" \
    "sudo visudo -c -f /etc/sudoers.d/ai-auditor"

# ==========================================
# USER ACCOUNT CHECKS
# ==========================================
echo ""
echo "[2] User Account Validation"
echo "---"

test_check "User ai-auditor exists" "id ai-auditor"
test_check "User has no password (locked)" \
    "sudo passwd --status ai-auditor | grep -q LK"
test_check "User home directory exists" "test -d /opt/ai-auditor"
test_check "Home directory owned by ai-auditor" \
    "test $(stat -c '%U:%G' /opt/ai-auditor) = 'ai-auditor:ai-auditor'"
test_check "Home directory permissions 700" \
    "test $(stat -c '%a' /opt/ai-auditor) = '700'"

# ==========================================
# SSH KEY CHECKS
# ==========================================
echo ""
echo "[3] SSH Key Validation"
echo "---"

test_check "SSH directory exists" "test -d /opt/ai-auditor/.ssh"
test_check "SSH directory permissions 700" \
    "test $(stat -c '%a' /opt/ai-auditor/.ssh) = '700'"
test_check "authorized_keys file exists" \
    "test -f /opt/ai-auditor/.ssh/authorized_keys"
test_check "authorized_keys permissions 600" \
    "test $(stat -c '%a' /opt/ai-auditor/.ssh/authorized_keys) = '600'"
test_check "SSH key format valid (ed25519)" \
    "sudo grep -q 'ssh-ed25519' /opt/ai-auditor/.ssh/authorized_keys || \
     sudo grep -q 'ssh-rsa' /opt/ai-auditor/.ssh/authorized_keys"

# ==========================================
# SHELL CONFIGURATION CHECKS
# ==========================================
echo ""
echo "[4] Shell Configuration Validation"
echo "---"

test_check "Shell is /bin/bash" \
    "grep 'ai-auditor' /etc/passwd | grep -q '/bin/bash'"
test_check ".bashrc exists" "test -f /opt/ai-auditor/.bashrc"
test_check ".bashrc has safe PATH" \
    "sudo grep -q 'export PATH=' /opt/ai-auditor/.bashrc"
test_check "History disabled in .bashrc" \
    "sudo grep -q 'HISTFILE=/dev/null' /opt/ai-auditor/.bashrc"

# ==========================================
# SSHD CONFIGURATION CHECKS
# ==========================================
echo ""
echo "[5] SSHD Configuration Validation"
echo "---"

test_check "sshd_config syntax valid" "sudo sshd -t"
test_check "ai-auditor has Match block" \
    "sudo grep -q 'Match User ai-auditor' /etc/ssh/sshd_config"
test_check "PubkeyAuthentication enabled" \
    "sudo grep -A5 'Match User ai-auditor' /etc/ssh/sshd_config | \
     grep -q 'PubkeyAuthentication yes'"
test_check "PasswordAuthentication disabled" \
    "sudo grep -A5 'Match User ai-auditor' /etc/ssh/sshd_config | \
     grep -q 'PasswordAuthentication no'"
test_check "Port forwarding disabled" \
    "sudo grep -A10 'Match User ai-auditor' /etc/ssh/sshd_config | \
     grep -q 'AllowTcpForwarding no'"

# ==========================================
# AUDIT LOG CHECKS
# ==========================================
echo ""
echo "[6] Audit Logging Validation"
echo "---"

test_check "Sudo log file exists" "sudo test -f /var/log/sudo-ai-auditor.log"
test_check "Log file readable" "sudo test -r /var/log/sudo-ai-auditor.log"
test_check "Log file owned by root" \
    "test $(sudo stat -c '%U:%G' /var/log/sudo-ai-auditor.log) = 'root:root'"
test_check "Log file permissions 600" \
    "test $(sudo stat -c '%a' /var/log/sudo-ai-auditor.log) = '600'"

# ==========================================
# SUMMARY
# ==========================================
echo ""
echo "===== VALIDATION SUMMARY ====="
echo -e "Passed: ${GREEN}$PASS_COUNT${NC}"
echo -e "Failed: ${RED}$FAIL_COUNT${NC}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${GREEN}✓ All static validations passed${NC}"
    exit 0
else
    echo -e "${RED}✗ Some validations failed${NC}"
    exit 1
fi
```

---

## Test Suite 2: Dynamic Permission Testing

### File 2.1: Read-Only Command Testing

```bash
#!/bin/bash
# scripts/50-validate-dynamic.sh
# Dynamic testing of sudo permissions

set -e

echo "===== DYNAMIC VALIDATION ====="
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAIL_COUNT=0
PASS_COUNT=0

test_command() {
    local name="$1"
    local command="$2"
    local should_succeed="${3:-yes}"
    
    if [[ "$should_succeed" == "yes" ]]; then
        if sudo -u ai-auditor sudo $command > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} ALLOWED: $name"
            ((PASS_COUNT++))
        else
            echo -e "${RED}✗${NC} ALLOWED FAILED: $name"
            ((FAIL_COUNT++))
        fi
    else
        if ! sudo -u ai-auditor sudo $command > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} BLOCKED: $name"
            ((PASS_COUNT++))
        else
            echo -e "${RED}✗${NC} BLOCKED FAILED (command succeeded): $name"
            ((FAIL_COUNT++))
        fi
    fi
}

# ==========================================
# ALLOWED COMMANDS - SHOULD SUCCEED
# ==========================================
echo "[1] Testing Allowed Commands (Should Succeed)"
echo "---"

test_command "uname" "uname -a" "yes"
test_command "hostname" "hostname" "yes"
test_command "ip addr" "/usr/sbin/ip addr show" "yes"
test_command "ss network" "/usr/sbin/ss -tlnp" "yes"
test_command "ps processes" "/usr/bin/ps aux | head -1" "yes"
test_command "systemctl status" "/usr/bin/systemctl status ssh" "yes"
test_command "dpkg list" "/usr/bin/dpkg -l | head -1" "yes"
test_command "journalctl" "/usr/bin/journalctl -n 1" "yes"

# ==========================================
# DENIED COMMANDS - SHOULD FAIL
# ==========================================
echo ""
echo "[2] Testing Denied Commands (Should Fail)"
echo "---"

test_command "apt install" "apt install -y vim" "no"
test_command "apt remove" "apt remove -y vim" "no"
test_command "systemctl restart" "systemctl restart ssh" "no"
test_command "systemctl start" "systemctl start ssh" "no"
test_command "useradd" "useradd testuser" "no"
test_command "userdel" "userdel testuser" "no"
test_command "rm file" "rm /tmp/testfile.txt" "no"
test_command "touch file" "touch /tmp/testfile.txt" "no"
test_command "passwd user" "passwd root" "no"
test_command "visudo editor" "visudo" "no"

# ==========================================
# COMMAND ARGUMENT RESTRICTION TESTS
# ==========================================
echo ""
echo "[3] Testing Command Argument Restrictions"
echo "---"

# These should test that arguments are validated
test_command "find with -type" "/usr/bin/find /etc -type f -readable" "yes"
test_command "journalctl -u service" "/usr/bin/journalctl -u ssh" "yes"
test_command "systemctl status service" "/usr/bin/systemctl status ssh" "yes"

# Argument manipulation attempts
test_command "find with exec (should fail)" \
    "/usr/bin/find /etc -type f -exec rm {} \;" "no"
test_command "journalctl -e flag (outside scope)" \
    "/usr/bin/journalctl -u ssh -e" "no"

# ==========================================
# INFORMATION DISCLOSURE TESTS
# ==========================================
echo ""
echo "[4] Testing Information Disclosure Prevention"
echo "---"

# These commands should be allowed (read-only)
test_command "read config files" \
    "/usr/bin/find /etc -type f -readable -name '*.conf'" "yes"

# Root-only paths should fail
test_command "access /root (should fail)" \
    "/usr/bin/find /root -type f" "no"

test_command "access /home/sensitive (should fail if exists)" \
    "/bin/ls -la /root/.ssh" "no"

# ==========================================
# SUMMARY
# ==========================================
echo ""
echo "===== DYNAMIC VALIDATION SUMMARY ====="
echo -e "Passed: ${GREEN}$PASS_COUNT${NC}"
echo -e "Failed: ${RED}$FAIL_COUNT${NC}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${GREEN}✓ All dynamic validations passed${NC}"
    exit 0
else
    echo -e "${RED}✗ Some dynamic validations failed${NC}"
    exit 1
fi
```

---

## Test Suite 3: Security Attack Vector Testing

### File 3.1: Shell Escape Detection

```bash
#!/bin/bash
# tests/test-shell-escapes.sh
# Test shell escape attempts and metacharacter exploitation

echo "===== SHELL ESCAPE TESTING ====="
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

ATTACKS_BLOCKED=0
ATTACKS_FAILED=0

test_escape() {
    local name="$1"
    local command="$2"
    
    if ! sudo -u ai-auditor bash -c "sudo $command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ BLOCKED${NC}: $name"
        ((ATTACKS_BLOCKED++))
    else
        echo -e "${RED}✗ FAILED${NC}: $name (attack succeeded!)"
        ((ATTACKS_FAILED++))
    fi
}

# Command substitution attempts
test_escape "Command substitution via ()" \
    "ip addr show && whoami"

test_escape "Command substitution via backticks" \
    "ip addr show \`whoami\`"

test_escape "Command substitution via \$()" \
    "ip addr show \$(whoami)"

# Pipe and redirect attempts
test_escape "Pipe to shell" \
    "ip addr show | cat"

test_escape "Redirect to file" \
    "ps aux > /tmp/output.txt"

test_escape "Append to file" \
    "ps aux >> /tmp/output.txt"

test_escape "Redirect stderr" \
    "ps aux 2>/tmp/error.txt"

# Semicolon and logical operators
test_escape "Semicolon chaining" \
    "ip addr show; whoami"

test_escape "Logical AND" \
    "ps aux && whoami"

test_escape "Logical OR" \
    "ls /nonexistent || whoami"

# Globbing and expansion
test_escape "Wildcard expansion" \
    "find /etc -name '*.conf' -exec cat {} \\;"

test_escape "Brace expansion" \
    "touch {/tmp/a,/tmp/b}.txt"

# PATH manipulation
test_escape "PATH override attempt" \
    "PATH=/tmp:/usr/bin ps aux"

# Summary
echo ""
echo "===== ESCAPE TEST SUMMARY ====="
echo -e "Blocked: ${GREEN}$ATTACKS_BLOCKED${NC}"
echo -e "Failed (Leaked): ${RED}$ATTACKS_FAILED${NC}"

if [[ $ATTACKS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}✓ All escape attempts blocked${NC}"
    exit 0
else
    echo -e "${RED}✗ Some escape attempts succeeded${NC}"
    exit 1
fi
```

### File 3.2: Privilege Escalation Testing

```bash
#!/bin/bash
# tests/test-privilege-escalation.sh
# Test privilege escalation attempts

echo "===== PRIVILEGE ESCALATION TESTING ====="
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

ATTEMPTS_BLOCKED=0
ATTEMPTS_FAILED=0

test_escalation() {
    local name="$1"
    local command="$2"
    local target_uid="$3"
    
    result=$(sudo -u ai-auditor $command 2>&1 || true)
    
    if ! echo "$result" | grep -q "uid=$target_uid"; then
        echo -e "${GREEN}✓ BLOCKED${NC}: $name"
        ((ATTEMPTS_BLOCKED++))
    else
        echo -e "${RED}✗ FAILED${NC}: $name (escalation succeeded!)"
        ((ATTEMPTS_FAILED++))
    fi
}

# UID tests
AI_UID=$(id -u ai-auditor)
ROOT_UID=0

echo "[1] Direct Privilege Escalation"
echo "---"

test_escalation "Escalate to root via sudo -u root" \
    "sudo -u root whoami" "$ROOT_UID"

test_escalation "Escalate to root via sudo -i" \
    "sudo -i id" "$ROOT_UID"

test_escalation "Escalate to root via sudo su" \
    "sudo su - root -c whoami" "$ROOT_UID"

# ==========================================
# SUID Binary Exploitation
# ==========================================
echo ""
echo "[2] SUID Binary Exploitation"
echo "---"

test_escalation "Execute SUID binary as root" \
    "sudo /usr/bin/find /etc -name passwd" "$ROOT_UID"

# ==========================================
# Environment Variable Injection
# ==========================================
echo ""
echo "[3] Environment Variable Injection"
echo "---"

test_escalation "LD_PRELOAD injection" \
    "sudo LD_PRELOAD=/tmp/evil.so ps aux" "$ROOT_UID"

test_escalation "LD_LIBRARY_PATH injection" \
    "sudo LD_LIBRARY_PATH=/tmp:/usr/lib ps aux" "$ROOT_UID"

# ==========================================
# Summary
# ==========================================
echo ""
echo "===== ESCALATION TEST SUMMARY ====="
echo -e "Blocked: ${GREEN}$ATTEMPTS_BLOCKED${NC}"
echo -e "Failed (Leaked): ${RED}$ATTEMPTS_FAILED${NC}"

if [[ $ATTEMPTS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}✓ All escalation attempts blocked${NC}"
    exit 0
else
    echo -e "${RED}✗ Some escalation attempts succeeded${NC}"
    exit 1
fi
```

---

## Test Suite 4: Audit Logging Verification

### File 4.1: Audit Log Testing

```bash
#!/bin/bash
# tests/test-audit-logging.sh
# Verify sudo actions are properly logged

echo "===== AUDIT LOGGING TESTING ====="
echo ""

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

LOG_FILE="/var/log/sudo-ai-auditor.log"

# Get initial log line count
INITIAL_LINES=$(sudo wc -l < "$LOG_FILE" || echo "0")

echo "[1] Testing Successful Command Logging"
echo "---"

# Execute allowed command as ai-auditor
sudo -u ai-auditor sudo /usr/bin/ps aux > /dev/null 2>&1

# Check if command is logged
CURRENT_LINES=$(sudo wc -l < "$LOG_FILE")

if [[ $CURRENT_LINES -gt $INITIAL_LINES ]]; then
    echo -e "${GREEN}✓${NC} Command execution logged"
    
    # Check log content
    if sudo tail -5 "$LOG_FILE" | grep -q "ai-auditor.*ps aux"; then
        echo -e "${GREEN}✓${NC} Log contains command details"
    else
        echo -e "${RED}✗${NC} Log missing command details"
    fi
else
    echo -e "${RED}✗${NC} Command not logged"
fi

# ==========================================
# Test Failed Command Logging
# ==========================================
echo ""
echo "[2] Testing Failed Command Logging"
echo "---"

INITIAL_LINES=$(sudo wc -l < "$LOG_FILE" || echo "0")

# Attempt denied command
sudo -u ai-auditor sudo apt install -y vim > /dev/null 2>&1 || true

CURRENT_LINES=$(sudo wc -l < "$LOG_FILE")

if [[ $CURRENT_LINES -gt $INITIAL_LINES ]]; then
    echo -e "${GREEN}✓${NC} Failed command attempt logged"
else
    echo -e "${RED}✗${NC} Failed command not logged"
fi

echo ""
echo "===== AUDIT LOGGING SUMMARY ====="
echo -e "Log file: $LOG_FILE"
echo -e "Latest entries:"
sudo tail -5 "$LOG_FILE"
```

---

## Master Validation Script

```bash
#!/bin/bash
# scripts/validate-all.sh
# Run all validation suites

set -e

echo "╔════════════════════════════════════════╗"
echo "║  AI-AUDITOR SECURITY VALIDATION SUITE  ║"
echo "╚════════════════════════════════════════╝"
echo ""

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPTS_DIR/../tests"

FAILED=0

# Run static validation
echo "[1/4] Running static validation..."
if bash "$SCRIPTS_DIR/40-validate-static.sh"; then
    echo "✓ Static validation passed"
else
    echo "✗ Static validation failed"
    ((FAILED++))
fi

echo ""

# Run dynamic validation
echo "[2/4] Running dynamic permission tests..."
if bash "$SCRIPTS_DIR/50-validate-dynamic.sh"; then
    echo "✓ Dynamic validation passed"
else
    echo "✗ Dynamic validation failed"
    ((FAILED++))
fi

echo ""

# Run escape tests
echo "[3/4] Running shell escape tests..."
if bash "$TEST_DIR/test-shell-escapes.sh"; then
    echo "✓ Shell escape tests passed"
else
    echo "✗ Shell escape tests failed"
    ((FAILED++))
fi

echo ""

# Run logging tests
echo "[4/4] Running audit logging tests..."
if bash "$TEST_DIR/test-audit-logging.sh"; then
    echo "✓ Audit logging tests passed"
else
    echo "✗ Audit logging tests failed"
    ((FAILED++))
fi

echo ""
echo "╔════════════════════════════════════════╗"

if [[ $FAILED -eq 0 ]]; then
    echo "║  ✓ ALL VALIDATIONS PASSED              ║"
else
    echo "║  ✗ $FAILED VALIDATION(S) FAILED        ║"
fi

echo "╚════════════════════════════════════════╝"

exit $FAILED
```

---

## Next Steps

Proceed to [04-RISK-ASSESSMENT.md](04-RISK-ASSESSMENT.md) for detailed threat model and mitigations.
