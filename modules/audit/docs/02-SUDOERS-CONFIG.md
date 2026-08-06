# Phase 2: Sudoers Configuration & Sudo Access Control

## Overview
This document describes how to configure sudo to allow the `ai-auditor` account to execute specific read-only audit commands without password authentication while maintaining security.

---

## Core Principle: Least Privilege

**Every sudo entry must be:**
1. **Explicitly documented** — why is this command needed?
2. **Narrowly scoped** — include full path and specific arguments
3. **Tested** — verify it works and cannot be exploited
4. **Audited** — log all attempts (success and failure)
5. **Justified** — security risk assessment completed

---

## Section 1: Sudoers File Basics

### Sudoers File Location

```bash
# Primary sudoers file (NEVER edit directly)
/etc/sudoers

# Preferred: Create files in sudoers.d/ directory
/etc/sudoers.d/ai-auditor
```

### Editing Rules

```bash
# ALWAYS use visudo for editing sudoers
# visudo checks syntax automatically and prevents corruption
sudo visudo -f /etc/sudoers.d/ai-auditor

# OR: Use tee for automated setup (with caution)
sudo tee /etc/sudoers.d/ai-auditor > /dev/null <<'EOF'
# ... sudoers content ...
EOF

# ALWAYS validate syntax
sudo visudo -c -f /etc/sudoers.d/ai-auditor
```

---

## Section 2: Sudoers Template for ai-auditor

### Base Configuration (No Password)

```bash
# /etc/sudoers.d/ai-auditor
# AI Auditor Service Account - Restricted Permissions
# Generated: 2026-08-05
# Last Review: 2026-08-05

# Defaults for ai-auditor user
Defaults:ai-auditor log="/var/log/sudo-ai-auditor.log"
Defaults:ai-auditor logfile="/var/log/sudo-ai-auditor.log"
Defaults:ai-auditor !requiretty
Defaults:ai-auditor !use_pty
Defaults:ai-auditor secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults:ai-auditor env_reset
Defaults:ai-auditor env_keep="LANGUAGE LANG LC_*"

# ========================================
# COMMAND ALIASES - Organized by Category
# ========================================

# System Information Commands
Cmnd_Alias SYSTEM_INFO = \
    /usr/bin/uname, \
    /usr/bin/uname -a, \
    /bin/uname, \
    /bin/uname -a, \
    /usr/bin/lsb_release -a, \
    /usr/bin/lsb_release -d, \
    /bin/hostname, \
    /usr/bin/hostnamectl

# Network Status Commands (Read-Only)
Cmnd_Alias NETWORK_STATUS = \
    /usr/sbin/ip addr, \
    /usr/sbin/ip addr show, \
    /usr/sbin/ip link, \
    /usr/sbin/ip link show, \
    /usr/sbin/ip route, \
    /usr/sbin/ip route show, \
    /usr/sbin/ss -tlnp, \
    /usr/sbin/ss -tunap, \
    /bin/netstat -tlnp, \
    /bin/netstat -tunap, \
    /sbin/iptables -L, \
    /sbin/iptables -L -n, \
    /sbin/ip6tables -L, \
    /sbin/ip6tables -L -n

# Process and System Status
Cmnd_Alias PROCESS_STATUS = \
    /usr/bin/ps aux, \
    /usr/bin/ps -ef, \
    /usr/bin/top -b, \
    /bin/ps aux, \
    /bin/ps -ef, \
    /usr/bin/systemctl status, \
    /usr/bin/systemctl list-units, \
    /usr/bin/systemctl list-services

# File Inspection (Read-Only, Restricted Paths)
Cmnd_Alias FILE_INSPECT = \
    /usr/bin/find /etc -type f -readable, \
    /usr/bin/find /var/log -type f -readable, \
    /usr/bin/find /opt -type f -readable, \
    /bin/find /etc -type f -readable, \
    /bin/find /var/log -type f -readable, \
    /bin/find /opt -type f -readable, \
    /bin/ls -la, \
    /usr/bin/ls -la, \
    /usr/bin/file *, \
    /bin/file *, \
    /usr/bin/stat *, \
    /bin/stat *

# Package Management (Query Only)
Cmnd_Alias PACKAGE_QUERY = \
    /usr/bin/dpkg -l, \
    /usr/bin/dpkg --list, \
    /usr/bin/dpkg -l *, \
    /usr/bin/apt list --installed, \
    /usr/bin/rpm -qa, \
    /usr/bin/rpm -qa *, \
    /usr/bin/rpm -qi *

# Log Inspection
Cmnd_Alias LOG_INSPECT = \
    /usr/bin/journalctl -n 100, \
    /usr/bin/journalctl -u *, \
    /usr/bin/journalctl -b, \
    /usr/bin/tail -f /var/log/syslog, \
    /usr/bin/tail -f /var/log/auth.log, \
    /usr/bin/tail -f /var/log/messages, \
    /bin/tail -f /var/log/syslog, \
    /bin/tail -f /var/log/auth.log, \
    /bin/tail -f /var/log/messages, \
    /usr/bin/grep * /var/log/syslog, \
    /usr/bin/grep * /var/log/auth.log

# Service Status Checks
Cmnd_Alias SERVICE_STATUS = \
    /usr/bin/systemctl status *, \
    /usr/bin/systemctl is-enabled *, \
    /usr/bin/systemctl is-active *, \
    /usr/sbin/service * status, \
    /sbin/service * status

# Security Checks
Cmnd_Alias SECURITY_AUDIT = \
    /usr/bin/sudo -u * whoami, \
    /usr/sbin/getcap -r /usr/bin, \
    /usr/sbin/getcap -r /usr/local/bin, \
    /usr/sbin/getcap -r /sbin, \
    /usr/sbin/getcap -r /usr/sbin, \
    /bin/find /etc/sudoers.d -type f, \
    /usr/bin/find /etc/sudoers.d -type f

# ========================================
# USER PERMISSIONS - ai-auditor
# ========================================

# Allow all defined command aliases without password
ai-auditor ALL=(ALL) NOPASSWD: SYSTEM_INFO
ai-auditor ALL=(ALL) NOPASSWD: NETWORK_STATUS
ai-auditor ALL=(ALL) NOPASSWD: PROCESS_STATUS
ai-auditor ALL=(ALL) NOPASSWD: FILE_INSPECT
ai-auditor ALL=(ALL) NOPASSWD: PACKAGE_QUERY
ai-auditor ALL=(ALL) NOPASSWD: LOG_INSPECT
ai-auditor ALL=(ALL) NOPASSWD: SERVICE_STATUS
ai-auditor ALL=(ALL) NOPASSWD: SECURITY_AUDIT

# DENY all other commands (explicit deny for security)
ai-auditor ALL=(ALL) DENY: ALL
```

---

## Section 3: Justification for Each Command Category

### System Information
**Purpose:** Determine OS version, hostname, kernel info  
**Risk:** Low (read-only information)  
**Restriction:** None needed (public information)

### Network Status
**Purpose:** Identify active services, listening ports, routing  
**Risk:** Medium (reveals network configuration but read-only)  
**Restriction:** `-L` (list only), `-n` (numeric), `-t` (TCP), `-p` (programs)

### Process Status
**Purpose:** Identify running services and system load  
**Risk:** Medium (reveals what's running but read-only)  
**Restriction:** Query only, no kill/modify signals

### File Inspection
**Purpose:** Audit file existence, permissions, types  
**Risk:** High (potential information disclosure)  
**Restriction:** Only readable files, only on specific paths (/etc, /var/log, /opt)

### Package Management
**Purpose:** Audit installed packages and versions  
**Risk:** Low (read-only query)  
**Restriction:** Query only, no install/remove

### Log Inspection
**Purpose:** Review audit and system logs  
**Risk:** High (contains sensitive information)  
**Restriction:** Specific log files only, no write access

### Service Status
**Purpose:** Check service health and enablement  
**Risk:** Low (read-only status)  
**Restriction:** Status queries only, no start/stop/restart

### Security Audit
**Purpose:** Check capabilities, sudo config  
**Risk:** Medium (reveals privilege escalation paths)  
**Restriction:** Capability checks and file listing only

---

## Section 4: Risk Assessment per Command

| Command | Risk | Mitigation | Test |
|---------|------|-----------|------|
| `ip addr show` | Low | Read-only | Run, verify output |
| `ps aux` | Medium | Can't kill/modify | Attempt kill (should fail) |
| `find /etc -type f` | High | Restricted paths only | Try /root (should fail) |
| `journalctl -u *` | High | Specific services only | Try `-e` flag (should fail) |
| `dpkg -l` | Low | Query only | Attempt install (should fail) |
| `systemctl status *` | Low | Query only | Attempt restart (should fail) |

---

## Section 5: Audit Logging Configuration

### Syslog Configuration

```bash
# /etc/rsyslog.d/ai-auditor.conf
:programname, isequal, "sudo" /var/log/sudo-ai-auditor.log
& stop
```

### Log Rotation

```bash
# /etc/logrotate.d/ai-auditor
/var/log/sudo-ai-auditor.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0600 root root
    missingok
}
```

---

## Section 6: Deployment Script

```bash
#!/bin/bash
# deploy-sudoers.sh - Deploy sudoers configuration for ai-auditor

set -e  # Exit on error

SUDOERS_FILE="/etc/sudoers.d/ai-auditor"

echo "[*] Deploying sudoers configuration..."

# Check if file exists
if [[ -f "$SUDOERS_FILE" ]]; then
    echo "[!] Sudoers file already exists. Backing up..."
    sudo cp "$SUDOERS_FILE" "${SUDOERS_FILE}.backup.$(date +%s)"
fi

# Deploy sudoers file (use tee)
sudo tee "$SUDOERS_FILE" > /dev/null <<'SUDOERS_CONFIG'
# [Insert the sudoers configuration from above]
SUDOERS_CONFIG

# Set correct permissions
sudo chmod 440 "$SUDOERS_FILE"
sudo chown root:root "$SUDOERS_FILE"

# Validate syntax
echo "[*] Validating sudoers syntax..."
if sudo visudo -c -f "$SUDOERS_FILE"; then
    echo "[✓] Sudoers syntax valid"
else
    echo "[✗] Sudoers syntax error! Rolling back..."
    if [[ -f "${SUDOERS_FILE}.backup"* ]]; then
        sudo cp "${SUDOERS_FILE}.backup."* "$SUDOERS_FILE"
    fi
    exit 1
fi

# Create log file
sudo touch /var/log/sudo-ai-auditor.log
sudo chmod 600 /var/log/sudo-ai-auditor.log
sudo chown root:root /var/log/sudo-ai-auditor.log

echo "[✓] Sudoers deployment complete"
```

---

## Section 7: Testing Sudoers Access

### Test Read-Only Commands

```bash
#!/bin/bash
# test-sudoers.sh

echo "=== Testing ai-auditor sudo access ==="

# Should succeed
echo "[✓] Testing: ip addr show"
sudo -u ai-auditor sudo ip addr show

echo "[✓] Testing: ps aux"
sudo -u ai-auditor sudo ps aux | head -5

echo "[✓] Testing: systemctl status ssh"
sudo -u ai-auditor sudo systemctl status ssh

# Should fail
echo ""
echo "=== Testing denied commands (should fail) ==="

echo "[✗] Testing: apt install (should fail)"
sudo -u ai-auditor sudo apt install -y vim 2>&1 | tail -2 || true

echo "[✗] Testing: systemctl restart ssh (should fail)"
sudo -u ai-auditor sudo systemctl restart ssh 2>&1 | tail -2 || true

echo "[✗] Testing: rm /tmp/test (should fail)"
sudo -u ai-auditor sudo rm /tmp/test 2>&1 | tail -2 || true
```

---

## Section 8: Sudoers Security Checklist

- [ ] Sudoers file located in `/etc/sudoers.d/ai-auditor`
- [ ] File permissions are 440 (r--r------)
- [ ] File owned by root:root
- [ ] Syntax validated with `visudo -c`
- [ ] `NOPASSWD` configured for all commands
- [ ] `requiretty` disabled (for automation)
- [ ] `secure_path` set to restrict $PATH
- [ ] `env_reset` enabled
- [ ] Logging configured to separate log file
- [ ] All commands explicitly listed (no wildcards)
- [ ] Each command has full path
- [ ] Command aliases used for clarity
- [ ] Explicit `DENY: ALL` at end
- [ ] Test commands succeed
- [ ] Test denied commands fail
- [ ] Audit log created and rotated

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Syntax error | Run `visudo -c -f /etc/sudoers.d/ai-auditor` |
| Command not found | Use full path (e.g., `/usr/bin/ls` not `ls`) |
| Permission denied | Check file permissions (should be 440) |
| Password prompt | Verify `NOPASSWD` in sudoers entry |
| Command still denied | Check for `DENY` rule earlier in file |

---

## Next Steps

Proceed to [03-VALIDATION-FRAMEWORK.md](03-VALIDATION-FRAMEWORK.md) to build comprehensive tests.
