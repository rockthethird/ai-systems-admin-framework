# AI Auditor Service Account - Command Justification & Risk Assessment (Historical)

> This describes an earlier multi-command design. Those commands are not enabled. The fixed collector and `configure/enabled-commands.yaml` are authoritative.

## Overview
This document provides justification for each command category allowed for the `ai-auditor` service account, including risk assessment and restrictions.

---

## Command Categories & Justifications

### 1. SYSTEM_INFO - Operating System Information

**Commands Included:**
- `uname` — Kernel and OS version
- `lsb_release` — Distribution information
- `hostname` / `hostnamectl` — System hostname

**Audit Purpose:**
- Determine target system OS version for compatibility
- Identify kernel version for known vulnerability checks
- Verify system hostname matches network expectations

**Risk Assessment:**
- **Severity:** LOW
- **Confidentiality:** Public information
- **Integrity Risk:** None (read-only)
- **Availability Risk:** None (instantaneous, low overhead)

**Restrictions:**
- None needed (public information)
- Read-only by nature

**Test Case:**
```bash
sudo -u ai-auditor sudo uname -a        # Should succeed
sudo -u ai-auditor sudo lsb_release -a  # Should succeed
```

---

### 2. NETWORK_STATUS - Network Configuration & Connection Status

**Commands Included:**
- `ip addr show` — Network interfaces
- `ip route show` — Routing table
- `ss -tulnap` — Socket statistics (TCP/UDP/Listening/Numeric/Programs)
- `netstat -tulnap` — Alternative to ss
- `iptables -L` / `ip6tables -L` — Firewall rules

**Audit Purpose:**
- Identify all network interfaces and IP addresses
- Determine which services are listening on network
- Review firewall rules for security posture
- Detect unauthorized listening ports
- Verify expected network connectivity

**Risk Assessment:**
- **Severity:** MEDIUM
- **Confidentiality Risk:** Medium (reveals network configuration)
- **Integrity Risk:** None (read-only)
- **Availability Risk:** Low (fast queries)

**Restrictions:**
- `-L` (list only) — cannot modify rules
- `-n` (numeric) — no DNS lookups
- `-t` (TCP), `-u` (UDP) — specific protocols only
- Output only, cannot execute modifications

**Potential Exploits Prevented:**
- Cannot add firewall rules
- Cannot close listening ports
- Cannot modify routing
- Cannot intercept traffic

**Test Cases:**
```bash
sudo -u ai-auditor sudo ip addr show              # Should work
sudo -u ai-auditor sudo ss -tulnap                # Should work
sudo -u ai-auditor sudo iptables -L               # Should work
sudo -u ai-auditor sudo iptables -A INPUT -j DROP # Should FAIL
sudo -u ai-auditor sudo ip route add 10.0.0.0     # Should FAIL
```

---

### 3. PROCESS_STATUS - Running Process & Service Status

**Commands Included:**
- `ps aux` — All running processes with details
- `ps -ef` — Alternative format
- `top -b -n 1` — Process statistics
- `systemctl status` — Service status
- `systemctl list-units` — Service listing
- `systemctl show` — Service details
- `systemctl is-enabled / is-active` — Service state queries

**Audit Purpose:**
- Identify all running processes
- Detect rogue/unauthorized processes
- Check service health and status
- Verify expected services are running
- Identify resource-consuming processes

**Risk Assessment:**
- **Severity:** LOW-MEDIUM
- **Confidentiality Risk:** Low-Medium (process info is mostly public, some args may contain secrets)
- **Integrity Risk:** None (read-only)
- **Availability Risk:** Low (queries only)

**Restrictions:**
- Status/list only — cannot send signals
- Cannot use `-k` (kill), `-9`, `-15`, etc.
- Cannot use `-s` (signal)
- Cannot restart/start/stop services

**Potential Exploits Prevented:**
- Cannot kill processes
- Cannot stop critical services
- Cannot SIGHUP to reload configurations
- Cannot pause/suspend processes

**Test Cases:**
```bash
sudo -u ai-auditor sudo ps aux                    # Should work
sudo -u ai-auditor sudo systemctl status ssh      # Should work
sudo -u ai-auditor sudo ps -9 $(pgrep sshd)       # Should FAIL
sudo -u ai-auditor sudo systemctl restart ssh     # Should FAIL
sudo -u ai-auditor sudo killall apache2           # Should FAIL
```

---

### 4. FILE_INSPECT - File System Inspection (Restricted Paths)

**Commands Included:**
- `find /etc` — Configuration files (readable only)
- `find /var/log` — Log files (readable only)
- `find /opt` — Application directories (readable only)
- `ls` — Directory listing
- `file` — File type detection
- `stat` — File metadata

**Audit Purpose:**
- Audit configuration files for changes
- Search for specific configurations
- Check file permissions and ownership
- Detect suspicious files in system paths
- Verify file integrity

**Risk Assessment:**
- **Severity:** HIGH
- **Confidentiality Risk:** High (configs may contain secrets)
- **Integrity Risk:** None (read-only)
- **Availability Risk:** Medium (could enumerate large trees)

**Restrictions:**
- `-type f -readable` — only readable regular files
- Specific paths only: /etc, /var/log, /opt
- Cannot use `-exec` with commands
- Cannot follow symlinks into sensitive areas
- Output only, no modifications

**Potential Exploits Prevented:**
- Cannot read /etc/shadow (not readable to regular user)
- Cannot traverse /root or /home/sensitive
- Cannot find and execute suspicious scripts
- Cannot use find to discover and attack sensitive files

**Test Cases:**
```bash
sudo -u ai-auditor sudo find /etc -type f -readable      # Should work
sudo -u ai-auditor sudo find /var/log -type f -readable  # Should work
sudo -u ai-auditor sudo find /root -type f               # Should FAIL
sudo -u ai-auditor sudo find / -type f -exec rm {} \;    # Should FAIL
sudo -u ai-auditor sudo cat /etc/shadow                  # Should FAIL
```

---

### 5. PACKAGE_QUERY - Package Management (Query Only)

**Commands Included:**
- `dpkg -l` / `dpkg -L` — Debian packages list
- `apt list --installed` — APT packages
- `rpm -qa` / `rpm -ql` — RPM packages
- Output only, no package modification

**Audit Purpose:**
- Audit installed packages for known vulnerabilities
- Verify expected packages are installed
- Check package versions for compliance
- Generate software Bill of Materials (SBOM)
- Identify unauthorized software installations

**Risk Assessment:**
- **Severity:** LOW
- **Confidentiality Risk:** Low (package info is metadata)
- **Integrity Risk:** None (read-only)
- **Availability Risk:** Low (queries only)

**Restrictions:**
- Query/list only — no install/remove/upgrade
- No `-e` (evidence), `-i` (install), `-r` (remove)
- No system modification possible
- Output only

**Potential Exploits Prevented:**
- Cannot install backdoored packages
- Cannot remove security packages
- Cannot modify package management
- Cannot use package system for privilege escalation

**Test Cases:**
```bash
sudo -u ai-auditor sudo dpkg -l                       # Should work
sudo -u ai-auditor sudo apt list --installed          # Should work
sudo -u ai-auditor sudo dpkg -L curl                  # Should work
sudo -u ai-auditor sudo apt install -y vim            # Should FAIL
sudo -u ai-auditor sudo apt remove -y openssh-server  # Should FAIL
```

---

### 6. LOG_INSPECT - System Log Inspection (Path Restricted)

**Commands Included:**
- `journalctl` — Systemd journal with various filters
- `tail -f /var/log/*.log` — Follow specific log files
- `grep` — Search logs
- Output filters only, no modification

**Audit Purpose:**
- Review system events and warnings
- Investigate security-related events
- Check service startup/failure reasons
- Search for specific error messages
- Audit user login attempts and sudo commands
- Detect anomalous system behavior

**Risk Assessment:**
- **Severity:** HIGH
- **Confidentiality Risk:** High (logs contain sensitive info)
- **Integrity Risk:** None (read-only)
- **Availability Risk:** Low (queries only)

**Restrictions:**
- Specific log files and systemd journal only
- Output only, no log modification/deletion
- Cannot clear logs or rotate prematurely
- Cannot write to log files

**Potential Exploits Prevented:**
- Cannot modify or delete audit logs
- Cannot cover tracks of unauthorized access
- Cannot clear evidence of security breaches
- Cannot manipulate log timestamps
- Cannot inject false log entries

**Test Cases:**
```bash
sudo -u ai-auditor sudo journalctl -n 100           # Should work
sudo -u ai-auditor sudo journalctl -u ssh           # Should work
sudo -u ai-auditor sudo tail -f /var/log/auth.log   # Should work
sudo -u ai-auditor sudo grep 'error' /var/log/syslog # Should work
sudo -u ai-auditor sudo rm /var/log/auth.log        # Should FAIL
sudo -u ai-auditor sudo journalctl --vacuum-size=1G # Should FAIL
```

---

### 7. SERVICE_STATUS - Service Management (Status Only)

**Commands Included:**
- `systemctl status` — Service status
- `service * status` — Alternative status command
- Status queries only

**Audit Purpose:**
- Check if critical services are running
- Verify service is in expected state
- Diagnose service-related issues
- Monitor service health
- Detect service crashes or stops

**Risk Assessment:**
- **Severity:** LOW
- **Confidentiality Risk:** Low
- **Integrity Risk:** None (read-only)
- **Availability Risk:** Low

**Restrictions:**
- Status queries only
- No `start`, `stop`, `restart`, `reload`, `enable`, `disable`
- No configuration modification
- No signal sending

**Potential Exploits Prevented:**
- Cannot start malicious services
- Cannot stop security services
- Cannot disable critical services
- Cannot use systemctl for privilege escalation

**Test Cases:**
```bash
sudo -u ai-auditor sudo systemctl status ssh         # Should work
sudo -u ai-auditor sudo systemctl is-active ssh     # Should work
sudo -u ai-auditor sudo systemctl start ssh         # Should FAIL
sudo -u ai-auditor sudo systemctl restart ssh       # Should FAIL
sudo -u ai-auditor sudo systemctl stop ssh          # Should FAIL
```

---

### 8. SECURITY_AUDIT - Capability & Permission Auditing

**Commands Included:**
- `getcap -r` — Linux capabilities audit
- `find /etc/sudoers.d` — Sudoers file discovery
- `cat /etc/sudoers.d/*` — Sudoers review
- Read-only auditing only

**Audit Purpose:**
- Audit Linux capabilities on binaries
- Verify no unexpected capabilities granted
- Detect capability-based privilege escalation vectors
- Review sudo configuration for weaknesses
- Verify least-privilege enforcement

**Risk Assessment:**
- **Severity:** MEDIUM
- **Confidentiality Risk:** Medium (reveals escalation paths)
- **Integrity Risk:** None (read-only)
- **Availability Risk:** Low

**Restrictions:**
- `-r` (read/report only) for capabilities
- No `setcap` to modify capabilities
- No `visudo` or direct sudoers editing
- Read-only access to configuration

**Potential Exploits Prevented:**
- Cannot grant new capabilities
- Cannot remove capability restrictions
- Cannot modify sudo configuration
- Cannot create new privilege escalation paths

**Test Cases:**
```bash
sudo -u ai-auditor sudo getcap -r /usr/bin          # Should work
sudo -u ai-auditor sudo find /etc/sudoers.d -type f # Should work
sudo -u ai-auditor sudo setcap cap_net_admin=ep /bin/ping  # Should FAIL
sudo -u ai-auditor sudo visudo                      # Should FAIL
```

---

## Commands Explicitly DENIED

### System Modification
- `apt install`, `apt remove`, `apt upgrade` — Package installation
- `useradd`, `userdel`, `passwd` — User management
- `systemctl start/stop/restart` — Service control
- `mount`, `umount` — Filesystem operations

### File Operations
- `rm`, `touch`, `chmod`, `chown` — File manipulation
- `cp`, `mv` — File moving
- `write` — Kernel log manipulation

### Network Modification
- `iptables -A`, `ip route add` — Network rule modification
- `ifconfig up/down` — Interface control
- `ip link set` — Link configuration

### Shell & Execution
- `bash`, `sh`, `csh` — Interactive shells
- `sudo su`, `sudo -i` — Privilege escalation
- `visudo`, `editors` — Configuration editing

### Logging & Audit
- `journalctl --vacuum` — Log clearing
- `logrotate`, manual log deletion — Evidence destruction
- `auditctl` — Audit configuration

---

## Summary Risk Matrix

| Command Category | Audit Need | Risk Level | Restrictions | Test Coverage |
|------------------|-----------|-----------|--------------|----------------|
| System Info | Required | LOW | None | ✅ High |
| Network Status | Required | MEDIUM | List-only, specific flags | ✅ High |
| Process Status | Required | MEDIUM | Query-only, no signals | ✅ High |
| File Inspect | Required | HIGH | Readable only, specific paths | ✅ High |
| Package Query | Required | LOW | Query-only, no modification | ✅ Medium |
| Log Inspect | Required | HIGH | Read-only, no deletion | ✅ High |
| Service Status | Required | LOW | Status-only, no control | ✅ Medium |
| Security Audit | Required | MEDIUM | Read-only, no modification | ✅ Medium |

---

## Approval & Sign-Off

**Document Prepared By:** _________________  
**Security Review Date:** _________________  
**Approved By:** _________________ (Security Team)  
**Deployment Date:** _________________  

**Approval Notes:**
```
All command restrictions have been reviewed and approved.
Each command category has been justified for the audit use case.
All attempted exploits are prevented by the restrictions.
```

---

*Last Updated: 2026-08-05*  
*Version: 1.0 - Initial Command Justification*
