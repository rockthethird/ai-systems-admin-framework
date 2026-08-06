# AI Security Validation Framework for Linux Service Accounts

## Project Objective
Design and build a security-first validation framework that creates and continuously verifies the effective permissions of a restricted Linux service account for autonomous AI auditing operations.

**Core Principle:** Every permission is a potential security vulnerability until explicitly justified, tested, and documented.

---

## Phase 1: Strategy & Architecture

### 1.1 User Account Architecture

#### Account Profile
- **Username:** `ai-auditor` (or similar)
- **Shell:** `/bin/bash` (or `/bin/sh` for minimal attack surface)
- **Home Directory:** `/opt/ai-auditor` or `/var/lib/ai-auditor`
- **Authentication:** SSH key only (no password)
- **Privilege Escalation:** Sudo with specific, audited commands only

#### Core Constraints
1. **Read-only operations only** — no write/modify/delete capabilities
2. **No shell escapes** — commands must be restrictive
3. **No password-based authentication** — SSH key required
4. **No privilege to become root** — cannot escalate beyond own account
5. **Minimal default permissions** — start with least privilege, add only what's needed

### 1.2 Command Categories for Auditing

| Category | Examples | Risk Level | Notes |
|----------|----------|-----------|-------|
| **System Info** | `uname`, `lsb_release`, `hostnamectl` | Low | Read system configuration |
| **Network Status** | `ip`, `ss`, `netstat` | Low | Read network state |
| **Process Inspection** | `ps`, `top`, `systemctl status` | Low | Read process information |
| **File Inspection** | `find`, `ls`, `file`, `stat` | Medium | Restricted paths, no write |
| **Package Info** | `dpkg`, `rpm`, `apt list` | Low | Read package metadata |
| **Service Auditing** | `systemctl`, `service` (status only) | Low | Interrogate service state |
| **Logs Inspection** | `journalctl`, `tail`, `grep` on logs | Medium | Restricted to specific logs |

---

## Phase 2: Implementation Components

### 2.1 User Creation & Configuration
- Create restricted user account
- Configure shell environment
- Set up SSH key authentication
- Apply file permissions

### 2.2 Sudo Configuration (sudoers)
- Define allowed commands with arguments
- Use command aliases for clarity
- Implement `NOPASSWD` with EMPTY PASSWORD
- Add audit logging
- Restrict shell metacharacters

### 2.3 Validation Framework

#### Static Analysis
- Verify sudoers syntax
- Check file ownership and permissions
- Validate SSH key setup
- Audit shell configuration

#### Dynamic Testing
- Test each allowed command
- Verify restrictions work
- Test privilege escalation blocks
- Validate log entries

#### Permission Auditing
- Capability scanning (`getcap`)
- File permission analysis
- Directory traversal checks
- Shell escape attempts

---

## Phase 3: Risk Assessment & Mitigation

### Potential Attack Vectors

| Vector | Mitigation | Test |
|--------|-----------|------|
| Shell escape via sudo | Use `NOPASSWD`, disable shell features | Attempt command substitution |
| Wildcard expansion | Disable in sudoers | Test `*` and `?` in arguments |
| Environment variable injection | Clean environment via sudoers | Set malicious `PATH`, `LD_LIBRARY_PATH` |
| File write via symlink | Restrict file operations | Create symlink to sensitive file |
| SUID binary exploitation | Regular security audits | Check for new SUID binaries |
| Credential reuse | No password stored | Verify no password auth works |
| Capability abuse | Audit capabilities | Run `getcap` on binaries |

---

## Phase 4: Continuous Validation

### Automated Checks
- Weekly permission audits
- Sudoers file integrity
- SSH key validation
- Capability scanning
- Failed sudo attempt logs

### Documentation Requirements
- Justified sudoers entries
- Risk assessment per command
- Test cases for each permission
- Audit log locations

---

## Implementation Roadmap

### Stage 1: Foundation (Week 1)
- [ ] Create user account
- [ ] Configure SSH key authentication
- [ ] Write sudoers template
- [ ] Build static validation scripts

### Stage 2: Testing & Validation (Week 2)
- [ ] Create dynamic test suite
- [ ] Perform permission auditing
- [ ] Document all findings
- [ ] Remediate vulnerabilities

### Stage 3: Deployment (Week 3)
- [ ] Deploy to test servers
- [ ] Set up continuous monitoring
- [ ] Create incident response procedures
- [ ] Document runbooks

### Stage 4: Maintenance (Ongoing)
- [ ] Weekly security audits
- [ ] Update allowed commands as needed
- [ ] Monitor and analyze logs
- [ ] Periodic penetration testing

---

## File Structure

```
ai-agent-security-framework/
├── 00-PROJECT-PLAN.md                 (this file)
├── 01-USER-CREATION.md                (step-by-step user setup)
├── 02-SUDOERS-CONFIG.md               (sudoers design & templates)
├── 03-VALIDATION-FRAMEWORK.md         (testing & auditing approach)
├── 04-RISK-ASSESSMENT.md              (threat model & mitigations)
│
├── scripts/
│   ├── 10-create-user.sh              (automated user creation)
│   ├── 20-setup-ssh-keys.sh           (SSH key generation & deployment)
│   ├── 30-configure-sudoers.sh        (sudoers setup)
│   ├── 40-validate-static.sh          (static permission checks)
│   └── 50-validate-dynamic.sh         (dynamic permission testing)
│
├── sudoers/
│   ├── ai-auditor-template            (base sudoers config)
│   └── ai-auditor-commands.md         (documented allowed commands)
│
├── tests/
│   ├── test-read-only.sh              (read-only enforcement)
│   ├── test-shell-escapes.sh          (escape attempt detection)
│   ├── test-privilege-escalation.sh   (privilege boundary tests)
│   ├── test-environment.sh            (env variable injection tests)
│   └── test-results.log               (test output)
│
└── auditing/
    ├── capability-audit.sh            (getcap analysis)
    ├── permission-audit.sh            (file permission analysis)
    ├── sudoers-audit.sh               (sudoers compliance check)
    └── audit-report.md                (findings & recommendations)
```

---

## Success Criteria

✅ **User Account:** Account created with no password, SSH key authentication only  
✅ **Sudo Access:** Only documented, justified commands executable  
✅ **Read-Only Enforcement:** No write/modify/delete permissions, all tests pass  
✅ **Privilege Boundary:** Cannot escalate to root or other users  
✅ **Shell Security:** No shell escape or metacharacter exploitation  
✅ **Validation:** Automated tests confirm all restrictions  
✅ **Documentation:** Every permission justified and tested  
✅ **Monitoring:** Audit logs capture all sudo attempts  

---

## Security Review Checklist

Before deployment to production:

- [ ] All sudoers entries documented with justification
- [ ] Static validation passed (syntax, ownership, permissions)
- [ ] Dynamic testing passed (all commands work as expected)
- [ ] Escape attempt tests failed (as expected)
- [ ] Privilege escalation attempts blocked
- [ ] Capability audit completed
- [ ] File permission analysis completed
- [ ] SSH key hardening implemented
- [ ] Audit logging configured
- [ ] Incident response procedures documented
- [ ] Security review sign-off obtained

---

## References & Standards

- CIS Linux Benchmarks
- NIST Cybersecurity Framework
- Linux PAM (Pluggable Authentication Modules)
- Sudoers Manual (man sudoers)
- SSH Security Best Practices (RFC 4251-4254)
- Linux Capabilities (man capabilities, man setcap)

---

## Next Steps

1. Review this plan with security team
2. Customize command list for your specific auditing needs
3. Begin Phase 1 implementation with user creation
4. Execute validation framework tests
5. Deploy to test environment
6. Monitor and iterate

---

*Last Updated: 2026-08-05*  
*Version: 1.0 - Initial Plan*
