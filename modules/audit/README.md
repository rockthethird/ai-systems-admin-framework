# Auditing Module

> **Read-only infrastructure auditing with AI agents**

Complete, production-ready framework for deploying an AI agent that can safely inspect infrastructure across your network.

---

## 🎯 What This Module Does

The auditing module allows an AI agent to:

✅ **Inspect Infrastructure**
- View network configuration and listening services
- Check running processes and services
- Review system configuration files
- Analyze installed packages

✅ **Security Assessment**
- Audit Linux capabilities
- Review sudo configuration
- Scan for SUID binaries
- Check file permissions

✅ **Monitoring & Compliance**
- Review system and application logs
- Check service health status
- Verify security settings
- Generate audit reports

❌ **What It Cannot Do**
- Modify any files or configurations
- Install/remove packages
- Restart/stop services
- Escalate privileges
- Execute unauthorized commands

---

## 🚀 Quick Start

**Estimated Time:** 5-10 hours over 1-2 weeks

### 1. Read the Documentation

Start with the implementation guide:

```bash
# Read the overview and strategy
cat docs/00-PROJECT-PLAN.md

# Read the detailed implementation roadmap
cat docs/IMPLEMENTATION-ROADMAP.md
```

### 2. Follow the Setup Phases

**Phase 1: User Account & SSH (30 min)**
```bash
cat docs/01-USER-CREATION.md
bash scripts/setup/10-create-user.sh
bash scripts/setup/20-setup-ssh-keys.sh
```

**Phase 2: Sudo Configuration (1 hour)**
```bash
cat docs/02-SUDOERS-CONFIG.md
bash scripts/setup/30-configure-sudoers.sh
```

**Phase 3: Validation Testing (2 hours)**
```bash
cat docs/03-VALIDATION-FRAMEWORK.md
bash scripts/validate/validate-all.sh
```

**Phase 4: Risk Assessment (1 hour)**
```bash
cat docs/04-RISK-ASSESSMENT.md
# Review security policies
```

### 3. Deploy

Once validation passes 100%, you're ready to deploy to production.

---

## 📁 Module Structure

```
audit/
├── README.md                    (This file)
├── docs/
│   ├── 00-PROJECT-PLAN.md      (Strategic plan & phases)
│   ├── 01-USER-CREATION.md     (User setup with SSH hardening)
│   ├── 02-SUDOERS-CONFIG.md    (Sudo configuration guide)
│   ├── 03-VALIDATION-FRAMEWORK.md (Testing & validation)
│   ├── 04-RISK-ASSESSMENT.md   (Threat model & mitigations)
│   └── IMPLEMENTATION-ROADMAP.md (Week-by-week implementation)
│
├── templates/
│   ├── sudoers-ai-auditor      (Sudo configuration template)
│   └── ai-auditor-commands.md  (Justification for each command)
│
├── scripts/
│   ├── setup/
│   │   ├── 10-create-user.sh          (Create ai-auditor account)
│   │   └── 20-setup-ssh-keys.sh       (SSH key setup)
│   │   └── 30-configure-sudoers.sh    (Deploy sudoers config)
│   │
│   └── validate/
│       ├── 40-validate-static.sh      (27 configuration checks)
│       ├── 50-validate-dynamic.sh     (18 permission tests)
│       └── validate-all.sh            (Master validation suite)
│
└── tests/
    ├── test-shell-escapes.sh      (8 shell escape vectors)
    ├── test-privilege-escalation.sh (6 escalation vectors)
    └── test-audit-logging.sh       (Logging verification)
```

---

## 🔐 Security Model

### Three-Layer Defense

1. **Authentication:** SSH keys only (no password, account locked)
2. **Authorization:** Explicit sudoers allowlist (NOPASSWD, all logged)
3. **Validation:** Automated tests (40+ checks, 14+ attack vectors)

### Guarantees

✅ No password authentication possible  
✅ No interactive shell access  
✅ Cannot escalate to root or other users  
✅ Cannot modify files or configurations  
✅ All actions logged and auditable  
✅ Shell escapes blocked  
✅ Privilege escalation blocked  

---

## 📊 Testing Coverage

### Static Validation (27 checks)
- User account configuration
- SSH key setup
- Sudoers syntax and permissions
- Shell environment
- Audit logging

### Dynamic Validation (18 tests)
- Allowed commands execute correctly
- Denied commands are blocked
- Arguments validated
- Logging works

### Security Testing (14+ vectors)
- 8 shell escape attempts blocked
- 6 privilege escalation attempts blocked
- 3 environment injection attempts blocked
- Symlink exploitation prevented
- SUID/capability abuse prevented
- Information disclosure prevented

**Run complete validation:**
```bash
bash scripts/validate/validate-all.sh
```

---

## 🎓 Learning Outcomes

After completing this module, you'll understand:

- How to create restricted Linux user accounts
- SSH key-based authentication hardening
- Sudo configuration and security best practices
- Automated permission validation approaches
- Threat modeling and risk assessment
- Compliance frameworks (CIS, NIST)

---

## 📋 Audit Commands

The framework grants access to 8 command categories:

1. **System Information** — OS version, hostname, kernel
2. **Network Status** — Interfaces, routes, firewall rules (read-only)
3. **Process Status** — Running processes, service status
4. **File Inspection** — Configuration files (readable only, limited paths)
5. **Package Query** — Installed packages (query-only)
6. **Log Inspection** — System and application logs
7. **Service Status** — Service health and enablement
8. **Security Audit** — Capabilities, SUID binaries, sudoers review

**All other commands are denied.**

See [templates/ai-auditor-commands.md](templates/ai-auditor-commands.md) for justifications.

---

## 🚀 Deployment

### For Small Networks (10-20 hosts)

1. Create ssh-auditor account on each host
2. Deploy authorized_keys from control machine
3. Configure sudoers on each host
4. Run validation on each host
5. Access from AI agent machine via SSH

### For Large Networks (100+ hosts)

1. Use Ansible/Terraform for automated deployment
2. Store SSH keys in secure vault (HashiCorp Vault, AWS Secrets Manager)
3. Centralize audit log collection
4. Set up monitoring and alerting
5. Use configuration management (Ansible, Chef, Puppet)

---

## 🔄 Maintenance

### Daily
- Monitoring systems track access attempts
- No manual action needed

### Weekly
- Run automated audits
- Review access patterns
- Check for suspicious activity

### Monthly
- Review and update sudoers if needed
- Analyze audit logs for trends
- Update documentation

### Quarterly
- Penetration testing
- Security assessment
- Capabilities audit

### Annually
- Full security review
- Compliance validation
- Risk assessment update

---

## ❓ Common Questions

### Q: Can I add more commands?

**A:** Yes! Update sudoers template, test the command, run validation, update documentation, and assess risks. The framework makes this safe.

### Q: What if I need to rotate SSH keys?

**A:** Remove old key from authorized_keys, add new key, test access, destroy old key. See runbooks for detailed procedures.

### Q: Can multiple AI agents use this account?

**A:** Not recommended. Create separate accounts for each agent. This enables per-agent audit trails and independent permission management.

### Q: How do I know it's working correctly?

**A:** Run the validation suite. It performs 40+ checks across static configuration, dynamic permissions, and security testing.

```bash
bash scripts/validate/validate-all.sh
```

Expected: 100% pass rate.

---

## 📞 Support

- **Documentation:** See [docs/](docs/) directory
- **Issues:** Report bugs in GitHub Issues
- **Security:** See [SECURITY.md](../../SECURITY.md)

---

## 📜 License

MIT License — See root [LICENSE](../../LICENSE) file

---

**Ready to audit your infrastructure safely?** Start with [docs/00-PROJECT-PLAN.md](docs/00-PROJECT-PLAN.md) 🚀
