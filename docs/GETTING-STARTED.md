# Getting Started with AI Systems Admin Framework

Welcome! This guide will help you get up and running with the framework.

---

## 🎯 What Is This?

The **AI Systems Admin Framework** enables autonomous AI agents to safely perform infrastructure administration tasks through:

- **Security-First Design** — Multiple layers of protection
- **Role-Based Access** — Different agents for different functions
- **Continuous Validation** — Automated testing of restrictions
- **Complete Auditability** — Everything logged and reviewable

---

## 📋 Prerequisites

### System Requirements

- Linux system (Ubuntu, Debian, CentOS, RHEL, or similar)
- SSH access with key authentication
- Sudo access (for initial setup)
- Bash shell

### Knowledge Requirements

- Familiarity with Linux command line
- Understanding of SSH keys and authentication
- Basic knowledge of sudoers and sudo
- Appreciation for security best practices

---

## 🚀 Quick Start (30 minutes)

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ai-systems-admin-framework.git
cd ai-systems-admin-framework
```

### 2. Explore the Structure

```bash
# See what's available
tree -L 2

# Start with auditing module
cd modules/audit
```

### 3. Read the Overview

```bash
# Module overview (10 min)
cat README.md

# Project plan (10 min)
cat docs/00-PROJECT-PLAN.md

# Implementation roadmap (10 min)
cat docs/IMPLEMENTATION-ROADMAP.md
```

### 4. Understand the Security Model

```bash
# Risk assessment and threat model (15 min)
cat docs/04-RISK-ASSESSMENT.md
```

### 5. Review the Code

```bash
# Check the sudoers template
cat templates/sudoers-ai-auditor

# Read the command justifications
cat modules/audit/policy/collectors.yaml
cat modules/audit/policy/rules.yaml
cat modules/audit/policy/profiles.yaml
cat modules/audit/policy/identities.yaml
```

---

## 🔐 Security Model (Quick Version)

### Three-Layer Protection

```
Layer 1: SSH Key Authentication
  └─ Only way to access account
  └─ Password authentication disabled
  └─ Account locked (cannot be accessed interactively)

Layer 2: Sudo Explicit Allowlist
  └─ Only documented commands allowed
  └─ No password required (SSH key auth is sufficient)
  └─ Environment variables reset for security
  └─ All actions logged

Layer 3: Automated Validation
  └─ 40+ configuration checks
  └─ 18 permission tests
  └─ 14+ attack vector simulations
  └─ 100% pass rate required before production
```

### What The Framework Prevents

- ✓ Password-based authentication
- ✓ Shell escape attempts
- ✓ Privilege escalation to root
- ✓ Execution of unauthorized commands
- ✓ Environment variable injection
- ✓ Symlink exploitation
- ✓ Information disclosure

---

## 📁 Finding What You Need

### For AI Auditing

Start here: [modules/audit/README.md](modules/audit/README.md)

Key files:
- Setup guide: [modules/audit/docs/01-USER-CREATION.md](modules/audit/docs/01-USER-CREATION.md)
- Sudoers config: [modules/audit/docs/02-SUDOERS-CONFIG.md](modules/audit/docs/02-SUDOERS-CONFIG.md)
- Validation: [modules/audit/docs/03-VALIDATION-FRAMEWORK.md](modules/audit/docs/03-VALIDATION-FRAMEWORK.md)
- Risk assessment: [modules/audit/docs/04-RISK-ASSESSMENT.md](modules/audit/docs/04-RISK-ASSESSMENT.md)

### For Creating a New Module

Start here: [CONTRIBUTING.md](CONTRIBUTING.md)

Key sections:
- Module structure requirements
- Documentation template
- Testing checklist
- Security review process

### For System Architecture

Start here: [architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md)

Key concepts:
- Overall system design
- Trust model
- Deployment patterns
- Scalability

### For Security Policies

Start here: [security/SECURITY-POLICY.md](security/SECURITY-POLICY.md)

Key topics:
- SSH key management
- Audit logging
- Incident response
- Compliance

---

## ✅ Implementation Checklist

### Phase 1: Learning (1-2 hours)
- [ ] Read README.md (this project)
- [ ] Read architecture/ARCHITECTURE.md
- [ ] Read modules/audit/README.md
- [ ] Review threat model in docs/04-RISK-ASSESSMENT.md
- [ ] Understand the security model

### Phase 2: Setup (2-3 hours)
- [ ] Choose your module (start with audit)
- [ ] Read the module documentation
- [ ] Prepare your test/staging environment
- [ ] Gather SSH keys and configuration

### Phase 3: Deployment (2-4 hours)
- [ ] Follow the module setup guide step-by-step
- [ ] Create user account
- [ ] Configure SSH keys
- [ ] Deploy sudoers configuration
- [ ] Run validation suite

### Phase 4: Validation (1-2 hours)
- [ ] Run all validation tests
- [ ] Fix any issues
- [ ] Achieve 100% test pass rate
- [ ] Review audit logs

### Phase 5: Production (1 hour)
- [ ] Deploy to production servers
- [ ] Test access from control machine
- [ ] Set up monitoring/alerting
- [ ] Document your setup

---

## 🧪 Testing Your Setup

Every module includes comprehensive tests. Run them frequently:

```bash
# For auditing module
cd modules/audit
bash scripts/validate/validate-all.sh

# Expected output: All tests pass ✓
```

What gets tested:
- ✓ Static configuration (27 checks)
- ✓ Dynamic permissions (18 tests)
- ✓ Security restrictions (14+ vectors)

---

## 🆘 Common Issues

### "Permission denied" when running sudo

**Cause:** Sudoers not configured correctly

**Fix:**
1. Verify sudoers syntax: `sudo visudo -c -f /etc/sudoers.d/ai-auditor`
2. Check file permissions: `sudo ls -la /etc/sudoers.d/ai-auditor`
3. Should be: `-r--r-----  1 root root`
4. Re-run setup script: `bash scripts/setup/30-configure-sudoers.sh`

### "SSH key rejected"

**Cause:** Public key not in authorized_keys

**Fix:**
1. Verify key location: `cat ~/.ssh/id_rsa.pub`
2. Check authorized_keys: `sudo cat /opt/ai-auditor/.ssh/authorized_keys`
3. Add key if missing: `echo "YOUR-PUBLIC-KEY" | sudo tee -a /opt/ai-auditor/.ssh/authorized_keys`
4. Fix permissions: `sudo chmod 600 /opt/ai-auditor/.ssh/authorized_keys`

### Validation tests failing

**Cause:** Configuration not yet complete

**Fix:**
1. Read the error message carefully
2. Check the specific setup step mentioned
3. Follow the module documentation
4. Re-run validation: `bash scripts/validate/validate-all.sh`

---

## 🎓 Learning Path

### Beginner
1. Read README.md (overview)
2. Read architecture/ARCHITECTURE.md (how it works)
3. Read modules/audit/README.md (your first module)

### Intermediate
1. Follow setup guide step-by-step
2. Understand each configuration file
3. Run validation tests
4. Review audit logs

### Advanced
1. Create custom sudoers entries
2. Add new audit commands
3. Create new modules
4. Contribute improvements

---

## 🤝 Contributing

Found an issue? Want to add a module? See [CONTRIBUTING.md](CONTRIBUTING.md)

Improvements we'd love:
- New modules (compliance, reporting, maintenance)
- Better documentation
- Additional test cases
- Real-world examples

---

## 📚 Key Documentation

| Document | Purpose | Time |
|----------|---------|------|
| README.md | Project overview | 15 min |
| architecture/ARCHITECTURE.md | System design | 20 min |
| architecture/ROLES.md | Role definitions | 15 min |
| modules/audit/docs/00-PROJECT-PLAN.md | Audit strategy | 15 min |
| modules/audit/docs/01-USER-CREATION.md | Setup guide | 20 min |
| modules/audit/docs/02-SUDOERS-CONFIG.md | Sudo config | 20 min |
| modules/audit/docs/03-VALIDATION-FRAMEWORK.md | Testing | 20 min |
| modules/audit/docs/04-RISK-ASSESSMENT.md | Security | 20 min |

---

## 🎯 Next Steps

**Right now:**
1. Clone the repository
2. Read the project README
3. Explore the architecture

**Tomorrow:**
1. Choose your first module (probably auditing)
2. Read the module documentation
3. Set up a test environment

**This week:**
1. Follow the implementation guide
2. Create the user account
3. Configure SSH and sudo
4. Run validation tests

**Next week:**
1. Deploy to production
2. Test access
3. Set up monitoring
4. Start using the framework

---

## ❓ Questions?

- Check [docs/FAQ.md](docs/FAQ.md) for common questions
- Open a GitHub Issue for bugs
- See [SECURITY.md](SECURITY.md) for security questions
- Review module-specific documentation

---

**Ready to get started?** Read [modules/audit/README.md](modules/audit/README.md) next! 🚀
