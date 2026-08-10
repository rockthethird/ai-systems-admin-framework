# AI Systems Administrator Framework

> **A comprehensive, security-first framework for deploying AI agents to perform autonomous infrastructure administration tasks across your network.**

**Status:** Alpha. The auditing inventory path is experimental and not production-ready.

---

## Vision

Enable autonomous AI agents to safely perform infrastructure administration tasks across your network through:

- **Least Privilege:** Each AI role has minimal permissions for its function
- **Continuous Validation:** Automated tests verify restrictions and prevent privilege escalation
- **Auditability:** Preserve useful execution evidence and work toward centralized, tamper-resistant records
- **Defense-in-Depth:** Multiple independent security layers
- **Role-Based Access:** Different AI agents for different functions (audit, compliance, remediation, reporting, etc.)

---

## 🎯 Project Scope

This framework provides templates, validation frameworks, and security best practices for deploying **multiple specialized AI agents**, each with strictly controlled permissions.

### Currently Available

🧪 **Auditing Module** — bounded host inventory prototype
- Fixed privileged collector with a narrow sudo rule
- Host, network, service, package, account, task, and optional container inventory
- Findings, adaptive drill-down, compliance scanning, and reports are not implemented yet

### Planned Modules

🔜 **Compliance Module** — Policy enforcement and remediation  
- Validate configurations against policies
- Remediate violations within controlled scope
- Generate compliance reports
- Produced: Compliance status, remediation logs

🔜 **Reporting Module** — Analysis and insights  
- Aggregate audit data
- Generate executive summaries
- Trend analysis and anomaly detection
- Produced: Reports, dashboards, alerts

🔜 **Maintenance Module** — Routine infrastructure tasks  
- Security patching
- Log rotation and cleanup
- Certificate management
- Produced: Maintenance logs, status updates

🔜 **Incident Response Module** — Automated response actions  
- Malware isolation
- Service restarts
- Network isolation
- Produced: Incident response logs

---

## 📁 Project Structure

```
ai-systems-admin-framework/
│
├── README.md                          (This file - Project overview)
├── CONTRIBUTING.md                    (How to contribute & extend)
├── LICENSE                            (MIT License)
├── .gitignore                         (Git ignore rules)
│
├── architecture/                      (Design & planning)
│   ├── ARCHITECTURE.md                (Overall system design)
│   ├── THREAT-MODEL.md                (Security considerations)
│   └── ROLES.md                       (Role definitions & capabilities)
│
├── modules/                           (Role-specific implementations)
│   │
│   ├── audit/                         (✅ AUDITING MODULE)
│   │   ├── README.md                  (Module overview)
│   │   ├── docs/
│   │   │   ├── 00-PROJECT-PLAN.md
│   │   │   ├── 01-USER-CREATION.md
│   │   │   ├── 02-SUDOERS-CONFIG.md
│   │   │   ├── 03-VALIDATION-FRAMEWORK.md
│   │   │   └── 04-RISK-ASSESSMENT.md
│   │   ├── templates/
│   │   │   ├── sudoers-ai-auditor
│   │   │   └── sshd-config.snippet
│   │   ├── scripts/
│   │   │   ├── setup/
│   │   │   │   ├── 10-create-user.sh
│   │   │   │   ├── 20-setup-ssh-keys.sh
│   │   │   │   └── 30-configure-sudoers.sh
│   │   │   └── validate/
│   │   │       ├── 40-validate-static.sh
│   │   │       ├── 50-validate-dynamic.sh
│   │   │       └── validate-all.sh
│   │   └── tests/
│   │       ├── test-shell-escapes.sh
│   │       ├── test-privilege-escalation.sh
│   │       └── test-audit-logging.sh
│   │
│   ├── compliance/                    (🔜 COMPLIANCE MODULE - Planned)
│   │   └── README.md
│   │
│   ├── reporting/                     (🔜 REPORTING MODULE - Planned)
│   │   └── README.md
│   │
│   └── maintenance/                   (🔜 MAINTENANCE MODULE - Planned)
│       └── README.md
│
├── deployment/                        (Deployment tools & procedures)
│   ├── README.md
│   ├── docker/
│   │   ├── Dockerfile                 (Container image)
│   │   └── docker-compose.yml         (Multi-service setup)
│   ├── terraform/                     (IaC templates)
│   │   ├── main.tf
│   │   └── variables.tf
│   └── ansible/                       (Ansible playbooks)
│       ├── deploy-audit-agent.yml
│       └── group_vars/
│
├── examples/                          (Real-world examples)
│   ├── README.md
│   ├── small-network/                 (Example: 10-20 hosts)
│   ├── medium-network/                (Example: 50-200 hosts)
│   └── enterprise-network/            (Example: 1000+ hosts)
│
├── security/                          (Security policies & validation)
│   ├── SECURITY-POLICY.md
│   ├── INCIDENT-RESPONSE.md
│   └── AUDIT-LOG-SCHEMA.md
│
├── docs/                              (General documentation)
│   ├── GETTING-STARTED.md
│   ├── FAQ.md
│   ├── GLOSSARY.md
│   └── TROUBLESHOOTING.md
│
└── tools/                             (Utility scripts)
    ├── audit-validator.sh             (Comprehensive validation)
    ├── key-rotator.sh                 (SSH key rotation)
    └── compliance-reporter.sh         (Generate reports)
```

---

## 🚀 Quick Start

### For Auditing Module

**Estimated Time:** 5-10 hours spread over 1-2 weeks

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/ai-systems-admin-framework.git
cd ai-systems-admin-framework

# 2. Start with the auditing module
cd modules/audit

# 3. Read the documentation
cat docs/00-PROJECT-PLAN.md

# 4. Follow the implementation roadmap
cat docs/01-USER-CREATION.md

# 5. Run setup scripts
bash scripts/setup/10-create-user.sh
bash scripts/setup/20-setup-ssh-keys.sh
bash scripts/setup/30-configure-sudoers.sh

# 6. Run the currently implemented collector checks
bash tests/test-inventory-collector.sh
```

### For Adding a New Module

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on creating new AI agent roles and modules.

---

## 🔐 Security Foundation

All modules in this framework are built on:

### Three-Layer Security Model

1. **Authentication Layer**
   - SSH key-based only (no passwords)
   - Account locked, cannot be accessed interactively
   - Strict sshd configuration

2. **Authorization Layer**
   - Explicit sudo allowlist (deny by default)
   - Role-specific commands only
   - NOPASSWD for automation
   - Environment reset for injection prevention

3. **Audit & Validation Layer**
   - Local sudo logging
   - Collector schema and failure-boundary tests
   - Manual target-host authorization checks
   - Additional attack simulation and centralized monitoring remain future work

### Intended and currently tested constraints

✅ **No Password Authentication** — Only SSH keys  
🧪 **Narrow Sudo Surface** — One fixed collector path with no arguments
🧪 **Bounded Collection** — Child output and execution time are capped
⚠️ **Sensitive Output** — Inventory must be protected as infrastructure data
⚠️ **Local Logging Only** — Tamper-resistant centralized audit logging is not implemented

---

## 📊 Validation status

The collector currently has executable schema, timeout, missing-command, and output-bound checks. Sudo allow/deny behavior must also be verified on every target host. Older design documents and audit reports are historical context, not evidence that their proposed test suites exist.

---

## 🧪 Validation Framework

Every module includes comprehensive automated testing:

### Static Validation (Configuration)
- Syntax verification
- File permissions and ownership
- User account status
- SSH/sudo/shell configuration

### Dynamic Validation (Functionality)
- Allowed commands execute correctly
- Denied commands are blocked
- Arguments are validated
- Logging works

### Security Validation (Attack Vectors)
- Shell escape attempts blocked
- Privilege escalation attempts blocked
- Environment variable injection prevented
- Information disclosure prevention

**Run the implemented collector validation:**
```bash
bash modules/audit/tests/test-inventory-collector.sh
```

---

## 🎓 Who Is This For?

### Infrastructure Teams
- Deploy read-only auditing agents to network
- Validate security posture automatically
- Generate compliance reports

### Security Teams
- Enforce policy through specialized agents
- Validate privilege restrictions
- Audit access and actions

### DevOps/SRE
- Automate routine infrastructure tasks
- Reduce manual toil
- Maintain security controls

### AI/ML Engineers
- Safe sandbox for AI system administration tasks
- Validated permission frameworks
- Example implementations to build upon

---

## 📚 Documentation

- **[CONTRIBUTING.md](CONTRIBUTING.md)** — How to extend and contribute
- **[architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md)** — System design
- **[architecture/ROLES.md](architecture/ROLES.md)** — Role definitions
- **[security/SECURITY-POLICY.md](security/SECURITY-POLICY.md)** — Security policies
- **[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)** — Getting started guide

**Module-Specific:**
- **[modules/audit/README.md](modules/audit/README.md)** — Auditing module overview
- **[modules/audit/docs/](modules/audit/docs/)** — Complete auditing documentation

---

## 🔄 Development Roadmap

### Phase 1: Auditing (🧪 Alpha)
- Core user account and SSH setup scripts
- Root-only inventory pipeline with one sanitized report sudo capability
- Initial collector boundary tests and threat model
- Target-host validation, findings, and reporting remain in progress

### Phase 2: Compliance (🔜 Q4 2026)
- Policy validation framework
- Automated remediation (controlled)
- Compliance reporting
- Audit trail analysis

### Phase 3: Reporting (🔜 Q1 2027)
- Data aggregation
- Report generation
- Dashboard/visualization
- Alert generation

### Phase 4: Maintenance (🔜 Q2 2027)
- Security patching orchestration
- Certificate management
- Log management
- Routine maintenance tasks

### Phase 5: Incident Response (🔜 Q3 2027)
- Automated response playbooks
- Service isolation
- Evidence preservation
- Incident tracking

---

## 🤝 Contributing

This project welcomes contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- How to add new modules
- Code style and standards
- Testing requirements
- Security considerations

---

## 📜 License

MIT License — See [LICENSE](LICENSE) file

---

## 🆘 Support

- **Issues:** [GitHub Issues](https://github.com/yourusername/ai-systems-admin-framework/issues)
- **Documentation:** See [docs/](docs/) directory
- **Security Issues:** See [SECURITY.md](SECURITY.md)

---

## 🙏 Acknowledgments

Built on security best practices from:
- CIS Benchmarks
- NIST Cybersecurity Framework
- Linux Capabilities & PAM
- Industry-standard hardening guides

---

## 📬 Newsletter & Updates

Star this repository to stay updated on new modules and features!

---

*Building a small, testable safety boundary for AI-assisted infrastructure auditing.*
