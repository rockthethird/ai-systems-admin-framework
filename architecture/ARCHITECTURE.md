# Architecture & System Design

## System Overview

The AI Systems Admin Framework enables autonomous AI agents to safely perform infrastructure administration tasks through:

1. **Authentication** — SSH key-based, no passwords
2. **Authorization** — Explicit role-based sudoers allowlist
3. **Validation** — Automated testing of restrictions
4. **Auditability** — Complete logging and monitoring

---

## Core Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 INFRASTRUCTURE NETWORK                   │
│         (Audited Systems, Monitored Services)            │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│         SSH Connection (Key-Based, Restricted)           │
│     • No Password Authentication Possible               │
│     • ED25519 Keys Enforced                              │
│     • Forwarding/Tunneling Disabled                     │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│          AI Agent Service Account (Locked)              │
│     • No Interactive Shell Access                        │
│     • System Account (UID < 1000)                        │
│     • Only SSH Key Authentication                        │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│        Sudo Command Execution Layer (Allowlist)          │
│     • Explicit Command Whitelist Only                    │
│     • NOPASSWD (No Password Required)                    │
│     • Environment Reset (Security)                       │
│     • Detailed Logging to Syslog                        │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│      Allowed Operations (Role-Specific)                  │
│     • Audit Module: Read-Only Inspection                │
│     • Compliance Module: Policy Validation               │
│     • Remediation Module: Controlled Fixes               │
│     • Reporting Module: Data Aggregation                │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│         Audit Trail & Monitoring                         │
│     • All Commands Logged to Syslog                      │
│     • Centralized Log Collection (Optional)              │
│     • Real-Time Alerting (Optional)                      │
│     • Archive & Long-Term Storage                        │
└─────────────────────────────────────────────────────────┘
```

---

## Module Architecture

Each module follows the same security pattern:

### 1. Module Definition

```
Module Purpose:  What can this agent do?
Audit Target:    What systems does it access?
Authorization:   Which commands are allowed?
Logging:         What actions are recorded?
Constraints:     What can it NOT do?
```

### 2. Security Layers

```
Layer 1: Authentication
  └─ SSH key-only (no password)
  
Layer 2: Authorization
  └─ Explicit sudoers allowlist
  
Layer 3: Environment
  └─ Restricted shell, reset environment
  
Layer 4: Validation
  └─ Automated testing of restrictions
  
Layer 5: Audit Trail
  └─ Comprehensive logging
```

### 3. Validation Testing

Every module includes:

```
Static Validation:     Configuration is correct
  ├─ Sudoers syntax
  ├─ File permissions
  ├─ User account status
  └─ SSH configuration

Dynamic Validation:    Permissions work as intended
  ├─ Allowed commands execute
  ├─ Denied commands blocked
  ├─ Arguments validated
  └─ Logging functions

Security Validation:   Attack vectors are blocked
  ├─ Shell escapes
  ├─ Privilege escalation
  ├─ Environment injection
  ├─ Information disclosure
  └─ Resource exhaustion
```

---

## Role-Based Access Model

### Role Definition

Each role has:

1. **Purpose** — Why this agent exists
2. **Scope** — Which systems/resources it accesses
3. **Commands** — Explicit allowlist of operations
4. **Constraints** — What it cannot do
5. **Audit** — What gets logged

### Example: Auditor Role

```
Purpose:      Read-only infrastructure inspection
Scope:        All systems on network
Commands:     
  - System info (uname, hostname)
  - Network status (ip, ss, iptables)
  - Process status (ps, systemctl)
  - File inspection (find, ls, stat)
  - Package query (dpkg, apt, rpm)
  - Log inspection (journalctl, tail, grep)
  - Service status (systemctl status)
  - Security audit (getcap, sudoers review)
Constraints:
  ✗ Cannot modify files
  ✗ Cannot restart services
  ✗ Cannot escalate privileges
  ✗ Cannot access /root, /home/*
Audit:
  ✓ All commands logged
  ✓ Failed attempts logged
  ✓ Centralized log collection
```

---

## Trust Model

### Assumptions

1. **SSH Keys are Secure** — Private keys stored in vault or secure environment
2. **Sudoers File Integrity** — Only root can modify sudoers
3. **Kernel Security** — Linux kernel enforces permissions correctly
4. **Audit Log Integrity** — Logs not tampered with by normal processes

### Threat Model

**Attacker Goals:**
- Escalate to root
- Modify protected files
- Access sensitive data
- Maintain persistence
- Cover tracks

**Our Defenses:**
- No password means no authentication bypass
- SSH key-only prevents brute force
- Explicit sudoers allowlist prevents unauthorized commands
- env_reset prevents environment variable injection
- No shell access prevents escape attempts
- Comprehensive logging prevents undetected access

---

## Deployment Models

### Single Server

```
┌─────────────────────┐
│  AI Agent Control   │
│  Machine            │
└──────────┬──────────┘
           │ SSH
           ↓
┌─────────────────────┐
│  Target Server      │
│  ai-auditor account │
│  + sudoers config   │
└─────────────────────┘
```

### Small Network (10-20 servers)

```
┌─────────────────┐
│ AI Agent        │
│ Controller      │
└────────┬────────┘
         │ SSH to each host
    ┌────┴──────┬─────────┬──────────┐
    ↓           ↓         ↓          ↓
 [Host1]    [Host2]   [Host3]  ...[HostN]
```

### Large Network (100+ servers)

```
┌──────────────────────────────────────┐
│  Centralized AI Agent Infrastructure │
│  ├─ SSH Key Management (Vault)       │
│  ├─ Log Aggregation (ELK/Splunk)    │
│  ├─ Monitoring & Alerting            │
│  └─ Compliance Dashboard             │
└──────────────────────────────────────┘
         ↓ SSH to each host
    ┌────┴──────┬─────────┬──────────┐
    ↓           ↓         ↓          ↓
 [Host1]    [Host2]   [Host3]  ...[HostN]
 (ai-auditor)
```

---

## Data Flow

### Audit Execution Flow

```
1. AI Agent initiates audit
   └─ Connects via SSH with key authentication
   
2. SSH daemon validates key
   └─ Enforces sshd config restrictions
   
3. AI Agent executes commands via sudo
   └─ Sudoers verifies allowlist
   └─ Command executes with limited privileges
   
4. Command output returned to agent
   └─ Standard output captured
   └─ Errors logged to audit log
   
5. Audit log written to syslog
   └─ All commands recorded
   └─ Failed attempts recorded
   └─ Timestamps and user recorded
   
6. Logs collected centrally (optional)
   └─ Aggregated with other systems
   └─ Available for analysis and compliance
```

### Permission Enforcement Flow

```
User Input
   ↓
SSH Key Authentication
   ├─ Validates public key
   └─ Rejects if no match
   ↓
sshd_config Restrictions
   ├─ Enforces PubkeyAuthentication
   ├─ Disables forwarding
   ├─ Disables tunneling
   └─ Enforces environment restrictions
   ↓
Sudo Execution
   ├─ Checks sudoers allowlist
   ├─ Rejects if not listed
   ├─ Resets environment
   └─ Logs attempt
   ↓
Command Execution
   ├─ Executes with user privileges
   ├─ Prevented from escalating
   └─ Output returned
   ↓
Audit Logging
   └─ Records all details
```

---

## Scalability Considerations

### Single Agent Deployment

- **Pros:** Simple, minimal configuration
- **Cons:** Single point of failure, limited throughput
- **Use Case:** Small environments, testing

### Distributed Agents

- **Pros:** High availability, parallelization
- **Cons:** Complexity, key management
- **Use Case:** Large enterprises

### Hybrid Model

- **Pros:** Balance between simplicity and scale
- **Cons:** Requires orchestration
- **Use Case:** Medium to large environments

---

## Security Considerations

### Key Management

- Store private keys in secure vault (HashiCorp Vault, AWS Secrets Manager)
- Rotate keys periodically (quarterly or on compromise)
- Different keys per environment (dev, staging, prod)
- Audit key access

### Log Management

- Centralize logs to avoid tampering
- Encrypt logs in transit and at rest
- Retain logs per compliance requirements
- Alert on suspicious access patterns

### Network Security

- Restrict SSH to trusted IPs only
- Use VPN for remote access
- Monitor unusual connection patterns
- Log all SSH authentication attempts

### Operational Security

- Run validation suite regularly
- Review audit logs weekly
- Test incident response procedures quarterly
- Keep framework updated
- Document all customizations

---

## Compliance Mapping

### CIS Benchmarks

- **1.1** Filesystem Configuration ✓
- **3.1** Network Configuration ✓
- **5.2** SSH Configuration ✓
- **6.2** User & Group Settings ✓

### NIST Cybersecurity Framework

- **Identify:** Threats documented, roles defined
- **Protect:** SSH keys, sudoers, validation
- **Detect:** Logging, monitoring, alerts
- **Respond:** Incident procedures documented
- **Recover:** Runbooks and restoration procedures

---

## Extension Points

Framework designed for extensibility:

1. **New Modules** — Add new AI roles with same security model
2. **Custom Commands** — Extend sudoers with additional operations
3. **Custom Validation** — Add module-specific tests
4. **Integrations** — Connect to SIEM, monitoring systems
5. **Orchestration** — Integrate with automation platforms

See [../CONTRIBUTING.md](../CONTRIBUTING.md) for extending the framework.

---

## Performance Characteristics

| Operation | Typical Time | Notes |
|-----------|---------|-------|
| SSH Connection | 100-200ms | Depends on network latency |
| Sudo Validation | 10-50ms | Sudoers file lookup |
| Command Execution | Varies | Depends on command |
| Validation Suite | 1-2 min | Full static + dynamic tests |
| Audit Log Write | <10ms | Asynchronous to syslog |

---

## Disaster Recovery

### Account Compromised

1. Revoke SSH key immediately
2. Lock account: `sudo passwd -l ai-auditor`
3. Kill active sessions: `sudo pkill -u ai-auditor`
4. Review audit logs for unauthorized access
5. Rebuild account from scratch
6. Run full validation suite

### Configuration Lost

1. Restore sudoers from version control
2. Restore SSH authorized_keys backup
3. Verify integrity with checksums
4. Run validation suite
5. Test access before restoring to production

---

## References

- [ROLES.md](ROLES.md) — Detailed role definitions
- [../../modules/audit/](../../modules/audit/) — Auditing module implementation
- [../../CONTRIBUTING.md](../../CONTRIBUTING.md) — Framework extension guide
- [../../security/SECURITY-POLICY.md](../../security/SECURITY-POLICY.md) — Security policies

---

*Last Updated: 2026-08-05*
