# Phase 1: User Account Creation & Configuration

## Overview
This document describes the step-by-step process to create a restricted `ai-auditor` service account with SSH key authentication and zero password authentication.

---

## Step 1: Create the User Account

### Execution

```bash
# Create the user with specific constraints
sudo useradd \
  --system \
  --no-create-home \
  --shell /bin/bash \
  --comment "AI Security Auditor" \
  ai-auditor

# OR: If you want a home directory for configuration
sudo useradd \
  --system \
  --create-home \
  --home-dir /opt/ai-auditor \
  --shell /bin/bash \
  --comment "AI Security Auditor" \
  ai-auditor
```

### Verification

```bash
# Verify user created
id ai-auditor
getent passwd ai-auditor

# Expected output:
# uid=XXX(ai-auditor) gid=YYY(ai-auditor) groups=YYY(ai-auditor)
# ai-auditor:x:XXX:YYY:AI Security Auditor:/opt/ai-auditor:/bin/bash
```

### Important Notes

- Use `--system` to mark as system account (UID < 1000 on most systems)
- `--no-create-home` reduces attack surface; use `--create-home` if SSH key management needs home directory
- Shell is `/bin/bash` to enable execution of audit scripts
- **Never** set a password — account is passwordless by design

---

## Step 2: Configure Shell Environment (Minimal)

### Create Shell Profile

```bash
sudo tee /opt/ai-auditor/.bashrc > /dev/null <<'EOF'
# Minimal shell for ai-auditor account
# No interactive features, no aliases, minimal functionality

# Set safe defaults
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HISTFILE=/dev/null        # Disable command history
export HISTSIZE=0
export HISTFILESIZE=0

# Disable job control (optional but adds security)
set +m

# Set readonly prompt
PS1='ai-auditor$ '

# Disable command completion (reduces functionality, increases security)
complete -r 2>/dev/null || true
EOF

# Set permissions
sudo chmod 644 /opt/ai-auditor/.bashrc
sudo chown ai-auditor:ai-auditor /opt/ai-auditor/.bashrc
```

### Verify Shell Configuration

```bash
sudo -u ai-auditor bash -i -c 'echo $PATH'
sudo -u ai-auditor bash -i -c 'echo $HISTFILE'
```

---

## Step 3: Lock the Account (No Password)

### Execution

```bash
# Lock the account (disable password login)
sudo passwd -l ai-auditor

# Verify account is locked
sudo passwd --status ai-auditor

# Expected output:
# ai-auditor LK 2026-08-05 ...
```

### Key Point

The `L` in the output means the account is **locked** and cannot be used for password authentication. This is the desired state.

---

## Step 4: Set Up SSH Key Authentication

### On Admin/Controller Machine

```bash
# Generate SSH key pair (without passphrase)
# WARNING: Do NOT generate without passphrase in production
# For this use case, consider key stored in secure vault or with passphrase

# Generate key (example with no passphrase for automation)
ssh-keygen -t ed25519 -f ~/.ssh/ai-auditor -C "ai-auditor@auditing-framework" -N ""

# Alternative with RSA (4096-bit)
ssh-keygen -t rsa -b 4096 -f ~/.ssh/ai-auditor -C "ai-auditor@auditing-framework" -N ""

# Output files:
# ~/.ssh/ai-auditor           (private key)
# ~/.ssh/ai-auditor.pub       (public key)
```

### On Target Server

```bash
# Create .ssh directory for ai-auditor
sudo mkdir -p /opt/ai-auditor/.ssh
sudo chmod 700 /opt/ai-auditor/.ssh
sudo chown ai-auditor:ai-auditor /opt/ai-auditor/.ssh

# Add public key to authorized_keys
sudo tee /opt/ai-auditor/.ssh/authorized_keys > /dev/null <<'PUBKEY'
[paste public key from ai-auditor.pub here]
PUBKEY

# Set strict permissions
sudo chmod 600 /opt/ai-auditor/.ssh/authorized_keys
sudo chown ai-auditor:ai-auditor /opt/ai-auditor/.ssh/authorized_keys
```

### Verify SSH Access

```bash
# From admin machine
ssh -i ~/.ssh/ai-auditor ai-auditor@target-server "whoami"

# Expected output:
# ai-auditor
```

---

## Step 5: Configure SSH Daemon (sshd_config)

### Restrict SSH for ai-auditor Account

```bash
# Add to /etc/ssh/sshd_config
sudo tee -a /etc/ssh/sshd_config > /dev/null <<'EOF'

# === Restrictions for ai-auditor service account ===
Match User ai-auditor
    # Allow key-based auth only
    PubkeyAuthentication yes
    PasswordAuthentication no
    
    # Restrict command execution (optional, for maximum lockdown)
    # ForceCommand /opt/ai-auditor/audit-wrapper.sh
    
    # Disable port forwarding
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    PermitTunnel no
    
    # Disable X11 forwarding
    X11Forwarding no
    
    # Restrict authentication methods
    AuthenticationMethods publickey
    
    # Session timeout (30 minutes)
    ClientAliveInterval 1800
    ClientAliveCountMax 0
    
    # Disable environment variable passing
    PermitUserEnvironment no
    
    # Log all login attempts
    LogLevel VERBOSE

EOF

# Validate sshd_config syntax
sudo sshd -t

# If valid, restart SSH daemon
sudo systemctl restart sshd
```

---

## Step 6: File and Directory Permissions

### Verify Ownership and Permissions

```bash
# ai-auditor home directory
sudo ls -ld /opt/ai-auditor/
# Expected: drwx------  ai-auditor ai-auditor

# SSH directory
sudo ls -ld /opt/ai-auditor/.ssh/
# Expected: drwx------  ai-auditor ai-auditor

# authorized_keys
sudo ls -l /opt/ai-auditor/.ssh/authorized_keys
# Expected: -rw-------  ai-auditor ai-auditor
```

### Set File Permissions Script

```bash
#!/bin/bash
# Fix ai-auditor file permissions

AUDIT_HOME="/opt/ai-auditor"
AUDIT_USER="ai-auditor"
AUDIT_GROUP="ai-auditor"

sudo chown -R ${AUDIT_USER}:${AUDIT_GROUP} ${AUDIT_HOME}
sudo chmod 700 ${AUDIT_HOME}
sudo chmod 700 ${AUDIT_HOME}/.ssh
sudo chmod 600 ${AUDIT_HOME}/.ssh/authorized_keys
sudo chmod 644 ${AUDIT_HOME}/.bashrc

echo "File permissions reset for ${AUDIT_USER}"
```

---

## Step 7: Disable Root Login (Optional Hardening)

```bash
# Verify root cannot login via SSH with ai-auditor key
# This should already be prevented by sshd_config Match blocks
```

---

## Security Checklist for User Creation

- [ ] User created with `--system` flag
- [ ] No password set (account locked with `passwd -l`)
- [ ] Home directory owned by ai-auditor with 700 permissions
- [ ] SSH directory exists with 700 permissions
- [ ] authorized_keys contains only necessary public key
- [ ] authorized_keys has 600 permissions
- [ ] Shell is /bin/bash (or restricted shell)
- [ ] Shell configuration is minimal (.bashrc)
- [ ] sshd_config restricts ai-auditor to key-only authentication
- [ ] sshd syntax validated with `sshd -t`
- [ ] SSH daemon restarted after sshd_config changes
- [ ] SSH login tested and verified working
- [ ] SSH password login blocked for ai-auditor

---

## Verification Commands

Run these to verify the account is properly configured:

```bash
#!/bin/bash
# verify-user-creation.sh

echo "=== User Account Verification ==="
id ai-auditor
getent passwd ai-auditor

echo -e "\n=== Password Status (should show LK for Locked) ==="
sudo passwd --status ai-auditor

echo -e "\n=== Home Directory Permissions ==="
sudo ls -ld /opt/ai-auditor/
sudo ls -la /opt/ai-auditor/.ssh/

echo -e "\n=== SSH Configuration ==="
grep -A 10 "Match User ai-auditor" /etc/ssh/sshd_config

echo -e "\n=== Test SSH Login ==="
ssh -i ~/.ssh/ai-auditor ai-auditor@localhost "echo 'SSH login successful'"
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| User not created | Check if user already exists: `getent passwd ai-auditor` |
| SSH login fails | Verify public key in authorized_keys, check sshd_config syntax |
| Permission denied | Check file ownership and permissions (700 for directories, 600 for files) |
| sshd_config error | Validate with `sshd -t`, check for typos |
| Command execution fails | Verify shell is `/bin/bash`, check PATH in .bashrc |

---

## Next Steps

Proceed to [02-SUDOERS-CONFIG.md](02-SUDOERS-CONFIG.md) to configure sudo permissions.
