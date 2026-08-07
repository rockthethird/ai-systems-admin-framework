# Deploy to Server

## Purpose

Deploy and configure the `ai-auditor` service account on monitored systems.

This is a three-step process:
1. Create user account on server
2. Setup SSH authentication on controller
3. Configure sudoers permissions on server

---

## Quick Start

### Step 1: Create User Account (On SERVER)

```bash
# On SERVER machine
sudo bash ./10-create-user.sh
```

Verifies:
- ✓ User `ai-auditor` created (UID < 1000)
- ✓ Home directory `/opt/ai-auditor` created (750)
- ✓ Password locked (SSH keys only)
- ✓ Shell set to `/bin/bash`
- ✓ `.ssh` directory created

**Output:** Guidance to run Step 2 on controller

---

### Step 2: Setup SSH Keys (On CONTROLLER)

```bash
# On CONTROLLER machine
bash ./20-setup-ssh-keys.sh -s server-address
```

Options:
- `-s, --server` **REQUIRED** — Server address (e.g., `user@192.168.1.100`)
- `-c, --controller` Optional — Controller name for documentation
- `-h, --help` Display help message

Performs:
- ✓ Generates ED25519 keypair on controller
- ✓ Deploys public key to server
- ✓ Verifies connection works

**Output:** Guidance to run Step 3 on server

---

### Step 3: Configure Sudoers (On SERVER)

```bash
# On SERVER machine
sudo bash ./30-configure-sudoers.sh
```

Options:
- `-v, --verbose` Verbose output for debugging
- `-h, --help` Display help message

Performs:
- ✓ Deploys sudoers configuration
- ✓ Validates syntax (if `visudo` available)
- ✓ Sets correct permissions (440)
- ✓ Verifies deployment

**Output:** Summary of deployed configuration

---

## Verification

After deployment, verify functionality:

```bash
# Test SSH connection
ssh ai-auditor@server "whoami"

# Test sudo access
ssh ai-auditor@server "sudo /usr/bin/uname -a"

# Check sudoers file
ssh user@server "sudo cat /etc/sudoers.d/ai-auditor"
```

---

## Rollback

Each script creates backups before making changes:

```bash
# On server: Check for backups
ls -la /opt/ai-auditor.backup.*
ls -la /etc/sudoers.d/ai-auditor.backup.*

# Restore user account
sudo /usr/bin/userdel -r ai-auditor

# Restore sudoers
sudo cp /etc/sudoers.d/ai-auditor.backup.* /etc/sudoers.d/ai-auditor
sudo chmod 440 /etc/sudoers.d/ai-auditor
```

---

## Troubleshooting

### "lib/common.sh not found" (Step 2)

This is intentional — script 20 must run on the **controller** (where it has access to lib/common.sh).

```bash
# WRONG: Running on server
ssh user@server bash 20-setup-ssh-keys.sh

# RIGHT: Running on controller
bash 20-setup-ssh-keys.sh -s server-address
```

### SSH connection fails after Step 2

```bash
# On controller: Check key permissions
ls -la ~/.ssh/ai-auditor*

# On server: Check authorized_keys
ssh user@server cat /opt/ai-auditor/.ssh/authorized_keys

# Verify permissions
ssh user@server ls -la /opt/ai-auditor/.ssh/
```

### Sudo access denied after Step 3

```bash
# Check sudoers syntax
sudo visudo -c -f /etc/sudoers.d/ai-auditor

# Check permissions
sudo ls -la /etc/sudoers.d/ai-auditor

# View the file
sudo cat /etc/sudoers.d/ai-auditor
```

---

## Prerequisites

**Step 1 (Create User):**
- Root access on server
- Bash 4.3+

**Step 2 (SSH Keys):**
- Must run on controller (where ai-systems-admin-framework is checked out)
- SSH access to server
- User with sudo privileges on server

**Step 3 (Configure Sudoers):**
- Root access on server
- (Optional) `visudo` for syntax validation

---

## Security Notes

- **SSH keys only** — User `ai-auditor` cannot log in with a password
- **Restricted permissions** — Home directory and SSH keys are 750 and 600
- **Sudo audit trail** — All sudo commands are logged
- **Explicit allowlist** — Only configured commands can be executed
- **DENY by default** — All unauthorized commands are denied

---

## Next Steps

After successful deployment:

1. **Manual testing** — Verify commands work on actual server
2. **Monitoring setup** — Configure logging/alerting if needed
3. **Phase 3+ verification** — See [Verification Roadmap](../verify/ROADMAP.md)

---

## See Also

- [Configure Commands](../configure/README.md) — Define sudoers commands
- [Build Sudoers](../build/README.md) — Generate sudoers configuration
- [Verification Roadmap](../verify/ROADMAP.md) — Future testing phases
