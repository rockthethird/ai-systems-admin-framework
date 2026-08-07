# Verification Roadmap (Phase 3+)

This directory is reserved for future testing and verification phases.

---

## Phase 3: Server-Side Verification (Planned)

After deploying sudoers configuration to the server, verification will test:

- ✓ Sudo rules are installed correctly
- ✓ AI Auditor can execute configured commands
- ✓ Commands execute with correct arguments
- ✓ Output is captured properly
- ✓ Permissions are enforced (can't run unauthorized commands)

### Planned Scripts

```
10-verify-sudoers-deployment.sh     Check that sudoers file is installed
20-verify-command-execution.sh      Test that commands actually work
30-verify-permissions-enforced.sh   Verify access control works
```

---

## Phase 4: Dry-Run Testing (Planned)

Safe execution of commands with simulation:

- Read-only commands: Execute and capture output
- State-modifying commands: Dry-run mode (if supported)
- Critical commands: Manual approval workflow

---

## Phase 5: Approval Workflow (Planned)

Formal command execution approval process:

- Command request from AI Auditor
- Admin review and approval
- Execution with audit logging
- Result notification

---

## Current Status

- **Phase 1** ✅ Complete: User creation and SSH setup
- **Phase 2** ✅ Complete: YAML-driven sudoers generation
- **Phase 3** 🔄 Planned: Server-side verification
- **Phase 4** 🔄 Planned: Dry-run testing
- **Phase 5** 🔄 Planned: Approval workflow

---

## Current Workflow

For now, manual testing is required:

```bash
# On server: test each command
ssh ai-auditor@server "sudo /usr/bin/uname -a"
ssh ai-auditor@server "sudo /path/to/other/command"

# Verify output
# Verify no errors
# Verify permissions enforced
```

See [Deploy to Server](../deploy/README.md) for deployment instructions.
