# Configure Commands

## Purpose

Define which commands the `ai-auditor` service account can execute via sudo.

---

## Configuration File

The YAML configuration file is located in this directory:

```
enabled-commands.yaml
```

---

## Quick Start

### 1. Edit Configuration

```bash
# Edit the YAML configuration
vi enabled-commands.yaml
```

### 2. YAML Format

```yaml
commands:
  - name: "system-info"
    path: "/usr/bin/uname"
    args: "-a"
    description: "Display system information"
```

### 3. Required Fields

| Field | Purpose | Example |
|-------|---------|---------|
| `name` | Unique identifier (used in logs) | `system-info` |
| `path` | Absolute path to executable | `/usr/bin/uname` |
| `args` | Command-line arguments | `-a` |
| `description` | Purpose for audit trail | `Display system information` |

### 4. Adding New Commands

```yaml
commands:
  - name: "system-info"
    path: "/usr/bin/uname"
    args: "-a"
    description: "Display system information"
    
  - name: "disk-usage"
    path: "/usr/bin/df"
    args: "-h"
    description: "Check disk space usage"
```

---

## Important Guidelines

- **One command per entry** — Do not combine multiple commands
- **Absolute paths** — Always use full paths (e.g., `/usr/bin/ls` not `ls`)
- **Test first** — Always test the command manually on the server
- **Review carefully** — Each command will be executable as root
- **Document well** — Use clear descriptions for audit purposes

---

## Security Warnings

⚠️ **CRITICAL:** Any command added here will be executable by `ai-auditor` with sudo privileges.

- Only add commands that are safe for service execution
- Avoid commands that modify system state unless absolutely necessary
- Test all commands on an actual server before deployment
- Review generated sudoers file carefully before deployment

---

## Workflow

After editing the configuration, proceed to build:

```bash
cd ../build
bash ./10-generate-sudoers-from-yaml.sh
```

See [Build Sudoers](../build/README.md) for next steps.

---

## Examples

### Read-Only Operations

```yaml
  - name: "system-info"
    path: "/usr/bin/uname"
    args: "-a"
    description: "Display system information"

  - name: "service-status"
    path: "/usr/bin/systemctl"
    args: "status nginx"
    description: "Check nginx service status"
```

### State-Modifying Operations

```yaml
  - name: "restart-service"
    path: "/usr/bin/systemctl"
    args: "restart nginx"
    description: "Restart nginx service"
```

---

## See Also

- [Build Sudoers](../build/README.md) — Generate sudoers from configuration
- [Deploy to Server](../deploy/README.md) — Deploy generated sudoers
