# AI Auditor Threat Model

## Protected assets

- Host integrity and availability
- Root-readable system and infrastructure metadata
- SSH credentials and the `ai-auditor` identity
- Sudo policy and audit records
- Docker daemon metadata, when available

## Trust boundaries

The AI and its prompt/input are untrusted. The fixed collector, its root-owned installation path, the generated sudoers rule, Python runtime, operating system tools, and target administrator are trusted. Collector JSON is sensitive evidence and remains untrusted input when consumed by later analysis.

Docker is a separate boundary. Membership in the Docker socket group or unrestricted daemon access is commonly root-equivalent. The collector invokes only a fixed `docker ps` query, but enabling daemon visibility increases disclosure and dependency risk and must be an explicit host decision.

## Enforced controls

- One no-argument sudo command, executed only as `root:root`
- Root ownership and non-writable installed collector/sudoers paths
- Absolute child executable paths and a fixed environment
- Closed stdin, per-command timeout, isolated process group, and bounded stdout/stderr capture
- Bounded item counts and truncated error text in JSON
- Candidate validation followed by atomic activation
- Positive inventory and negative arbitrary-command deployment checks

## Known limitations

- Root executes Python and several OS utilities, so vulnerabilities in those trusted components remain in scope.
- Inventory exposes account, network, package, service, filesystem, and possibly container metadata.
- A timeout/output cap limits collector resource consumption but is not a complete CPU, memory, syscall, or filesystem sandbox.
- Local sudo logging is not tamper-resistant against a compromised root host.
- SSH restrictions, sudo policy, and collector behavior have not yet been validated across a supported distribution matrix.
- The framework does not yet implement findings, drill-down authorization, report signing, remediation, or human approval workflows.

## Change rule

Do not add a generic interpreter, shell, pager, editor, file reader, recursive search tool, package manager, container command, or user-controlled argument to sudoers. New evidence requirements should normally become fixed collector code with explicit bounds, schema changes, tests, and threat analysis.
