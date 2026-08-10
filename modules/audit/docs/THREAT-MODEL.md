# AI Auditor Threat Model

## Protected assets

- Host integrity and availability
- Root-readable system and infrastructure metadata
- SSH credentials and the `ai-auditor` identity
- Sudo policy and audit records
- Docker daemon metadata, when available
- Raw inventory and evidence-rich local findings

## Trust boundaries

The AI and its prompt/input are untrusted. The fixed collector, its root-owned installation path, the generated sudoers rule, Python runtime, operating system tools, and target administrator are trusted. Collector JSON is sensitive evidence and remains untrusted input when consumed by later analysis.

Docker is a separate boundary. Membership in the Docker socket group or unrestricted daemon access is commonly root-equivalent. The collector invokes only a fixed `docker ps` query, but enabling daemon visibility increases disclosure and dependency risk and must be an explicit host decision.

Externally hosted model inference is another boundary. Raw inventory and local findings do not cross it by default. The `external-safe/v1` sanitizer emits a minimized, fail-closed view containing only known deterministic rule text, summary data, hashes, and evidence counts/categories. Host identifiers, timestamps, evidence paths, and observations remain local.

The current Hermes-on-audited-host arrangement is a temporary test topology. Its direct SSH and Docker access can bypass the sanitizer, so external-safe output is a data-minimization guardrail in that environment rather than an enforcement boundary. Future remote targets are expected to be reachable only through framework-defined collector, analysis, sanitization, and approved drill-down interfaces.

## Enforced controls

- One no-argument sudo command, executed only as `root:root`
- Root ownership and non-writable installed collector/sudoers paths
- Absolute child executable paths and a fixed environment
- Closed stdin, per-command timeout, isolated process group, and bounded stdout/stderr capture
- Child CPU-time, open-file, output-file, and core-dump resource limits
- Bounded item counts and truncated error text in JSON
- Candidate validation followed by atomic activation
- Positive inventory and negative arbitrary-command deployment checks
- A deterministic external-safe sanitizer that rejects altered or unknown rule content

## Known limitations

- Root executes Python and several OS utilities, so vulnerabilities in those trusted components remain in scope.
- Inventory exposes account, network, package, service, filesystem, and possibly container metadata.
- Resource limits reduce common denial-of-service paths but are not a complete memory, process-count, syscall, or filesystem sandbox. In particular, process-count limits are not relied upon for UID 0.
- Local sudo logging is not tamper-resistant against a compromised root host.
- SSH restrictions, sudo policy, and collector behavior have not yet been validated across a supported distribution matrix.
- External-safe sanitization does not prevent bypass while Hermes retains another route to raw host data.
- The framework does not yet implement drill-down authorization, report signing, remediation, or human approval workflows.

## Change rule

Do not add a generic interpreter, shell, pager, editor, file reader, recursive search tool, package manager, container command, or user-controlled argument to sudoers. New evidence requirements should normally become fixed collector code with explicit bounds, schema changes, tests, and threat analysis.
