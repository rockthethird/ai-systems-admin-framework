# AI Auditor Threat Model

## Protected assets

- Host integrity and availability
- Root-readable system and infrastructure metadata
- SSH credentials and the `ai-auditor` identity
- Sudo policy and audit records
- Docker daemon metadata, when available
- Raw inventory and evidence-rich local findings

## Trust boundaries

The AI and its prompt/input are untrusted. The fixed collector, analyzer, sanitizer, their root-owned installation paths, the generated sudoers rule, Python runtime, operating system tools, and target administrator are trusted. Collector JSON is sensitive evidence and remains untrusted input when consumed by later analysis.

Docker is a separate boundary. Membership in the Docker socket group or unrestricted daemon access is commonly root-equivalent. The collector invokes only a fixed `docker ps` query, but enabling daemon visibility increases disclosure and dependency risk and must be an explicit host decision.

Externally hosted model inference is another boundary. Raw inventory and local findings do not cross it by default. The `external-safe/v1` sanitizer emits a minimized, fail-closed view containing only known deterministic rule text, summary data, hashes, and evidence counts/categories. Host identifiers, timestamps, evidence paths, and observations remain local.

The `internal-rich/v1` profile is intended for a locally hosted model. It includes exact host identity and constrained finding-relevant details, all explicitly labeled as untrusted host evidence. It still excludes raw inventory, arbitrary evidence strings, logs, configuration contents, and unrelated inventory. Separate locked identities bind cloud and local consumers to their respective fixed endpoints; SSH credential binding remains intentionally undecided.

The current Hermes-on-audited-host arrangement is a temporary test topology. Its host Docker access and unprivileged shell visibility can bypass portions of the sanitizer, so external-safe output is not a complete confidentiality boundary in that environment. Future remote targets are expected to be reachable only through the sanitized report endpoint and later approved drill-down interfaces.

## Enforced controls

- One no-argument sanitized report command, executed only as `root:root`
- Root-only (`0700`) raw collector, analyzer, and sanitizer helpers absent from sudoers
- Root ownership and non-writable installed collector/sudoers paths
- Absolute child executable paths and a fixed environment
- Closed stdin, per-command timeout, isolated process group, and bounded stdout/stderr capture
- Child CPU-time, open-file, output-file, and core-dump resource limits
- Bounded item counts and truncated error text in JSON
- Candidate validation followed by atomic activation
- Positive inventory and negative arbitrary-command deployment checks
- A deterministic external-safe sanitizer that rejects altered or unknown rule content
- Root-only temporary raw inventory and findings removed on endpoint exit

## Known limitations

- Root executes Python and several OS utilities, so vulnerabilities in those trusted components remain in scope.
- Inventory exposes account, network, package, service, filesystem, and possibly container metadata.
- Resource limits reduce common denial-of-service paths but are not a complete memory, process-count, syscall, or filesystem sandbox. In particular, process-count limits are not relied upon for UID 0.
- Local sudo logging is not tamper-resistant against a compromised root host.
- SSH restrictions, sudo policy, and collector behavior have not yet been validated across a supported distribution matrix.
- External-safe sanitization does not prevent bypass while Hermes retains another route to raw host data.
- The framework does not yet implement drill-down authorization, report signing, remediation, or human approval workflows.

## Change rule

Do not add the raw collector, a generic interpreter, shell, pager, editor, file reader, recursive search tool, package manager, container command, or user-controlled argument to sudoers. New evidence requirements should normally become fixed collector or analyzer code with explicit bounds, schema changes, tests, sanitization policy, and threat analysis.
