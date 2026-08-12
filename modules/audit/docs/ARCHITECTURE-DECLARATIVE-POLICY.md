# Declarative Audit Policy Architecture

Status: Implemented

## Decision

The audit module describes privileged collection, deterministic controls,
report disclosure, and identity capabilities in small YAML policy files. A
strict controller-side tool compiles them into an exact local deployment
bundle containing the runtime manifest, sudoers policy, and artifact index.
Target runtimes consume only the validated runtime manifest.

Python remains responsible for security enforcement and a deliberately small
set of named primitives. YAML selects primitives and supplies bounded data; it
must not contain shell fragments, templates, regular expressions, Python, or a
general expression language.

## Human-review objective

A reviewer must be able to answer these questions primarily from policy:

1. Which commands and filesystem objects can privileged collection observe?
2. Which deterministic conditions are evaluated?
3. Which fields and evidence forms can each report profile disclose?
4. Which operating-system identity receives each profile?
5. Which named Python primitive implements behavior that policy cannot express?

Adding a normal rule must not require copying its title, severity, rationale,
impact, recommendation, or disclosure classification into Python.

## Policy sources

- `deploy/policy/collectors.yaml` defines fixed collectors, absolute command
  candidates, literal arguments, limits, and named parsers.
- `deploy/policy/rules.yaml` defines stable controls, public finding text, evidence
  dependencies, and named evaluators.
- `deploy/policy/profiles.yaml` defines allowed disclosures and named safe evidence
  formatters.
- `deploy/policy/identities.yaml` binds operating-system identities to exactly one
  report profile and no-argument endpoint.

Each file has a strict JSON Schema with `additionalProperties: false`.
Cross-file constraints that JSON Schema cannot express are enforced by the
compiler.

## Compilation and deployment

The compiler validates YAML, resolves references, enforces security invariants,
and writes the runtime manifest, sudoers policy, and canonical artifact index
under `deploy/artifacts/` deterministically. These local build outputs are not
committed. Human review displays their exact bytes and binds approval to the
complete bundle digest, including installation metadata.

Deployment rejects missing, stale, modified, or unmatched artifacts. The
local artifact index retains policy provenance; the installed runtime manifest
contains only operational policy consumed by report code.

`policy.py review` requires an interactive terminal, displays the exact bytes
and installation metadata, and records human approval only after the complete
bundle digest is entered. `policy.py verify` independently reconstructs the
expected bundle and requires the human approval record to match. The
privileged deployment command repeats that verification before installation.

Target report code uses the Python standard library to read JSON. PyYAML and
JSON Schema are build/test dependencies, not additions to the privileged target
runtime.

## Trusted runtime boundary

The runtime may implement only named, independently tested primitives such as:

- bounded fixed-command execution,
- account and filesystem metadata collection,
- equality, threshold, membership, and item-count evaluation,
- deterministic evidence construction,
- profile-specific safe evidence formatting,
- schema and manifest integrity validation.

A specialized control may use a named function when these primitives are not
clear enough. Its policy entry must name that function explicitly so reviewers
can follow the boundary from data to code.

## Prohibited policy features

- Caller-controlled executable paths or arguments
- Relative executable paths
- Shell evaluation or command strings
- Inline regular expressions
- Templates or interpolation
- Dynamic imports or function names outside fixed registries
- Arbitrary expressions or embedded programming languages
- Profile-selected privilege escalation
- Raw evidence disclosure to an external profile

## Fail-closed requirements

Compilation fails for unknown fields or primitives, duplicate IDs, unresolved
references, invalid limits, non-absolute commands, identity/profile mismatch,
or forbidden external disclosure. Deployment fails for artifact or approval
digest mismatch. Runtime loading fails for an unsupported or malformed
manifest. A failed or unknown dependency cannot be reported as a passed
control.

## Implemented workflow

1. `policy.py build` validates policy, renders both deployable artifacts,
   validates sudoers with `visudo`, and publishes the canonical index last.
2. `policy.py review` rebuilds, displays, and binds human approval to the exact
   bundle bytes and installation metadata.
3. `policy.py verify` reconstructs expected content and requires matching
   artifacts, metadata, and human approval.
4. `deploy.sh --check` runs the complete read-only source, policy, runtime, and
   target preflight.
5. `deploy.sh` repeats preflight and approval verification before atomic
   per-stage installation.

The workflow preserves fixed no-argument public endpoints, root-only helpers,
identity-bound profiles, local analysis, deterministic findings, and negative
authorization tests.

## Consequences

The project accepts an explicit build and human-approval step in exchange for a
smaller trusted runtime and one authoritative definition of security behavior.
Generated artifacts are local, reproducible, ignored by Git, and never edited
by hand. Policy diffs remain the main behavioral review surface; primitive and
deployment-tool changes continue to receive conventional code review and
focused tests.
