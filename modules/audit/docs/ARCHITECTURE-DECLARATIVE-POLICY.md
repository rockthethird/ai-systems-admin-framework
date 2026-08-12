# Declarative Audit Policy Architecture

Status: Accepted for incremental implementation

## Decision

The audit module will describe privileged collection, deterministic controls,
report disclosure, and identity capabilities in small YAML policy files. A
strict controller-side validator will compile those files into one checked-in
JSON manifest. Target runtimes will consume only that validated manifest.

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

- `policy/collectors.yaml` defines fixed collectors, absolute command
  candidates, literal arguments, limits, and named parsers.
- `policy/rules.yaml` defines stable controls, public finding text, evidence
  dependencies, and named evaluators.
- `policy/profiles.yaml` defines allowed disclosures and named safe evidence
  formatters.
- `policy/identities.yaml` binds operating-system identities to exactly one
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

Deployment rejects missing, stale, modified, or unapproved artifacts. The
local artifact index retains policy provenance; the installed runtime manifest
contains only operational policy consumed by report code.

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
or forbidden external disclosure. Runtime loading fails for an unsupported
manifest version or digest mismatch. A failed or unknown dependency cannot be
reported as a passed control.

## Migration strategy

1. Add policy schemas, representative policy, compilation, and guard tests
   without changing deployed output.
2. Move duplicated rule metadata into policy and make analyzer and sanitizers
   consume the generated manifest.
3. Replace the two sanitizers with one profile-driven engine and named evidence
   formatters.
4. Move fixed collector commands and limits into policy while retaining hard
   resource ceilings in code.
5. Generate sudoers and documentation views from the same identity policy.
6. Remove compatibility definitions only after fixture-corpus equivalence and
   live authorization tests pass.

Each migration step is independently reviewable and preserves the fixed,
no-argument public endpoints, root-only helpers, identity-bound profiles,
local analysis, deterministic findings, and negative authorization tests.

## Consequences

The project accepts a build step and checked-in generated artifact in exchange
for a smaller trusted runtime and one authoritative definition of security
behavior. Generated files are not edited by hand. Policy diffs become the main
review surface; primitive changes continue to receive conventional code review
and focused tests.
