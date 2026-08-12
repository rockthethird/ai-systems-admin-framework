# Build audit artifacts

The reviewed sources of audit behavior are the focused files under
`modules/audit/policy/`. Generated files are committed for review but must not
be edited by hand.

## Compile policy

```bash
python3 modules/audit/build/compile-policy.py
python3 modules/audit/build/compile-policy.py --check
```

Compilation validates strict schemas, cross-file references, named primitives,
absolute paths, identity/profile bindings, and mandatory external-safe
exclusions. It writes `modules/audit/generated/policy-manifest.json`.

Target reporting helpers read the compiled JSON manifest. PyYAML and
`jsonschema` are build/test dependencies, not privileged runtime dependencies.

## Generate sudoers — transitional

```bash
bash modules/audit/build/10-generate-sudoers-from-yaml.sh
bash modules/audit/tests/test-sudoers-generation.sh
```

The sudoers generator still reads
`modules/audit/configure/enabled-commands.yaml`. That file is a compatibility
input containing only the two fixed, no-argument report endpoints. Do not add
host commands or new capabilities there.

This compatibility path will be removed when sudoers generation consumes the
validated identity policy. Until then, changes to report identities or endpoint
paths must update both sources and pass the equality tests.

Review `modules/audit/build/sudoers-ai-auditor-generated`, validate it with
`visudo`, and deploy it using `modules/audit/deploy/30-configure-sudoers.sh`.
