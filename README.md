# AI Systems Administrator Framework

Security-first building blocks for giving AI systems narrow, reviewable
infrastructure capabilities.

Status: alpha. The audit module is implemented and tested on a disposable
development VM. It is not production-ready. Compliance, remediation,
maintenance, and incident-response modules remain future work.

## Current audit capability

The audit module:

- collects bounded Linux host inventory through root-only fixed helpers,
- evaluates nine deterministic controls locally,
- reports every control as passed, failed, or unknown,
- exposes separate external-safe and internal-rich JSON profiles,
- binds each profile to a distinct locked operating-system identity,
- permits only a fixed no-argument report endpoint through sudo,
- denies report identities access to the raw collector.

SSH credentials and forced-command bindings are intentionally not implemented
yet. The framework does not perform remediation or grant an AI general shell
authority.

## Human review surface

Current audit behavior is primarily defined by four constrained files:

- [`collectors.yaml`](modules/audit/deploy/policy/collectors.yaml)
- [`rules.yaml`](modules/audit/deploy/policy/rules.yaml)
- [`profiles.yaml`](modules/audit/deploy/policy/profiles.yaml)
- [`identities.yaml`](modules/audit/deploy/policy/identities.yaml)

Strict schemas and cross-reference checks compile these into deterministic,
local deployment artifacts. Privileged enforcement remains in a small set of
named, tested runtime primitives. See the
[`declarative-policy architecture decision`](modules/audit/docs/ARCHITECTURE-DECLARATIVE-POLICY.md).

## Validate

```bash
python3 modules/audit/deploy/scripts/policy.py build

for test in modules/audit/tests/test-*.sh; do
    bash "$test"
done
```

Live authorization and deployment checks are documented in
[`modules/audit/deploy/README.md`](modules/audit/deploy/README.md).

## Documentation

- [`Getting started`](docs/GETTING-STARTED.md)
- [`Audit module`](modules/audit/README.md)
- [`Threat model`](modules/audit/docs/THREAT-MODEL.md)
- [`Contributing`](CONTRIBUTING.md)
- [`Security policy`](SECURITY.md)

## License

MIT License. See [`LICENSE`](LICENSE).
