# Verification roadmap

This file lists unimplemented verification work for the current fixed-report,
identity-bound architecture. It does not claim that proposed checks exist.

## Current automated coverage

- Strict policy schemas, cross-references, and generated-manifest freshness
- Collector argument rejection, command bounds, timeouts, and resource ceilings
- Deterministic finding and report schema validation
- External-safe disclosure and prompt-injection resistance
- Internal-rich constrained evidence formatting
- Exact no-argument sudo rules and raw-collector denial
- Live cross-profile denial and semantic deployment equivalence on the
  disposable development VM

## Required before SSH binding

- Specify distinct credential ownership and lifecycle for cloud and local use.
- Generate forced-command configuration from validated identity policy.
- Validate candidate SSH configuration with `sshd -t` before activation.
- Test key-only authentication and rejection of password and
  keyboard-interactive authentication.
- Test denial of PTY, agent forwarding, port forwarding, X11 forwarding,
  subsystems, arbitrary commands, and cross-profile requests.
- Test key revocation and recovery without weakening sudo policy.

## Required before production claims

- Run the complete suite on every supported distribution and SSH/sudo version.
- Trace the deployed collector's fixed child commands on real systemd and
  optional Docker paths.
- Test environment injection, symlink substitution, race conditions, malformed
  evidence, output exhaustion, timeouts, and interrupted deployment.
- Verify endpoint, manifest, sudoers, SSH configuration, and credential
  ownership and modes continuously.
- Export allowed and denied authentication and sudo events to centralized,
  tamper-resistant storage with retention and alerting.
- Exercise credential rotation, revocation, host recovery, and rollback.

## Future authorization work

Any drill-down or remediation interface requires a separate threat analysis,
explicit policy primitive, human-approval model, denial tests, and audit trail.
It must not expand the fixed report identities implicitly.
