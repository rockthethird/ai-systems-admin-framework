# Contributing

Contributions must preserve least privilege, deterministic behavior, a small
trusted runtime, and a reviewable authorization boundary.

Report security vulnerabilities through [`SECURITY.md`](SECURITY.md), not a
public issue.

## Design rules

- Policy is the normal extension surface for collectors, controls, disclosure
  profiles, and identity bindings.
- YAML may select only registered primitives and bounded literal data. Do not
  add shell fragments, templates, inline regular expressions, Python, dynamic
  functions, or an expression language.
- Executable paths are absolute and arguments are fixed by reviewed policy.
- Caller input must not select commands, privileged arguments, or report
  sensitivity.
- External profiles fail closed and never expose raw inventory or arbitrary
  host-controlled text.
- A recommendation is report content, not execution authority.
- Generated artifacts are committed and never edited by hand.

Read the audit module's
[`architecture decision`](modules/audit/docs/ARCHITECTURE-DECLARATIVE-POLICY.md)
and [`threat model`](modules/audit/docs/THREAT-MODEL.md) before changing behavior.

## Adding a control

Prefer an existing named evaluator. Add the control once to
`modules/audit/deploy/policy/rules.yaml`, update fixtures, compile the manifest, and
confirm both disclosure profiles. If a new primitive is unavoidable, keep it
small, name it explicitly in schema, and test success, failure, unknown, and
malformed-input behavior.

Do not copy public rule title, rationale, impact, or recommendation into Python.
The review-surface test enforces this rule.

## Adding collection

Define fixed command candidates or a named built-in in
`modules/audit/deploy/policy/collectors.yaml`. Collection must retain hard ceilings for
time, CPU, file descriptors, bytes, and items. Review the information disclosed
by the new evidence and update both report-profile tests.

Never add the raw collector, shell, interpreter, pager, editor, generic file
reader, recursive search utility, package manager, container command, or
caller-controlled argument to sudoers.

## Required validation

From the repository root:

```bash
python3 modules/audit/deploy/scripts/policy.py build
python3 modules/audit/deploy/scripts/policy.py verify

for test in modules/audit/tests/test-*.sh; do
    bash "$test"
done

git diff --check
```

Behavioral changes also require live positive and negative authorization tests
on a disposable target. Compare sanitized JSON semantics before and after a
refactor; ignore only intentionally variable timestamps and content hashes.

## Change organization

Keep commits atomic and use Conventional Commit subjects. Commit messages
should explain the security boundary changed, tests performed, and concrete
result. Preserve unrelated worktree changes and do not commit local deployment
backups or generated Python caches.

Update current documentation in the same change. Git history is the archive;
do not retain superseded procedures inside active module directories.
