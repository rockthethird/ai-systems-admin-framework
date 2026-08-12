# Local deployment artifacts

Run the policy builder from the repository root:

```bash
python3 modules/audit/deploy/scripts/policy.py build
```

The generated files in this directory are local, reproducible build outputs.
Only this README and the localized `.gitignore` belong in version control.
Use `policy.py review` to inspect their exact bytes and create local approval;
use `policy.py verify` to reconstruct the bundle and confirm that approval.
