# Fixes Applied: 2026-08-07

**Date:** August 7, 2026  
**Audit:** Post-Phase 2 cleanup  
**Total Fixes:** 1  
**Time to Fix:** 5 minutes  

---

## Fix 1: SECURITY.md Email Placeholder → Template Reference

**File:** `SECURITY.md`  
**Lines Changed:** 2 instances  
**Severity:** DOCUMENTATION  

### Rationale

The security contact must be a real email address or clearly marked as a template placeholder that deployers will customize. `security@example.com` is ambiguous—it looks like a real contact but isn't. Replacing with `security@[your-domain]` is self-documenting: deployers immediately see they need to customize it.

### Implementation

**Change 1: Reporting Instructions (line 5)**
```diff
- Instead, please report security issues by emailing [security@example.com](mailto:security@example.com) with:
+ Instead, please report security issues by emailing security@[your-domain] with:
```

**Change 2: Contact Section (line 26)**
```diff
- Security team: [security@example.com](mailto:security@example.com)
+ Security team: security@[your-domain]
+
+ **Note:** Replace `[your-domain]` with your organization's domain before deploying.
```

### Verification

✅ Email placeholder removed  
✅ Template syntax clear to deployers  
✅ Instructions added for customization  
✅ No security risk introduced  

### Documentation Impact

- Deployers now know they must customize the email
- Self-documenting: bracket notation signals template variable
- Responsible disclosure process still clearly explained

---

## No Code Changes to Sudoers Template

**Audit Finding:** Sudoers template paths already comply with FHS 3.0 (all `/usr/bin/`)  
**Status:** ✅ VERIFIED—No changes needed  

Earlier audit (2026-08-06) flagged this as cleanup opportunity. Current code already implements best practice:
- Phase 1 template: Single command path `/usr/bin/uname -a`
- Phase 2+ YAML config: All paths use `/usr/bin/` exclusively
- No duplicate `/bin/` variants present

---

## Commit Summary

**Message:** `audit: 2026-08-07 - Fix SECURITY.md email, verify sudoers paths`

**Changes:**
- Modified: `SECURITY.md` (2 lines)
- Created: `modules/audit/audits/2026-08-07/` (5 files)
- Updated: `modules/audit/audits/AUDIT-LOG.md` (1 entry)

**Impact:** Framework deployment-ready (subject to domain customization)
