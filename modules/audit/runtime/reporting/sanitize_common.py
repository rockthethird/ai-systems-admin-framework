"""Shared fail-closed validation for deterministic findings sanitizers."""

from __future__ import annotations

from typing import Any, Callable

from audit_policy import PUBLIC_FIELDS, RULES

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("passed", "failed", "unknown")
FindingEvidence = Callable[[str, list[dict[str, Any]]], Any]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sanitize_assessment(report: dict[str, Any], failed_ids: set[str]) -> dict[str, Any]:
    assessment = report.get("assessment")
    require(isinstance(assessment, dict), "assessment must be an object")
    results = assessment.get("results")
    require(isinstance(results, list) and len(results) == len(RULES),
            "assessment must cover every supported rule")
    safe_results = []
    seen = set()
    counts = {status: 0 for status in STATUSES}
    for result in results:
        require(isinstance(result, dict), "assessment result must be an object")
        identifier = result.get("id")
        require(identifier in RULES and identifier not in seen,
                f"unsupported or duplicate assessment rule: {identifier}")
        seen.add(identifier)
        status = result.get("status")
        require(status in counts, f"assessment rule {identifier} has invalid status")
        require((status == "failed") == (identifier in failed_ids),
                f"assessment rule {identifier} disagrees with findings")
        rule = RULES[identifier]
        require(result.get("control") == rule["control"] and result.get("section") == rule["section"],
                f"assessment rule {identifier} has unexpected metadata")
        counts[status] += 1
        safe_results.append({"id": identifier, "control": rule["control"],
                             "section": rule["section"], "status": status})
    require(seen == set(RULES), "assessment omits supported rules")
    require(assessment.get("rules_evaluated") == len(results) and
            all(assessment.get(status) == count for status, count in counts.items()),
            "assessment counts do not match results")
    return {"rules_evaluated": len(results), **counts, "results": safe_results}


def sanitize_findings(report: dict[str, Any], transform_evidence: FindingEvidence
                      ) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, Any], bool]:
    findings = report.get("findings")
    require(isinstance(findings, list), "findings must be an array")
    safe_findings = []
    counts = {severity: 0 for severity in SEVERITIES}
    seen = set()
    for item in findings:
        require(isinstance(item, dict), "finding must be an object")
        identifier = item.get("id")
        require(identifier in RULES and identifier not in seen,
                f"unsupported or duplicate finding id: {identifier}")
        seen.add(identifier)
        rule = RULES[identifier]
        for field in PUBLIC_FIELDS:
            require(item.get(field) == rule[field], f"finding {identifier} has unexpected {field}")
        status = item.get("status")
        confidence = item.get("confidence")
        evidence = item.get("evidence")
        require(status in {"open", "accepted", "resolved", "not_applicable"},
                f"finding {identifier} has invalid status")
        require(isinstance(confidence, (int, float)) and not isinstance(confidence, bool)
                and 0 <= confidence <= 1, f"finding {identifier} has invalid confidence")
        require(confidence == rule["confidence"],
                f"finding {identifier} has unexpected confidence")
        require(isinstance(evidence, list) and evidence, f"finding {identifier} has no evidence")
        public = {field: rule[field] for field in PUBLIC_FIELDS}
        safe_findings.append({"id": identifier, **public, "status": status,
                              "confidence": rule["confidence"],
                              "evidence": transform_evidence(identifier, evidence)})
        counts[rule["severity"]] += 1
    summary = {"total": len(safe_findings), **counts}
    require(report.get("summary") == summary, "findings summary does not match findings")
    return safe_findings, summary, sanitize_assessment(report, seen), "AIA-1004" in seen
