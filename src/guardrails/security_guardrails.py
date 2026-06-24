import re
from typing import Any, Dict, List
import json

SECRET_PATTERNS = {
    "aws_access_key_id": re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    "aws_secret_access_key": re.compile(
        r"(?i)(aws_secret_access_key|secret_access_key|aws secret key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{30,})['\"]?"
    ),
    "api_key": re.compile(
        r"(?i)(api_key|apikey|api key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"
    ),
    "password": re.compile(
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{6,})['\"]?"
    ),
    "authorization_header": re.compile(
        r"(?i)(authorization:\s*bearer\s+)([A-Za-z0-9._\-]+)"
    ),
    "private_key": re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

DESTRUCTIVE_ACTION_PATTERNS = [
    r"\bdelete\s+the\s+user\b",
    r"\bdelete\s+user\b",
    r"\bdelete\s+the\s+access\s+key\b",
    r"\bdelete\s+access\s+key\b",
    r"\bterminate\s+the\s+ec2\s+instance\b",
    r"\bterminate\s+instance\b",
    r"\bdelete\s+all\s+logs\b",
    r"\bdelete\s+cloudtrail\b",
    r"\bremove\s+the\s+security\s+group\b",
    r"\bdestroy\s+the\s+resource\b",
]

CONTAINMENT_ACTION_PATTERNS = [
    r"\bdisable(?:s|d|ing)?\b",
    r"\bdelete(?:s|d|ing)?\b",
    r"\bterminate(?:s|d|ing)?\b",
    r"\brevoke(?:s|d|ing)?\b",
    r"\brotate(?:s|d|ing)?\b",
    r"\bremove(?:s|d|ing)?\b",
    r"\bisolate(?:s|d|ing)?\b",
    r"\brestrict(?:s|d|ing)?\b",
    r"\bblock(?:s|d|ing)?\b",
]

APPROVAL_LANGUAGE_PATTERNS = [
    r"\bwith approval\b",
    r"\bafter approval\b",
    r"\bwith authorization\b",
    r"\bafter authorization\b",
    r"\bafter analyst confirmation\b",
    r"\bafter incident response approval\b",
    r"\bwith human approval\b",
    r"\brequire human approval\b",
    r"\bshould require human approval\b",
]

UNSUPPORTED_CERTAINTY_PATTERNS = [
    r"\bdefinitely compromised\b",
    r"\bconfirmed compromised\b",
    r"\bthis is malicious\b",
    r"\bthe attacker\b",
    r"\bwas hacked\b",
    r"\bwas breached\b",
    r"\bis compromised\b",
]

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FINDING_ID_PATTERN = re.compile(r"\bgd-seeded-\d+\b")
SERVICE_ACCOUNT_PATTERN = re.compile(r"\bsvc-[a-z0-9-]+\b", re.IGNORECASE)
DOTTED_HANDLE_PATTERN = re.compile(r"\b[a-z]{2,}\.[a-z]{2,}\b", re.IGNORECASE)


def detect_secret_patterns(text: str) -> List[str]:
    findings = []

    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            findings.append(name)

    return findings


def mask_secrets(text: str) -> str:
    masked = text

    masked = SECRET_PATTERNS["aws_access_key_id"].sub(
        lambda match: match.group(0)[:4] + "*" * 16,
        masked,
    )

    masked = SECRET_PATTERNS["aws_secret_access_key"].sub(
        lambda match: f"{match.group(1)}=***",
        masked,
    )

    masked = SECRET_PATTERNS["api_key"].sub(
        lambda match: f"{match.group(1)}=***",
        masked,
    )

    masked = SECRET_PATTERNS["password"].sub(
        lambda match: f"{match.group(1)}=***",
        masked,
    )

    masked = SECRET_PATTERNS["authorization_header"].sub(
        lambda match: match.group(1) + "***MASKED***",
        masked,
    )

    masked = SECRET_PATTERNS["private_key"].sub(
        "-----BEGIN PRIVATE KEY-----***MASKED***",
        masked,
    )

    return masked


def detect_destructive_actions(text: str) -> List[str]:
    matches = []

    for pattern in DESTRUCTIVE_ACTION_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            matches.append(pattern)

    return matches


def contains_containment_action(text: str) -> bool:
    for pattern in CONTAINMENT_ACTION_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True

    return False


def contains_approval_language(text: str) -> bool:
    for pattern in APPROVAL_LANGUAGE_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True

    return False


def require_human_approval(text: str) -> Dict[str, Any]:
    has_containment_action = contains_containment_action(text)
    has_approval_language = contains_approval_language(text)

    passed = not has_containment_action or has_approval_language

    return {
        "passed": passed,
        "has_containment_action": has_containment_action,
        "has_approval_language": has_approval_language,
        "message": (
            "Containment actions include approval language."
            if passed
            else "Containment actions were found without clear approval language."
        ),
    }


def check_runbook_sources(context: Dict[str, Any]) -> Dict[str, Any]:
    runbook_context = context.get("runbook_context", [])

    passed = len(runbook_context) > 0

    return {
        "passed": passed,
        "source_count": len(runbook_context),
        "message": (
            "Runbook context is available."
            if passed
            else "No runbook context was found."
        ),
    }


def check_unsupported_conclusions(
    report: str, context: Dict[str, Any]
) -> Dict[str, Any]:
    matches = []

    for pattern in UNSUPPORTED_CERTAINTY_PATTERNS:
        if re.search(pattern, report, flags=re.IGNORECASE):
            matches.append(pattern)

    passed = len(matches) == 0

    return {
        "passed": passed,
        "matches": matches,
        "message": (
            "No unsupported certainty language found."
            if passed
            else "Potentially unsupported certainy language found."
        ),
    }

def extract_report_entities(report: str) -> Dict[str, List[str]]:
    ips = sorted(set(IP_PATTERN.findall(report)))
    finding_ids = sorted(set(FINDING_ID_PATTERN.findall(report)))
    user_names = sorted(
        set(SERVICE_ACCOUNT_PATTERN.findall(report))
        | set(DOTTED_HANDLE_PATTERN.findall(report))
    )
    return {"ips": ips, "finding_ids": finding_ids, "user_names": user_names}

def entity_coverage(report: str, context: Dict[str, Any]) -> Dict[str, Any]:
    entities = extract_report_entities(report)
    serialized = json.dumps(context, sort_keys=True, default=str).lower()

    mentioned: List[str] = []
    in_context: List[str] = []
    missing: List[str] = []

    for values in entities.values():
        for value in values:
            mentioned.append(value)
            if value.lower() in serialized:
                in_context.append(value)
            else:
                missing.append(value)

    total = len(mentioned)
    coverage_ratio = len(in_context) / total if total else 1.0

    return {
        "entities": entities,
        "mentioned": mentioned,
        "in_context": in_context,
        "missing": missing,
        "coverage_ratio": coverage_ratio,
    }

def groundedness_score(report: str, context: Dict[str, Any]) -> float:
    return entity_coverage(report, context)["coverage_ratio"]

def check_citation_coverage(report: str, context: Dict[str, Any]) -> Dict[str, Any]:
    coverage = entity_coverage(report, context)
    passed = len(coverage["missing"]) == 0

    return {
        "passed": passed,
        "missing_entities": coverage["missing"],
        "coverage_ratio": coverage["coverage_ratio"],
        "message": (
            "All cited entities appear in the evidence context."
            if passed
            else f"Entities not found in evidence (possible fabrication): {coverage['missing']}"
        ),
    }

def apply_guardrails(report: str, context: Dict[str, Any]) -> Dict[str, Any]:
    original_secret_findings = detect_secret_patterns(report)
    masked_report = mask_secrets(report)
    post_mask_secret_findings = detect_secret_patterns(masked_report)

    destructive_matches = detect_destructive_actions(masked_report)
    approval_check = require_human_approval(masked_report)
    runbook_check = check_runbook_sources(context)
    unsupported_check = check_unsupported_conclusions(masked_report, context)
    citation_check = check_citation_coverage(masked_report, context)

    checks = {
        "secret_leakage": {
            "passed": len(post_mask_secret_findings) == 0,
            "original_findings": original_secret_findings,
            "remaining_findings": post_mask_secret_findings,
            "message": (
                "No unmasked secrets detected."
                if len(post_mask_secret_findings) == 0
                else "Potential unmasked secrets remain."
            ),
        },
        "destructive_action_language": {
            "passed": len(destructive_matches) == 0,
            "matches": destructive_matches,
            "message": (
                "No unsafe destructive action language detected."
                if len(destructive_matches) == 0
                else "Unsafe destructive action language detected."
            ),
        },
        "human_approval": approval_check,
        "runbook_sources": runbook_check,
        "unsupported_conclusions": unsupported_check,
        "citation_coverage": citation_check,
    }

    passed = all(check["passed"] for check in checks.values())

    return {
        "passed": passed,
        "status": "PASS" if passed else "REVIEW_REQUIRED",
        "masked_report": masked_report,
        "checks": checks,
    }


def format_guardrail_result(result: Dict[str, Any]) -> str:
    lines = []

    lines.append("\n## Guardrail Check")
    lines.append(f"Status: {result['status']}")

    for check_name, check in result["checks"].items():
        status = "PASS" if check["passed"] else "REVIEW_REQUIRED"
        lines.append(f"- {check_name}: {status} - {check['message']}")

    return "\n".join(lines)
