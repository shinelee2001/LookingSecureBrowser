from dataclasses import dataclass, field


@dataclass
class MitreAttackMapping:
    tactic: str
    technique_id: str
    technique_name: str
    confidence: str
    signal: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""


TECHNIQUE_URLS = {
    "T1189": "https://attack.mitre.org/techniques/T1189/",
    "T1190": "https://attack.mitre.org/techniques/T1190/",
    "T1566": "https://attack.mitre.org/techniques/T1566/",
    "T1566.002": "https://attack.mitre.org/techniques/T1566/002/",
    "T1059.007": "https://attack.mitre.org/techniques/T1059/007/",
    "T1557": "https://attack.mitre.org/techniques/T1557/",
}


def add_mapping(
    mappings: dict[str, MitreAttackMapping],
    *,
    tactic: str,
    technique_id: str,
    technique_name: str,
    confidence: str,
    signal: str,
    evidence: str,
    recommendation: str,
):
    if technique_id not in mappings:
        mappings[technique_id] = MitreAttackMapping(
            tactic=tactic,
            technique_id=technique_id,
            technique_name=technique_name,
            confidence=confidence,
            signal=signal,
            recommendation=recommendation,
        )

    if evidence and evidence not in mappings[technique_id].evidence:
        mappings[technique_id].evidence.append(evidence)

    mappings[technique_id].confidence = higher_confidence(
        mappings[technique_id].confidence,
        confidence,
    )


def higher_confidence(left: str, right: str) -> str:
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    return left if rank.get(left, 0) >= rank.get(right, 0) else right


def map_header_findings(findings: list) -> list[MitreAttackMapping]:
    mappings: dict[str, MitreAttackMapping] = {}

    for finding in findings:
        name = getattr(finding, "name", "")
        status = getattr(finding, "status", "")
        message = getattr(finding, "message", "")
        evidence = getattr(finding, "evidence", "") or message

        if status == "OK":
            continue

        if name in {"HSTS", "Redirect Chain"}:
            add_mapping(
                mappings,
                tactic="Credential Access / Collection",
                technique_id="T1557",
                technique_name="Adversary-in-the-Middle",
                confidence="MEDIUM" if name == "Redirect Chain" else "LOW",
                signal=f"{name} transport weakness",
                evidence=f"{name}: {evidence}",
                recommendation="Enforce HTTPS, HSTS, and clean redirect chains to reduce downgrade and interception opportunities.",
            )

        if name == "CSP":
            add_mapping(
                mappings,
                tactic="Initial Access",
                technique_id="T1189",
                technique_name="Drive-by Compromise",
                confidence="LOW",
                signal="Weak browser-side execution controls",
                evidence=f"CSP: {evidence}",
                recommendation="Use a restrictive CSP to reduce injected script execution and drive-by payload impact.",
            )
            if "unsafe-inline" in evidence.lower() or "unsafe-eval" in evidence.lower():
                add_mapping(
                    mappings,
                    tactic="Execution",
                    technique_id="T1059.007",
                    technique_name="Command and Scripting Interpreter: JavaScript",
                    confidence="LOW",
                    signal="Inline or eval-style JavaScript allowed",
                    evidence=f"CSP: {evidence}",
                    recommendation="Remove unsafe-inline and unsafe-eval where possible; use nonces, hashes, and trusted script origins.",
                )

        if name == "CORS" and status in {"WARN", "BAD"}:
            add_mapping(
                mappings,
                tactic="Initial Access",
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                confidence="LOW",
                signal="Overly broad cross-origin access",
                evidence=f"CORS: {evidence}",
                recommendation="Scope CORS to trusted origins and avoid credentialed wildcard-style access.",
            )

        if name == "Cookie Security" and status in {"WARN", "BAD"}:
            add_mapping(
                mappings,
                tactic="Credential Access / Collection",
                technique_id="T1557",
                technique_name="Adversary-in-the-Middle",
                confidence="LOW",
                signal="Cookie attributes allow exposure or script access",
                evidence=f"Cookie Security: {evidence}",
                recommendation="Set Secure, HttpOnly, and SameSite on sensitive cookies.",
            )

    return sorted_mappings(mappings)


def map_network_events(events: list[dict]) -> list[MitreAttackMapping]:
    mappings: dict[str, MitreAttackMapping] = {}

    for event in events:
        reason = event.get("reason", "")
        action = event.get("action", "")
        url = event.get("url", "")

        if reason == "Mixed HTTP subresource":
            add_mapping(
                mappings,
                tactic="Credential Access / Collection",
                technique_id="T1557",
                technique_name="Adversary-in-the-Middle",
                confidence="MEDIUM" if action == "BLOCKED" else "LOW",
                signal="Mixed-content request",
                evidence=url,
                recommendation="Serve all subresources over HTTPS and block HTTP downgrade paths.",
            )

        if reason == "Tracker/ad host":
            add_mapping(
                mappings,
                tactic="Initial Access",
                technique_id="T1189",
                technique_name="Drive-by Compromise",
                confidence="LOW",
                signal="Third-party tracker or ad infrastructure request",
                evidence=url,
                recommendation="Review third-party scripts and ad tags; restrict script origins with CSP.",
            )

    return sorted_mappings(mappings)


def map_link_scan_results(results: list[dict]) -> list[MitreAttackMapping]:
    mappings: dict[str, MitreAttackMapping] = {}

    for result in results:
        label = result.get("label", "UNKNOWN")
        url = result.get("url", "")
        summary = result.get("summary", "")

        if label not in {"RISK", "WARN"}:
            continue

        confidence = "HIGH" if label == "RISK" else "MEDIUM"
        evidence = f"{label}: {url} ({summary})"

        add_mapping(
            mappings,
            tactic="Initial Access",
            technique_id="T1566.002",
            technique_name="Phishing: Spearphishing Link",
            confidence=confidence,
            signal="Malicious or suspicious linked URL",
            evidence=evidence,
            recommendation="Do not visit or distribute flagged links; validate ownership, final redirect destination, and hosting reputation.",
        )
        add_mapping(
            mappings,
            tactic="Initial Access",
            technique_id="T1189",
            technique_name="Drive-by Compromise",
            confidence="MEDIUM" if label == "RISK" else "LOW",
            signal="Risky web link could deliver browser-side payloads",
            evidence=evidence,
            recommendation="Investigate flagged links in an isolated environment and review redirects, scripts, and downloaded content.",
        )

    return sorted_mappings(mappings)


def combine_mappings(*mapping_groups: list[MitreAttackMapping]) -> list[MitreAttackMapping]:
    combined: dict[str, MitreAttackMapping] = {}

    for group in mapping_groups:
        for mapping in group:
            for evidence in mapping.evidence or [""]:
                add_mapping(
                    combined,
                    tactic=mapping.tactic,
                    technique_id=mapping.technique_id,
                    technique_name=mapping.technique_name,
                    confidence=mapping.confidence,
                    signal=mapping.signal,
                    evidence=evidence,
                    recommendation=mapping.recommendation,
                )

    return sorted_mappings(combined)


def sorted_mappings(mappings: dict[str, MitreAttackMapping]) -> list[MitreAttackMapping]:
    confidence_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(
        mappings.values(),
        key=lambda item: (
            confidence_order.get(item.confidence, 3),
            item.technique_id,
        ),
    )


def format_mitre_report(mappings: list[MitreAttackMapping]) -> str:
    if not mappings:
        return (
            "No ATT&CK mapping yet.\n\n"
            "Run a header scan, inspect network traffic, or scan page links to build technique candidates."
        )

    lines = [
        "MITRE ATT&CK Candidate Mapping",
        "",
        "These are analytical candidates based on browser-observed signals, not proof of compromise.",
    ]

    for mapping in mappings:
        url = TECHNIQUE_URLS.get(mapping.technique_id, "https://attack.mitre.org/")
        lines.extend(
            [
                "",
                f"[{mapping.confidence}] {mapping.technique_id} - {mapping.technique_name}",
                f"  Tactic: {mapping.tactic}",
                f"  Signal: {mapping.signal}",
                f"  ATT&CK: {url}",
                "  Evidence:",
            ]
        )

        for evidence in mapping.evidence[:5]:
            lines.append(f"    - {evidence}")

        if len(mapping.evidence) > 5:
            lines.append(f"    - +{len(mapping.evidence) - 5} more")

        lines.append(f"  Next step: {mapping.recommendation}")

    return "\n".join(lines)
