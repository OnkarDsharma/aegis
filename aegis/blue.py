"""Blue-team remediation recommendations (PRD FR-14, first iteration).

Deterministic rules keyed on weakness class. Phase 3 replaces this with a blue
agent that also predicts impact and stages a rollback plan; the rules stay as
the evidence-grounded fallback.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BlueAIRecommendation:
    summary: str
    fix_steps: list[str]
    verification: str
    priority: str


def recommend_blue_ai(
    name: str,
    severity: str,
    asset: str,
    classification: str,
    description: str = "",
) -> BlueAIRecommendation:
    """Return deterministic Blue AI remediation advice for demo stability."""
    text = " ".join((name, classification, description)).lower()
    priority = _priority_for_severity(severity)

    if "sql" in text or "cwe-89" in text or "injection" in text:
        return BlueAIRecommendation(
            summary=f"Blue AI: {asset} is accepting user input that can change a database query.",
            fix_steps=[
                "Replace string-built SQL with parameterized queries or ORM query builders.",
                "Validate the login request shape server-side and reject unexpected operators or comments.",
                "Keep database accounts least-privileged so a web injection cannot modify unrelated data.",
            ],
            verification="Re-run the login bypass test and the ZAP scan; the SQL injection alert should disappear.",
            priority=priority,
        )

    if "cross site scripting" in text or "xss" in text or "cwe-79" in text:
        return BlueAIRecommendation(
            summary=f"Blue AI: {asset} may render attacker-controlled script in a user's browser.",
            fix_steps=[
                "Encode untrusted output for the exact HTML, attribute, URL, or JavaScript context.",
                "Sanitize rich text with an allowlist sanitizer before storing or rendering it.",
                "Add a restrictive Content-Security-Policy to reduce script execution impact.",
            ],
            verification="Replay the payload that triggered the alert and confirm it renders as text, then re-run ZAP.",
            priority=priority,
        )

    if "header" in text or "csp" in text or "content security policy" in text:
        return BlueAIRecommendation(
            summary=f"Blue AI: {asset} is missing browser hardening headers.",
            fix_steps=[
                "Add Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, and frame protection headers.",
                "Apply the headers at the reverse proxy or app middleware so every response is covered.",
                "Start with report-only CSP if the app needs tuning before enforcement.",
            ],
            verification="Use curl or ZAP to confirm the headers appear on the Juice Shop responses.",
            priority=priority,
        )

    if "component" in text or "dependency" in text or "version" in text or "vulnerable js library" in text:
        return BlueAIRecommendation(
            summary=f"Blue AI: {asset} appears to include a dependency with known security risk.",
            fix_steps=[
                "Identify the vulnerable package and upgrade to a patched version.",
                "Remove unused client-side libraries and lock dependency versions in source control.",
                "Run dependency scanning in CI before rebuilding the range image.",
            ],
            verification="Rebuild the app image and re-run ZAP; the vulnerable component alert should clear.",
            priority=priority,
        )

    if "cwe-521" in text or "weak credential" in text or "cwe-798" in text:
        return BlueAIRecommendation(
            summary=f"Blue AI: {asset} is configured with a guessable secret reachable from other hosts.",
            fix_steps=[
                "Rotate the secret to a long random value stored in a secrets manager, not the compose file.",
                "Restrict the service port to the networks that genuinely need it (segmentation).",
                "Disable remote root/admin login and use per-application least-privileged accounts.",
            ],
            verification="Re-run inventory collection: the weak-credential finding and every path through it should close.",
            priority=priority,
        )

    if "t1082" in text or "system information discovery" in text or "discovery" in text:
        return BlueAIRecommendation(
            summary=f"Blue AI: {asset} allowed host discovery commands during adversary emulation.",
            fix_steps=[
                "Limit shell access and container capabilities for the employee host.",
                "Alert on reconnaissance commands such as uname, whoami, hostname, and network inventory commands.",
                "Segment the range so workstation discovery does not expose database or app internals.",
            ],
            verification="Run the Caldera ability again and confirm telemetry or controls detect the discovery step.",
            priority="observe",
        )

    return BlueAIRecommendation(
        summary=f"Blue AI: review this {severity} finding on {asset} and reduce the exposed attack path.",
        fix_steps=[
            "Confirm the finding manually so demo evidence distinguishes true positives from scanner noise.",
            "Apply the vendor or framework-specific mitigation for the reported weakness.",
            "Document the fix owner and expected retest command in the scenario file.",
        ],
        verification="Re-run the same source tool and confirm the finding is gone or downgraded.",
        priority=priority,
    )


def _priority_for_severity(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "fix-now"
    if severity == "medium":
        return "fix-next"
    if severity == "low":
        return "harden"
    return "observe"
