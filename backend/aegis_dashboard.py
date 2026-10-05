#!/usr/bin/env python3
"""AEGIS findings dashboard API.

The server intentionally uses only the Python standard library so the midsem
demo can run from a clean checkout or inside a tiny Python container.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = Path(os.environ.get("AEGIS_RESULTS_DIR", ROOT / "experiments" / "results"))
SCENARIOS_DIR = Path(os.environ.get("AEGIS_SCENARIOS_DIR", ROOT / "experiments" / "scenarios"))
FRONTEND_DIR = Path(os.environ.get("AEGIS_FRONTEND_DIR", ROOT / "frontend"))

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ZAP_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


@dataclass(frozen=True)
class BlueAIRecommendation:
    summary: str
    fix_steps: list[str]
    verification: str
    priority: str


@dataclass(frozen=True)
class Finding:
    finding_id: str
    name: str
    severity: str
    asset: str
    source_tool: str
    classification: str
    description: str
    timestamp: str
    blue_ai: BlueAIRecommendation


def main() -> None:
    host = os.environ.get("AEGIS_HOST", "127.0.0.1")
    port = int(os.environ.get("AEGIS_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), AegisHandler)
    print(f"AEGIS dashboard listening on http://{host}:{port}")
    server.serve_forever()


class AegisHandler(SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            self._json({"status": "ok"})
            return
        if path == "/api/findings":
            self._json({"findings": [asdict(finding) for finding in load_findings()]})
            return
        self._serve_frontend(path)

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_frontend(self, request_path: str) -> None:
        relative = unquote(request_path).lstrip("/") or "index.html"
        candidate = (FRONTEND_DIR / relative).resolve()
        if FRONTEND_DIR.resolve() not in candidate.parents and candidate != FRONTEND_DIR.resolve():
            self.send_error(403)
            return
        if candidate.is_dir():
            candidate = candidate / "index.html"
        if not candidate.exists():
            candidate = FRONTEND_DIR / "index.html"
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        body = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def load_findings() -> list[Finding]:
    findings: list[Finding] = []
    if RESULTS_DIR.exists():
        for path in sorted(RESULTS_DIR.glob("*.json")):
            payload = _read_json(path)
            if payload is None:
                continue
            timestamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
            lower_name = path.name.lower()
            if "zap" in lower_name:
                findings.extend(parse_zap_report(payload, timestamp))
            elif "caldera" in lower_name:
                findings.extend(parse_caldera_report(payload, timestamp))
    if not findings:
        findings.extend(load_manual_scenario_findings())
    return sorted(
        dedupe(findings),
        key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), item.source_tool, item.asset, item.name),
    )


def parse_zap_report(payload: Any, timestamp: str) -> list[Finding]:
    findings: list[Finding] = []
    for site in _as_list(_get(payload, "site")):
        asset = _asset_from_site(site)
        for alert in _as_list(_get(site, "alerts")):
            name = str(_get(alert, "alert", "name", default="Unnamed ZAP alert"))
            severity = normalize_severity(_get(alert, "riskdesc", "risk", "riskcode", default="info"))
            classification = _zap_classification(alert)
            description = str(_get(alert, "desc", "description", default=""))
            findings.append(
                Finding(
                    finding_id=stable_id("zap", asset, name, classification),
                    name=name,
                    severity=severity,
                    asset=asset,
                    source_tool="zap",
                    classification=classification,
                    description=strip_markup(description),
                    timestamp=timestamp,
                    blue_ai=recommend_blue_ai(name, severity, asset, classification, description),
                )
            )
    return findings


def parse_caldera_report(payload: Any, timestamp: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in walk_dicts(payload):
        technique = _get(node, "technique_id", "attack_id", "attack_technique")
        tactic = _get(node, "tactic", "attack_tactic")
        name = _get(node, "name", "ability_name", "technique_name")
        if not (technique or tactic or name):
            continue
        source_hint = " ".join(str(value).lower() for value in (technique, tactic, name) if value)
        if not any(marker in source_hint for marker in ("t10", "discovery", "attack", "ability")):
            continue
        asset = str(_get(node, "host", "hostname", "paw", "agent", default="employee"))
        classification = str(technique or tactic or "ATT&CK")
        findings.append(
            Finding(
                finding_id=stable_id("caldera", asset, str(name or classification), classification),
                name=str(name or classification),
                severity="info",
                asset=asset,
                source_tool="caldera",
                classification=classification,
                description=str(_get(node, "description", "command", "executor", default="")),
                timestamp=timestamp,
                blue_ai=recommend_blue_ai(
                    str(name or classification),
                    "info",
                    asset,
                    classification,
                    str(_get(node, "description", "command", "executor", default="")),
                ),
            )
        )
    return findings


def load_manual_scenario_findings() -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(SCENARIOS_DIR.glob("SC-*.yaml")):
        text = path.read_text(encoding="utf-8")
        scenario = simple_yaml(text)
        vulnerability = scenario.get("vulnerability", {})
        if not isinstance(vulnerability, dict) or not vulnerability:
            continue
        cwe = str(vulnerability.get("cwe", ""))
        owasp = str(vulnerability.get("owasp_category", ""))
        classification = " / ".join(part for part in (cwe, owasp) if part) or "manual"
        findings.append(
            Finding(
                finding_id=stable_id("manual", str(scenario.get("scenario_id", path.stem)), classification),
                name=str(vulnerability.get("class", scenario.get("name", path.stem))),
                severity=str(vulnerability.get("severity", "high")).lower(),
                asset=str(scenario.get("objective", {}).get("target", "webapp")),
                source_tool="manual",
                classification=classification,
                description=str(scenario.get("name", path.stem)),
                timestamp=datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
                blue_ai=recommend_blue_ai(
                    str(vulnerability.get("class", scenario.get("name", path.stem))),
                    str(vulnerability.get("severity", "high")).lower(),
                    str(scenario.get("objective", {}).get("target", "webapp")),
                    classification,
                    str(scenario.get("name", path.stem)),
                ),
            )
        )
    return findings


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


def simple_yaml(text: str) -> dict[str, Any]:
    """Parse the small, predictable scenario YAML shape without dependencies."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#") or raw_line.lstrip().startswith("-"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        key, separator, value = raw_line.strip().partition(":")
        if not separator:
            continue
        while stack and indent <= stack[-1][0]:
            stack.pop()
        current = stack[-1][1]
        value = value.strip().strip('"')
        if value:
            current[key] = value
        else:
            child: dict[str, Any] = {}
            current[key] = child
            stack.append((indent, child))
    return root


def normalize_severity(value: Any) -> str:
    text = str(value or "info").lower()
    if text in ZAP_RISK:
        return ZAP_RISK[text]
    for severity in ("critical", "high", "medium", "low", "info"):
        if severity in text:
            return severity
    return "info"


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for finding in findings:
        seen.setdefault(finding.finding_id, finding)
    return list(seen.values())


def stable_id(*parts: str) -> str:
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"finding-{digest}"


def strip_markup(value: str) -> str:
    return value.replace("<p>", "").replace("</p>", "\n").replace("<br>", "\n").strip()


def walk_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def _zap_classification(alert: dict[str, Any]) -> str:
    cwe = str(_get(alert, "cweid", "cwe", default="")).strip()
    wasc = str(_get(alert, "wascid", "wasc", default="")).strip()
    plugin = str(_get(alert, "pluginid", "pluginId", default="")).strip()
    parts = []
    if cwe and cwe not in ("0", "-1"):
        parts.append(f"CWE-{cwe}" if cwe.isdigit() else cwe)
    if wasc and wasc not in ("0", "-1"):
        parts.append(f"WASC-{wasc}" if wasc.isdigit() else wasc)
    if plugin:
        parts.append(f"ZAP-{plugin}")
    return " / ".join(parts) or "ZAP"


def _asset_from_site(site: dict[str, Any]) -> str:
    raw = str(_get(site, "@name", "name", "host", default="webapp"))
    host = urlparse(raw).hostname or raw
    return "webapp" if host in {"webapp", "localhost", "127.0.0.1"} else host


def _get(mapping: Any, *keys: str, default: Any = None) -> Any:
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return default


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


if __name__ == "__main__":
    main()
