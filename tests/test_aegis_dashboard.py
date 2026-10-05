import unittest

from backend.aegis_dashboard import recommend_blue_ai, parse_caldera_report, parse_zap_report


class AegisDashboardTests(unittest.TestCase):
    def test_parse_zap_report_normalizes_alerts(self):
        report = {
            "site": [
                {
                    "@name": "http://webapp:3000",
                    "alerts": [
                        {
                            "alert": "SQL Injection",
                            "riskcode": "3",
                            "cweid": "89",
                            "pluginid": "40018",
                            "desc": "<p>Parameter appears injectable.</p>",
                        }
                    ],
                }
            ]
        }

        findings = parse_zap_report(report, "2026-10-05T00:00:00+00:00")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].asset, "webapp")
        self.assertIn("CWE-89", findings[0].classification)
        self.assertEqual(findings[0].blue_ai.priority, "fix-now")
        self.assertIn("parameterized", " ".join(findings[0].blue_ai.fix_steps).lower())

    def test_parse_caldera_report_extracts_attack_technique(self):
        report = {
            "steps": {
                "employee-paw": {
                    "ability": {
                        "name": "System Information Discovery",
                        "technique_id": "T1082",
                        "tactic": "discovery",
                        "command": "uname -a",
                    }
                }
            }
        }

        findings = parse_caldera_report(report, "2026-10-05T00:00:00+00:00")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source_tool, "caldera")
        self.assertEqual(findings[0].classification, "T1082")
        self.assertEqual(findings[0].severity, "info")
        self.assertEqual(findings[0].blue_ai.priority, "observe")
        self.assertIn("discovery", findings[0].blue_ai.summary.lower())

    def test_blue_ai_recommends_security_headers(self):
        recommendation = recommend_blue_ai(
            "Content Security Policy Header Not Set",
            "medium",
            "webapp",
            "ZAP-10038",
        )

        self.assertEqual(recommendation.priority, "fix-next")
        self.assertIn("Content-Security-Policy", " ".join(recommendation.fix_steps))


if __name__ == "__main__":
    unittest.main()
