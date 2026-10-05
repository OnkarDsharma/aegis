import unittest

from backend.aegis_dashboard import parse_caldera_report, parse_zap_report


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


if __name__ == "__main__":
    unittest.main()
