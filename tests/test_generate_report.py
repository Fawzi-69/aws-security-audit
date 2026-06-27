"""Tests unitaires du générateur de rapport.

Couvre la normalisation de sévérité et les trois parsers, en particulier le parser
OCSF de Prowler confronté à un échantillon au schéma réaliste (metadata.event_code,
severity_id numérique, statut PASS à exclure, ressource sans nom, région via cloud).
"""
import json
import os
import sys
import unittest

# Le générateur vit dans scripts/ ; pas de package, on l'ajoute au path.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))

import generate_report as gr  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


class NormSeverity(unittest.TestCase):
    def test_string_labels(self):
        self.assertEqual(gr.norm_severity("CRITICAL"), "critical")
        self.assertEqual(gr.norm_severity("High"), "high")
        self.assertEqual(gr.norm_severity("informational"), "info")

    def test_numeric_ocsf_ids(self):
        self.assertEqual(gr.norm_severity(5), "critical")
        self.assertEqual(gr.norm_severity(4), "high")
        self.assertEqual(gr.norm_severity(3), "medium")
        self.assertEqual(gr.norm_severity("2"), "low")

    def test_empty_defaults_medium(self):
        self.assertEqual(gr.norm_severity(None), "medium")
        self.assertEqual(gr.norm_severity(""), "medium")


class ProwlerOcsf(unittest.TestCase):
    def setUp(self):
        self.findings = gr.parse_prowler_ocsf(load("prowler_ocsf_sample.json"))

    def test_excludes_pass(self):
        # 3 entrées dont 1 PASS -> 2 findings.
        self.assertEqual(len(self.findings), 2)
        self.assertTrue(all(f["status"] == "fail" for f in self.findings))

    def test_control_from_event_code(self):
        ctrls = {f["control"] for f in self.findings}
        self.assertIn("iam_root_mfa_enabled", ctrls)

    def test_control_falls_back_to_uid(self):
        # 2e entrée : pas d'event_code -> on retombe sur finding_info.uid.
        f = next(f for f in self.findings if "no_root_access_key" in f["control"])
        self.assertTrue(f["control"].startswith("prowler-aws-iam_no_root_access_key"))

    def test_severity_from_id(self):
        f = next(f for f in self.findings if f["control"] == "iam_root_mfa_enabled")
        self.assertEqual(f["severity"], "high")  # severity_id 4

    def test_resource_and_region_fallbacks(self):
        f = next(f for f in self.findings if "no_root_access_key" in f["control"])
        self.assertEqual(f["resource"], "arn:aws:iam::123456789012:root")  # uid faute de name
        self.assertEqual(f["location"], "global")

    def test_remediation_from_references_when_no_desc(self):
        f = next(f for f in self.findings if "no_root_access_key" in f["control"])
        self.assertIn("http", f["remediation"])


class CheckovTfsec(unittest.TestCase):
    def test_checkov_failed_checks(self):
        data = {"results": {"failed_checks": [
            {"check_id": "CKV_AWS_24", "check_name": "SSH open", "severity": "CRITICAL",
             "resource": "aws_security_group.app", "file_path": "/ec2.tf",
             "file_line_range": [22, 41], "guideline": "Restreindre."}
        ]}}
        out = gr.parse_checkov(data)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "critical")
        self.assertEqual(out[0]["location"], "/ec2.tf:22")

    def test_tfsec_results(self):
        data = {"results": [
            {"long_id": "aws-ec2-no-public-ingress-sgr", "rule_description": "public SSH",
             "severity": "CRITICAL", "resource": "aws_security_group.app",
             "location": {"filename": "/ec2.tf", "start_line": 27}, "resolution": "fix"}
        ]}
        out = gr.parse_tfsec(data)
        self.assertEqual(out[0]["control"], "aws-ec2-no-public-ingress-sgr")
        self.assertEqual(out[0]["location"], "/ec2.tf:27")


class DedupAndSort(unittest.TestCase):
    def test_dedup_and_severity_order(self):
        raw = [
            {"source": "checkov", "control": "C1", "resource": "r", "location": "l",
             "severity": "low", "title": "t", "status": "fail", "remediation": ""},
            {"source": "checkov", "control": "C1", "resource": "r", "location": "l",
             "severity": "low", "title": "t", "status": "fail", "remediation": ""},
            {"source": "prowler", "control": "C2", "resource": "r", "location": "l",
             "severity": "critical", "title": "t", "status": "fail", "remediation": ""},
        ]
        out = gr.dedup(raw)
        self.assertEqual(len(out), 2)            # doublon supprimé
        self.assertEqual(out[0]["severity"], "critical")  # trié par sévérité décroissante


if __name__ == "__main__":
    unittest.main()
