import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from defentail.cli import main as cli_main
from defentail.compliance import soc2_evidence
from defentail.core import digest_valid


class Soc2EvidenceTests(unittest.TestCase):
    def test_pack_is_sealed_and_covers_every_criterion(self):
        with tempfile.TemporaryDirectory() as folder:
            pack = soc2_evidence(Path(folder))
            self.assertTrue(digest_valid(pack))
            self.assertEqual(pack["schema"], "defentail.soc2.evidence.v1")
            self.assertEqual(len(pack["criteria"]), 10)
            self.assertEqual(sum(pack["control_summary"].values()), 10)
            self.assertIn("not an audit opinion", pack["disclaimer"].lower())
            self.assertTrue(pack["limitations"])

    def test_basic_scan_marks_vulnerability_detection_partial(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch("defentail.core.shutil.which", return_value=None):
                pack = soc2_evidence(Path(folder))
            cc71 = next(c for c in pack["criteria"] if c["id"] == "CC7.1")
            self.assertEqual(cc71["status"], "partial")
            self.assertIn("semgrep", cc71["checks_unavailable"])
            self.assertTrue(any(g["kind"] == "check-did-not-run" and g["engine"] == "semgrep"
                                for g in pack["gaps"]))

    def test_matching_finding_is_observed_not_passed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "client.py").write_text('requests.get("https://x", verify=False)\n', encoding="utf-8")
            pack = soc2_evidence(root)
            cc67 = next(c for c in pack["criteria"] if c["id"] == "CC6.7")
            self.assertEqual(cc67["status"], "finding-observed")
            self.assertEqual(cc67["observations"][0]["rule_id"], "DT-TLS-VERIFY-DISABLED")
            self.assertTrue(any(g["kind"] == "open-findings" and g["criterion"] == "CC6.7"
                                for g in pack["gaps"]))

    def test_criteria_without_tooling_ask_for_human_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            pack = soc2_evidence(Path(folder))
            for cid in ("A1.2", "P1.1"):
                criterion = next(c for c in pack["criteria"] if c["id"] == cid)
                self.assertEqual(criterion["status"], "human-evidence-required")
                self.assertTrue(criterion["human_evidence_required"])
            self.assertTrue(any(g["kind"] == "human-evidence-required" and g["criterion"] == "A1.2"
                                for g in pack["gaps"]))

    def test_clean_project_reports_collected_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            pack = soc2_evidence(Path(folder))
            cc41 = next(c for c in pack["criteria"] if c["id"] == "CC4.1")
            self.assertEqual(cc41["status"], "technical-evidence-collected")
            self.assertIn("recurring_findings", cc41)

    def test_cli_writes_evidence_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            out = root / "evidence" / "soc2.json"
            self.assertEqual(cli_main(["soc2", "--path", str(root), "--output", str(out)]), 0)
            self.assertTrue(out.is_file())
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(digest_valid(data))
            if os.name != "nt":
                self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_cli_json_mode_is_machine_readable(self):
        with tempfile.TemporaryDirectory() as folder:
            import io
            from contextlib import redirect_stdout
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cli_main(["soc2", "--path", folder, "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertIn("control_summary", payload)


if __name__ == "__main__":
    unittest.main()
