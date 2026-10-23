import json
import tempfile
import unittest
from pathlib import Path

from defentail.core import guard, scan
from defentail.memory import (fingerprint_stats, history_for, load, memory_path,
                              record_decision, record_scan, summary)


def _report(root, profile="basic"):
    return scan(root, profile=profile)


class AttackMemoryTests(unittest.TestCase):
    def test_scan_is_recorded_without_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "config.py").write_text('aws = "AKIAABCDEFGHIJKLMNOP"\n', encoding="utf-8")
            report = _report(root)
            self.assertTrue(record_scan(root, report))
            text = memory_path(root).read_text(encoding="utf-8")
            self.assertIn("DT-AWS-KEY-PATTERN", text)
            self.assertNotIn("AKIAABCDEFGHIJKLMNOP", text)
            data = summary(root)
            self.assertEqual(data["scans"], 1)
            self.assertEqual(data["decisions"], 0)

    def test_recurrence_and_reappearance_after_clear(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "client.py"
            target.write_text('requests.get("https://x", verify=False)\n', encoding="utf-8")
            record_scan(root, _report(root))
            target.write_text('requests.get("https://x", verify=True)\n', encoding="utf-8")
            record_scan(root, _report(root))
            target.write_text('requests.get("https://x", verify=False)\n', encoding="utf-8")
            record_scan(root, _report(root))
            stats = fingerprint_stats(root)
            self.assertEqual(len(stats), 1)
            entry = next(iter(stats.values()))
            self.assertEqual(entry["times_seen"], 2)
            self.assertTrue(entry["reappeared"])
            self.assertEqual(summary(root)["returned_after_clear"][0]["rule_id"], "DT-TLS-VERIFY-DISABLED")

    def test_decisions_are_counted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            record_decision(root, "BLOCK", ["abc"])
            record_decision(root, "PASS_SELECTED_CHECKS", [])
            data = summary(root)
            self.assertEqual(data["decisions"], 2)
            self.assertEqual(data["blocked_decisions"], 1)
            self.assertEqual(data["passed_decisions"], 1)
            with self.assertRaises(ValueError):
                record_decision(root, "ALL_GOOD", [])

    def test_corrupt_line_does_not_break_history(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = memory_path(root)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"kind":"scan","ts":"t","findings":[]}\nnot json at all\n', encoding="utf-8")
            records = load(root)
            self.assertEqual(len(records), 1)
            self.assertIsInstance(summary(root), dict)

    def test_guard_writes_and_reads_memory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "server.py").write_text('requests.get("https://x", verify=False)\n', encoding="utf-8")
            first = guard(root)
            self.assertEqual(first["verdict"], "BLOCK")
            self.assertNotIn("memory", first["blocking"][0])
            second = guard(root)
            self.assertEqual(second["blocking"][0]["memory"]["times_seen"], 1)
            third = guard(root)
            self.assertEqual(third["blocking"][0]["memory"]["times_seen"], 2)
            self.assertEqual(summary(root)["decisions"], 3)

    def test_history_returns_only_requested_fingerprints(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "server.py").write_text('requests.get("https://x", verify=False)\n', encoding="utf-8")
            record_scan(root, _report(root))
            fp = next(iter(fingerprint_stats(root)))
            self.assertEqual(list(history_for(root, [fp])), [fp])
            self.assertEqual(history_for(root, ["missing"]), {})

    def test_memory_is_skipped_by_the_scanner(self):
        """The ledger must never feed itself back into findings."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "server.py").write_text('requests.get("https://x", verify=False)\n', encoding="utf-8")
            record_scan(root, _report(root))
            again = scan(root, profile="basic")
            paths = {f["path"] for f in again["findings"]}
            self.assertTrue(all(not p.startswith(".defentail/") for p in paths))


if __name__ == "__main__":
    unittest.main()
