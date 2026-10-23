import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from defentail.cli import main as cli_main
from defentail.core import guard
from defentail.plugin import AGENTS, detect_agents, install, uninstall


class PluginInstallTests(unittest.TestCase):
    def test_install_merges_json_and_keeps_other_settings(self):
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as project:
            home = Path(home_dir)
            (home / ".claude").mkdir()
            config = home / ".claude.json"
            config.write_text(json.dumps({"theme": "dark", "mcpServers": {"other": {"command": "x"}}}))
            first = install(Path(project), targets="claude", home=home, project_files=False)
            self.assertEqual(first["changed"], 1)
            data = json.loads(config.read_text())
            self.assertEqual(data["theme"], "dark")
            self.assertEqual(data["mcpServers"]["other"], {"command": "x"})
            self.assertEqual(data["mcpServers"]["defentail"]["args"], ["-m", "defentail.mcp_server"])
            second = install(Path(project), targets="claude", home=home, project_files=False)
            self.assertEqual(second["actions"][0]["outcome"], "already-configured")
            self.assertTrue((home / ".claude.json.defentail-backup").is_file())

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as project:
            home = Path(home_dir)
            (home / ".cursor").mkdir()
            report = install(Path(project), targets="cursor", home=home,
                             project_files=False, dry_run=True)
            self.assertEqual(report["changed"], 1)
            self.assertFalse((home / ".cursor" / "mcp.json").exists())

    def test_codex_toml_block_is_added_once_and_removed(self):
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as project:
            home = Path(home_dir)
            (home / ".codex").mkdir()
            config = home / ".codex" / "config.toml"
            config.write_text('model = "gpt-5"\n')
            install(Path(project), targets="codex", home=home, project_files=False)
            text = config.read_text()
            self.assertIn('model = "gpt-5"', text)
            self.assertEqual(text.count("[mcp_servers.defentail]"), 1)
            install(Path(project), targets="codex", home=home, project_files=False)
            self.assertEqual(config.read_text().count("[mcp_servers.defentail]"), 1)
            uninstall(Path(project), targets="codex", home=home, project_files=False)
            remaining = config.read_text()
            self.assertIn('model = "gpt-5"', remaining)
            self.assertNotIn("mcp_servers.defentail", remaining)
            self.assertNotIn("Syrava DefenTail", remaining)
            self.assertEqual(remaining.strip(), 'model = "gpt-5"')

    def test_unreadable_config_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as project:
            home = Path(home_dir)
            (home / ".cursor").mkdir()
            config = home / ".cursor" / "mcp.json"
            config.write_text("{ this is not json")
            report = install(Path(project), targets="cursor", home=home, project_files=False)
            self.assertEqual(report["actions"][0]["outcome"], "skipped-unreadable-config")
            self.assertEqual(config.read_text(), "{ this is not json")

    def test_project_files_cover_agents_without_user_config(self):
        with tempfile.TemporaryDirectory() as project:
            workspace = Path(project)
            report = install(workspace, targets="all", home=workspace / "empty-home")
            targets = {action["target"]: action["outcome"] for action in report["actions"]}
            self.assertEqual(targets["vscode-project"], "configured")
            self.assertEqual(targets["claude-project"], "configured")
            self.assertEqual(targets["cursor-rule"], "configured")
            self.assertEqual(targets["agent-rules"], "configured")
            vscode = json.loads((workspace / ".vscode" / "mcp.json").read_text())
            self.assertEqual(vscode["servers"]["defentail"]["type"], "stdio")
            self.assertIn("defentail guard", (workspace / ".cursor" / "rules" / "defentail.mdc").read_text())
            # A second run must not leave backup churn behind for files DefenTail owns.
            self.assertFalse((workspace / ".vscode" / "mcp.json.defentail-backup").exists())
            uninstall(workspace, targets="all", home=workspace / "empty-home")
            self.assertFalse((workspace / ".vscode" / "mcp.json").exists())
            self.assertFalse((workspace / ".mcp.json").exists())

    def test_original_config_snapshot_is_preserved(self):
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as project:
            home = Path(home_dir)
            (home / ".cursor").mkdir()
            config = home / ".cursor" / "mcp.json"
            config.write_text(json.dumps({"mcpServers": {}}))
            install(Path(project), targets="cursor", home=home, project_files=False)
            original = (home / ".cursor" / "mcp.json.defentail-backup").read_text()
            self.assertEqual(json.loads(original), {"mcpServers": {}})
            install(Path(project), targets="cursor", home=home, project_files=False)
            self.assertEqual((home / ".cursor" / "mcp.json.defentail-backup").read_text(), original)

    def test_unknown_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as project:
            with self.assertRaises(ValueError):
                install(Path(project), targets="not-a-real-editor", home=Path(project))

    def test_uninstall_removes_only_the_defentail_entry(self):
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as project:
            home = Path(home_dir)
            (home / ".cursor").mkdir()
            config = home / ".cursor" / "mcp.json"
            config.write_text(json.dumps({"mcpServers": {"keep": {"command": "y"}}}))
            install(Path(project), targets="cursor", home=home, project_files=False)
            uninstall(Path(project), targets="cursor", home=home, project_files=False)
            data = json.loads(config.read_text())
            self.assertEqual(data["mcpServers"], {"keep": {"command": "y"}})

    def test_symlinked_config_is_never_written_through(self):
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as project:
            home = Path(home_dir)
            (home / ".cursor").mkdir()
            config = home / ".cursor" / "mcp.json"
            config.write_text(json.dumps({"mcpServers": {}}))
            with patch("pathlib.Path.is_symlink", return_value=True):
                report = install(Path(project), targets="cursor", home=home, project_files=False)
            self.assertEqual(report["actions"][0]["outcome"], "skipped-symlink")
            self.assertEqual(json.loads(config.read_text()), {"mcpServers": {}})

    def test_missing_mcp_sdk_is_reported_as_a_warning(self):
        with tempfile.TemporaryDirectory() as project:
            with patch("defentail.plugin.importlib.util.find_spec", return_value=None):
                report = install(Path(project), targets="all", home=Path(project) / "h", project_files=False)
            self.assertTrue(any("mcp" in w for w in report["warnings"]))
            with patch("defentail.plugin.importlib.util.find_spec", return_value=object()):
                report = install(Path(project), targets="all", home=Path(project) / "h", project_files=False)
            self.assertEqual(report["warnings"], [])

    def test_detection_uses_agent_markers(self):
        with tempfile.TemporaryDirectory() as home_dir:
            home = Path(home_dir)
            self.assertFalse(any(detect_agents(home).values()))
            (home / ".codex").mkdir()
            detected = detect_agents(home)
            self.assertTrue(detected["codex"])
            self.assertFalse(detected["cursor"])
            self.assertIn("cursor", AGENTS)


class GuardTests(unittest.TestCase):
    def test_guard_blocks_with_plain_language(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "server.py").write_text('requests.get("https://x", verify=False)\n')
            result = guard(root)
            self.assertEqual(result["verdict"], "BLOCK")
            self.assertFalse(result["can_ship"])
            item = result["blocking"][0]
            self.assertTrue(item["why_it_matters"])
            self.assertTrue(item["next_step"])
            self.assertIn("not proof", result["honesty"])
            self.assertNotIn("verify=False", json.dumps(result))
            self.assertEqual(cli_main(["guard", "--path", str(root), "--json"]), 2)

    def test_guard_passes_only_selected_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "server.py").write_text("print('hello')\n")
            result = guard(root)
            self.assertEqual(result["verdict"], "PASS_SELECTED_CHECKS")
            self.assertTrue(result["can_ship"])
            self.assertIn("static analysis cannot prove", result["honesty"].lower())
            self.assertEqual(cli_main(["guard", "--path", str(root)]), 0)

    def test_guard_rejects_unknown_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                guard(Path(folder), profile="everything")


if __name__ == "__main__":
    unittest.main()
