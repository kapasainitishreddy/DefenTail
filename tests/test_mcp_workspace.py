import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from defentail.mcp_server import workspace_path


class McpWorkspaceTests(unittest.TestCase):
    def test_pinned_workspace_is_used(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"DEFENTAIL_WORKSPACE": folder}):
                self.assertEqual(workspace_path(), Path(folder).resolve())

    def test_launch_directory_is_used_when_unpinned(self):
        with tempfile.TemporaryDirectory() as folder:
            env = {k: v for k, v in os.environ.items() if k != "DEFENTAIL_WORKSPACE"}
            with patch.dict(os.environ, env, clear=True):
                with patch("os.getcwd", return_value=folder):
                    self.assertEqual(workspace_path(), Path(folder).resolve())

    def test_filesystem_root_is_refused(self):
        root = str(Path("/").resolve())
        with patch.dict(os.environ, {"DEFENTAIL_WORKSPACE": root}):
            with self.assertRaises(ValueError):
                workspace_path()

    def test_missing_folder_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = str(Path(folder) / "nope")
            with patch.dict(os.environ, {"DEFENTAIL_WORKSPACE": missing}):
                with self.assertRaises(ValueError):
                    workspace_path()


if __name__ == "__main__":
    unittest.main()
