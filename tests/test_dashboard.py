import json
import shutil
import tempfile
import unittest
from pathlib import Path

from lab.dashboard import experiment_records, lab_overview, list_experiments
from lab.workspace import init_experiment


ROOT = Path(__file__).resolve().parents[1]


class DashboardReadModelTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        shutil.copytree(ROOT / "config", self.root / "config")
        shutil.copytree(ROOT / "lab", self.root / "lab")

    def tearDown(self):
        self.temporary.cleanup()

    def test_overview_does_not_require_streamlit_or_docker(self):
        overview = lab_overview(self.root)
        self.assertEqual(overview["configuration"], "investigation-independent")
        self.assertIn("docker.compose", overview["capabilities"])

    def test_workspace_and_records_are_readable(self):
        init_experiment("dashboard-one", self.root)
        records_dir = self.root / "state" / "experiments" / "dashboard-one" / "records"
        (records_dir / "command.json").write_text(
            json.dumps({"status": "completed"}), encoding="utf-8"
        )
        self.assertEqual(list_experiments(self.root)[0]["experiment_id"], "dashboard-one")
        self.assertEqual(experiment_records("dashboard-one", self.root)[0]["status"], "completed")
