import json
from pathlib import Path
import unittest

from config import Config


ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_VERSION = "1.5.1"
OFFICIAL_SHA256 = "e16bfc32798e4e395e28b0035bd27b2c9c3eedbdba8229776b914fbfc34a8288"
OFFICIAL_SIZE = 13725252


class VersionConsistencyTestCase(unittest.TestCase):
    def test_runtime_default_matches_official_release(self):
        self.assertEqual(Config.LATEST_AGENT_VERSION, OFFICIAL_VERSION)

    def test_manifest_matches_official_release(self):
        manifest = json.loads((ROOT / "releases" / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["version"], OFFICIAL_VERSION)
        self.assertEqual(manifest["sha256"], OFFICIAL_SHA256)
        self.assertEqual(manifest["file_size"], OFFICIAL_SIZE)
        self.assertEqual(manifest["object_key"], "agents/1.5.1/GivovaMonitorAgent.exe")

    def test_bootstrap_and_migration_seed_only_official_metadata(self):
        migration = (ROOT / "migrate.py").read_text(encoding="utf-8")
        bootstrap = (ROOT / "scripts" / "bootstrap_production_database.py").read_text(encoding="utf-8")
        for source in (migration, bootstrap):
            self.assertIn(OFFICIAL_SHA256, source)
            self.assertIn("agents/1.5.1/GivovaMonitorAgent.exe", source)
            self.assertIn(str(OFFICIAL_SIZE), source)
            self.assertNotIn('RELEASE_VERSION = "1.5.0"', source)
        self.assertNotIn('open(manifest_root, "w"', migration)

    def test_future_plan_does_not_publish_1_5_2(self):
        plan = (ROOT / "docs" / "AGENT_1_5_2_PLAN.md").read_text(encoding="utf-8")
        self.assertIn("somente desenho", plan)
        self.assertIn("Não construir, assinar, publicar", plan)
        self.assertIn("https://monitoramento-gb9g.onrender.com/api/agent/report", plan)
        self.assertIn("https://monitor.givovatransportes.com.br/api/agent/report", plan)


if __name__ == "__main__":
    unittest.main()
