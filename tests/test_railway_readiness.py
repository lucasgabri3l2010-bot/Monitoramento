import os
from pathlib import Path
import unittest

os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from models import db
from servidor import app


ROOT = Path(__file__).resolve().parents[1]


class RailwayReadinessTestCase(unittest.TestCase):
    def test_dockerfile_binds_injected_port_and_uses_exec(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("--bind 0.0.0.0:${PORT}", dockerfile)
        self.assertIn("python migrate.py && exec gunicorn", dockerfile)
        self.assertIn("/health", dockerfile)
        self.assertNotIn("--access-logfile -", dockerfile)

    def test_health_checks_include_database_connectivity(self):
        app.config["TESTING"] = True
        with app.app_context():
            db.create_all()
        client = app.test_client()
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["database"], "connected")

    def test_runbook_covers_safe_restore_and_no_cutover(self):
        runbook = (ROOT / "docs" / "RAILWAY_DEPLOY.md").read_text(encoding="utf-8")
        self.assertIn("não autoriza o cutover", runbook)
        self.assertIn("pg_dump", runbook)
        self.assertIn("pg_restore", runbook)
        self.assertIn("db.create_all()", runbook)
        self.assertIn("não existe uma cadeia Alembic", runbook)
        self.assertIn("monitor.givovatransportes.com.br", runbook)
        self.assertIn("e16bfc32798e4e395e28b0035bd27b2c9c3eedbdba8229776b914fbfc34a8288", runbook)

    def test_postgres_validation_script_checks_required_objects(self):
        validation = (ROOT / "scripts" / "validate_postgres_migration.sql").read_text(encoding="utf-8")
        self.assertIn("EXACT ROW COUNTS", validation)
        self.assertIn("PRIMARY AND FOREIGN KEYS", validation)
        self.assertIn("INDEXES", validation)
        self.assertIn("SEQUENCES", validation)


if __name__ == "__main__":
    unittest.main()
