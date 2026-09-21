import gzip
import json
import os
import unittest

os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from models import db, Device
from servidor import app


class DashboardResponseOptimizationTestCase(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        with app.app_context():
            db.drop_all()
            db.create_all()
            db.session.add_all([
                Device(
                    uuid=f"dashboard-{index:02d}",
                    hostname=f"PC-DASHBOARD-{index:02d}",
                    display_name=f"Computador de teste {index:02d}",
                    department="Operações",
                    agent_version="1.5.1",
                    ram_total_gb=16.0,
                    disk_total_gb=512.0,
                )
                for index in range(30)
            ])
            db.session.commit()
        with self.client.session_transaction() as session:
            session["user_id"] = 1
            session["username"] = "dashboard-test"
            session["role"] = "admin"

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_devices_supports_gzip_and_conditional_get(self):
        response = self.client.get(
            "/api/devices",
            headers={"Accept-Encoding": "gzip"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Content-Encoding"), "gzip")
        self.assertIn("private", response.headers.get("Cache-Control", ""))
        self.assertIn("no-cache", response.headers.get("Cache-Control", ""))
        self.assertIn("Accept-Encoding", response.headers.get("Vary", ""))
        self.assertIn("Cookie", response.headers.get("Vary", ""))

        decoded = json.loads(gzip.decompress(response.data))
        self.assertEqual(len(decoded), 30)

        etag = response.headers.get("ETag")
        self.assertTrue(etag)
        unchanged = self.client.get(
            "/api/devices",
            headers={"Accept-Encoding": "gzip", "If-None-Match": etag},
        )
        self.assertEqual(unchanged.status_code, 304)
        self.assertEqual(unchanged.data, b"")


if __name__ == "__main__":
    unittest.main()
