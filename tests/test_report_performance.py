import os
import unittest
from unittest.mock import patch

from sqlalchemy import event

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AGENT_SECRET_TOKEN"] = "test_secret_token_123"

from config import Config
from models import db, Device, DomainClassification, SystemMetadata
from servidor import app
import services


class AgentReportPerformanceTestCase(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        Config.AGENT_SECRET_TOKEN = "test_secret_token_123"
        Config.ACTIVITY_MONITORING_ENABLED = True
        Config.POLICY_MONITORING_ENABLED = True
        Config.DOMAIN_CLASSIFICATION_ENABLED = True
        self.client = app.test_client()

        with app.app_context():
            db.drop_all()
            db.create_all()
            device = Device(
                uuid="perf-device-001",
                hostname="PC-PERF-01",
                display_name="PC-PERF-01",
                department="TI",
                agent_version="1.5.1",
                ram_total_gb=16.0,
                disk_total_gb=512.0,
            )
            classification = DomainClassification(
                domain="intranet.example",
                category="business",
                risk_level="info",
                confidence=1.0,
                status="classified",
                source="test",
            )
            db.session.add_all([device, classification])
            db.session.commit()

        services._local_rules_cache = None
        services._local_rules_version = None
        services._last_version_check_time = 0
        services._local_allowlists_cache = None
        services._last_allowlists_load_time = 0
        services._idle_threshold_cache = None
        services._idle_threshold_cache_time = 0
        services._last_policy_evaluation.clear()
        services._last_normal_alert_evaluation.clear()

        self.payload = {
            "uuid": "perf-device-001",
            "computador": "PC-PERF-01",
            "usuario": "performance.test",
            "ip": "192.0.2.10",
            "mac": "00:11:22:33:44:55",
            "agent_version": "1.5.1",
            "cpu": 20.0,
            "ram": 35.0,
            "disco": 40.0,
            "ram_total_gb": 16.0,
            "ram_used_gb": 5.6,
            "disk_total_gb": 512.0,
            "disk_used_gb": 204.8,
            "uptime_seconds": 7200,
            "active_application": "EXCEL.EXE",
            "active_domain": "intranet.example",
            "idle_seconds": 5,
            "session_state": "active",
            "is_locked": False,
            "user_active": True,
            "windows_session_id": 1,
        }
        self.headers = {
            "X-Agent-Token": "test_secret_token_123",
            "X-Device-UUID": "perf-device-001",
        }

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_warm_report_keeps_contract_and_bounded_sql(self):
        with patch("services.random.random", return_value=1.0):
            warmup = self.client.post(
                "/api/agent/report", json=self.payload, headers=self.headers
            )
        self.assertEqual(warmup.status_code, 200)

        statements = []

        def record_statement(_conn, _cursor, statement, _parameters, _context, _many):
            statements.append(statement.strip())

        with app.app_context():
            engine = db.engine
            event.listen(engine, "before_cursor_execute", record_statement)
            try:
                with patch("services.random.random", return_value=1.0):
                    response = self.client.post(
                        "/api/agent/report", json=self.payload, headers=self.headers
                    )
            finally:
                event.remove(engine, "before_cursor_execute", record_statement)

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["device_id"], 1)
        self.assertIn("status_computed", body)
        self.assertIn("idle_threshold_seconds", body)

        device_selects = [
            sql for sql in statements
            if sql.upper().startswith("SELECT") and "FROM devices" in sql
        ]
        device_updates = [
            sql for sql in statements
            if sql.upper().startswith("UPDATE devices")
        ]
        self.assertEqual(len(device_selects), 1, statements)
        self.assertLessEqual(len(device_updates), 1, statements)
        self.assertFalse(any("policy_allowlists" in sql for sql in statements), statements)
        self.assertFalse(any("system_metadata" in sql for sql in statements), statements)
        self.assertLessEqual(len(statements), 5, statements)


if __name__ == "__main__":
    unittest.main()
