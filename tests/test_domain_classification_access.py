import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AGENT_SECRET_TOKEN"] = "classification-access-test"

from config import Config
from models import db, Device, DomainClassification, User
from servidor import app
from services import process_agent_payload, update_domain_access_metadata
import services


class DomainClassificationAccessTestCase(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        Config.ACTIVITY_MONITORING_ENABLED = True
        Config.POLICY_MONITORING_ENABLED = True
        Config.DOMAIN_CLASSIFICATION_ENABLED = True
        self.client = app.test_client()

        with app.app_context():
            db.drop_all()
            db.create_all()
            admin = User(username="classification-admin", role="admin")
            admin.set_password("ClassificationPass123!")
            db.session.add(admin)
            db.session.commit()

        services._local_rules_cache = None
        services._local_rules_version = None
        services._last_version_check_time = 0
        services._last_policy_evaluation.clear()
        services._pending_domains_set.clear()
        services._pending_domain_access.clear()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_first_report_stores_access_without_changing_classification(self):
        with app.app_context():
            classification = DomainClassification(
                domain="portal.example",
                category="business",
                risk_level="info",
                confidence=0.97,
                source="test",
                status="classified",
            )
            db.session.add(classification)
            db.session.commit()

            before = datetime.now(timezone.utc)
            with patch("services.random.random", return_value=1.0):
                device = process_agent_payload({
                    "uuid": "access-device-1",
                    "computador": "PC-FIN-01",
                    "usuario": "maria.silva",
                    "setor": "Financeiro",
                    "active_app": "chrome.exe",
                    "active_domain": "portal.example",
                })
            after = datetime.now(timezone.utc)

            db.session.refresh(classification)
            accessed_at = classification.last_accessed_at.replace(tzinfo=timezone.utc)
            self.assertEqual(classification.last_device_id, device.id)
            self.assertGreaterEqual(accessed_at, before)
            self.assertLessEqual(accessed_at, after)
            self.assertEqual(classification.category, "business")
            self.assertEqual(classification.status, "classified")
            self.assertEqual(classification.confidence, 0.97)

    def test_first_access_is_kept_when_classification_is_created(self):
        with app.app_context():
            with patch("services.random.random", return_value=1.0):
                device = process_agent_payload({
                    "uuid": "new-domain-device",
                    "computador": "PC-NEW-DOMAIN",
                    "usuario": "new.user",
                    "setor": "TI",
                    "active_app": "chrome.exe",
                    "active_domain": "new-access.example",
                })

            classification = DomainClassification.query.filter_by(domain="new-access.example").one()
            self.assertEqual(classification.last_device_id, device.id)
            self.assertIsNotNone(classification.last_accessed_at)
            self.assertEqual(classification.status, "classified")

    def test_latest_device_wins_and_older_access_cannot_replace_it(self):
        with app.app_context():
            first = Device(uuid="access-device-1", hostname="PC-ONE", user_name="first.user")
            second = Device(uuid="access-device-2", hostname="PC-TWO", user_name="second.user")
            classification = DomainClassification(domain="shared.example", category="business")
            db.session.add_all([first, second, classification])
            db.session.commit()

            first_at = datetime(2026, 9, 23, 11, 0, tzinfo=timezone.utc)
            newest_at = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)
            stale_at = datetime(2026, 9, 23, 11, 30, tzinfo=timezone.utc)
            self.assertTrue(update_domain_access_metadata(first, "shared.example", first_at))
            self.assertTrue(update_domain_access_metadata(second, "shared.example", newest_at))
            self.assertFalse(update_domain_access_metadata(first, "shared.example", stale_at))
            db.session.commit()

            db.session.refresh(classification)
            self.assertEqual(classification.last_device_id, second.id)
            self.assertEqual(
                classification.last_accessed_at.replace(tzinfo=timezone.utc),
                newest_at,
            )

    def test_missing_device_metadata_and_sao_paulo_time_are_safe(self):
        with app.app_context():
            classification = DomainClassification(
                domain="orphan.example",
                category="unknown",
                last_accessed_at=datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc),
            )
            db.session.add(classification)
            db.session.commit()

            data = classification.to_dict()
            self.assertEqual(data["last_accessed_by"], "-")
            self.assertEqual(data["last_computer"], "-")
            self.assertEqual(data["last_department"], "-")
            self.assertEqual(data["last_accessed_at"], "23/09/2026 09:00:00")

    def test_status_endpoint_exposes_latest_device_values(self):
        with app.app_context():
            device = Device(
                uuid="access-device-api",
                hostname="PC-RH-01",
                display_name="Recepção RH",
                user_name="ana.souza",
                department="RH",
            )
            classification = DomainClassification(
                domain="rh.example",
                category="business",
                status="classified",
                last_accessed_at=datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc),
            )
            db.session.add_all([device, classification])
            db.session.flush()
            classification.last_device_id = device.id
            db.session.commit()

        self.client.post("/login", data={
            "username": "classification-admin",
            "password": "ClassificationPass123!",
        })
        response = self.client.get("/api/policies/classification/status")
        self.assertEqual(response.status_code, 200)
        item = response.get_json()["recent_classifications"][0]
        self.assertEqual(item["last_accessed_by"], "ana.souza")
        self.assertEqual(item["last_computer"], "Recepção RH")
        self.assertEqual(item["last_department"], "RH")
        self.assertEqual(item["last_accessed_at"], "23/09/2026 09:00:00")


if __name__ == "__main__":
    unittest.main()
