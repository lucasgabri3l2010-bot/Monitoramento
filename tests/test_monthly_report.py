"""Focused monthly activity report tests."""

import unittest
from datetime import date, datetime, timedelta

from models import db, Device, DailyUsageSummary, UsageSession
from servidor import app
from usage_service import get_monthly_activity_report, reconcile_daily_usage_for_date


class MonthlyReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        with app.app_context():
            db.create_all()

    @classmethod
    def tearDownClass(cls):
        with app.app_context():
            db.drop_all()

    def setUp(self):
        self.context = app.app_context()
        self.context.push()
        DailyUsageSummary.query.delete()
        UsageSession.query.delete()
        Device.query.delete()
        self.alice = Device(uuid="monthly-alice", hostname="PC-A", user_name="Alice", department="TI")
        self.bob = Device(uuid="monthly-bob", hostname="PC-B", user_name="Bob", department="RH")
        self.no_data = Device(uuid="monthly-empty", hostname="PC-C", user_name="Carol", department="TI")
        db.session.add_all([self.alice, self.bob, self.no_data])
        db.session.commit()

    def tearDown(self):
        db.session.rollback()
        db.session.remove()
        self.context.pop()

    def session(self, device, state, start, minutes):
        db.session.add(UsageSession(
            device_id=device.id, state=state, started_at=start,
            ended_at=start + timedelta(minutes=minutes), duration_seconds=minutes * 60,
            is_open=False,
        ))

    def test_work_windows_overtime_offline_and_month_boundary(self):
        # UTC = São Paulo local + 3 hours in September 2026.
        self.session(self.alice, "active", datetime(2026, 9, 15, 11), 60)  # Tue 08:00
        self.session(self.alice, "idle", datetime(2026, 9, 15, 12), 30)
        self.session(self.alice, "off_hours", datetime(2026, 9, 15, 15), 60)  # lunch, not idle
        self.session(self.alice, "overtime", datetime(2026, 9, 15, 16), 20)
        self.session(self.alice, "active", datetime(2026, 9, 19, 11), 60)  # Sat 08:00
        self.session(self.alice, "idle", datetime(2026, 9, 19, 14), 30)
        self.session(self.alice, "overtime", datetime(2026, 9, 19, 15), 15)  # Sat 12:00
        self.session(self.alice, "overtime", datetime(2026, 9, 20, 13), 10)  # Sunday
        self.session(self.alice, "off_hours", datetime(2026, 9, 21, 10, 50), 20)  # off-hours crossing Mon 08:00
        self.session(self.alice, "active", datetime(2026, 10, 1, 11), 60)  # next month
        db.session.commit()
        for day in (date(2026, 9, 15), date(2026, 9, 19), date(2026, 9, 20), date(2026, 9, 21), date(2026, 10, 1)):
            reconcile_daily_usage_for_date(self.alice.id, day)
        db.session.commit()

        report = get_monthly_activity_report(2026, 9)
        alice = next(row for row in report["rows"] if row["device_id"] == self.alice.id)
        self.assertEqual(alice["monitored_workdays"], 2)
        self.assertEqual(alice["regular_active_seconds"], 7200)
        self.assertEqual(alice["regular_idle_seconds"], 3600)
        self.assertEqual(alice["average_active_seconds"], 3600)
        self.assertEqual(alice["average_idle_seconds"], 1800)
        self.assertEqual(alice["active_percentage"], 66.7)
        self.assertEqual(alice["overtime_seconds"], 2700)
        self.assertEqual(report["overall"]["overtime_seconds"], 2700)
        self.assertEqual(next(row for row in report["rows"] if row["device_id"] == self.no_data.id)["monitored_workdays"], 0)

    def test_weighted_fleet_percentage_and_filtered_daily_means(self):
        db.session.add_all([
            DailyUsageSummary(device_id=self.alice.id, date=date(2026, 9, 15), active_seconds=3600, idle_seconds=0),
            DailyUsageSummary(device_id=self.alice.id, date=date(2026, 9, 16), active_seconds=3600, idle_seconds=0),
            DailyUsageSummary(device_id=self.bob.id, date=date(2026, 9, 15), active_seconds=0, idle_seconds=3600),
        ])
        db.session.commit()
        report = get_monthly_activity_report(2026, 9)
        self.assertEqual(report["overall"]["average_active_seconds"], 1200)  # (3600+0+0)/3 devices
        self.assertEqual(report["overall"]["average_idle_seconds"], 1200)
        self.assertEqual(report["overall"]["active_percentage"], 66.7)  # weighted 7200/10800
        ti = get_monthly_activity_report(2026, 9, "ti")
        self.assertEqual({row["employee"] for row in ti["rows"]}, {"Alice", "Carol"})
        self.assertEqual(ti["overall"]["active_percentage"], 100.0)
        self.assertEqual([row["employee"] for row in get_monthly_activity_report(2026, 9, search="bob")["rows"]], ["Bob"])
        self.assertFalse(get_monthly_activity_report(2026, 8)["has_data"])

    def test_same_free_text_name_keeps_devices_separate(self):
        self.bob.user_name = "Alice"
        db.session.add(DailyUsageSummary(
            device_id=self.alice.id, date=date(2026, 9, 15), active_seconds=600, idle_seconds=0,
        ))
        db.session.commit()
        rows = get_monthly_activity_report(2026, 9)["rows"]
        self.assertEqual(len([row for row in rows if row["employee"] == "Alice"]), 2)
        self.assertEqual(len({row["device_id"] for row in rows}), 3)

    def test_endpoint_requires_login_and_valid_month(self):
        client = app.test_client()
        self.assertEqual(client.get("/api/reports/monthly?year=2026&month=9").status_code, 401)
        with client.session_transaction() as session:
            session["user_id"] = 1
        self.assertEqual(client.get("/api/reports/monthly?year=2026&month=13").status_code, 400)
        response = client.get("/api/reports/monthly?year=2026&month=9")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["month"], 9)


if __name__ == "__main__":
    unittest.main()
