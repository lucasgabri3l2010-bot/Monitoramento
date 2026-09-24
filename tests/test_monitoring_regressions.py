"""Focused regressions for daytime reporting and displayed idle intervals."""

import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch

import requests

import agente
from models import db, Device, UsageSession, DailyUsageSummary
from servidor import app
from usage_service import current_idle_duration, process_device_usage_telemetry, reconcile_daily_usage_for_date


class _StopAfterWaits:
    def __init__(self, count):
        self.remaining = count
        self.stopped = False
        self.delays = []

    def clear(self):
        self.stopped = False

    def is_set(self):
        return self.stopped

    def wait(self, delay):
        self.delays.append(delay)
        self.remaining -= 1
        self.stopped = self.remaining <= 0
        return self.stopped


class AgentRuntimeRegressionTests(unittest.TestCase):
    def _run_cycles(self, report_side_effect, count=4, auto_update=False, update_workers=None):
        config = {
            "server_url": "https://example.invalid/api/agent/report",
            "agent_token": "test-token-with-enough-length",
            "device_token": "device-token",
            "department": "Test", "display_name": "",
            "interval_seconds": 1, "timeout_seconds": 1,
            "activity_monitoring": False, "auto_update": auto_update,
            "admin_notifications": False, "idle_threshold_seconds": 300,
        }
        event = _StopAfterWaits(count)
        metric = {
            "hostname": "PC", "cpu": 1, "ram": 2, "ram_used_gb": 1,
            "ram_total_gb": 2, "disco": 3, "session_state": "idle",
            "idle_seconds": 60,
        }
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(agente, "_shutdown_event", event), \
             patch.object(agente, "acquire_single_instance_mutex", return_value=True), \
             patch.object(agente, "release_single_instance_mutex") as release, \
             patch.object(agente, "load_config", return_value=config), \
             patch.object(agente, "get_config_file_path", return_value=directory + "/config.json"), \
             patch.object(agente, "get_system_metrics", return_value=metric), \
             patch.object(agente, "send_metrics", side_effect=report_side_effect) as send, \
             patch.object(agente, "emit_health_confirmation"), \
             patch.object(agente, "start_auto_update_worker", side_effect=update_workers or [None]) as start_update, \
             patch.object(agente, "start_admin_notifications_worker", return_value=None):
            agente.run_agent()
        release.assert_called_once()
        return send.call_count, event.delays, start_update.call_count

    def test_timeout_connection_and_5xx_keep_reporting_with_bounded_backoff(self):
        failures = [
            (False, None, "timeout", None),
            (False, None, "connection error", None),
            (False, 503, "server error", None),
            (True, 200, "ok", {}),
        ]
        calls, delays, _ = self._run_cycles(failures)
        self.assertEqual(calls, 4)
        self.assertEqual(delays, [5, 10, 20, 1])

    def test_malformed_http_response_does_not_kill_agent(self):
        response = Mock(status_code=200)
        response.json.side_effect = ValueError("malformed JSON")
        with patch.object(agente.requests, "post", return_value=response):
            self.assertTrue(agente.send_metrics("https://example.invalid", "test", {}, 1)[0])

    def test_report_loop_exceptions_are_contained_and_worker_is_restarted(self):
        dead = Mock()
        dead.is_alive.return_value = False
        alive = Mock()
        alive.is_alive.return_value = True
        effects = [RuntimeError("collection failed")] * 3 + [(True, 200, "ok", {})]
        calls, delays, starts = self._run_cycles(effects, auto_update=True, update_workers=[dead, alive])
        self.assertEqual(calls, 4)
        self.assertEqual(starts, 2)
        self.assertEqual(delays, [5, 10, 20, 1])

    def test_graceful_shutdown_stops_without_restarting(self):
        calls, _, _ = self._run_cycles([(True, 200, "ok", {})], count=1)
        self.assertEqual(calls, 1)

    def test_background_worker_failure_records_its_reason(self):
        with patch.object(agente.logger, "exception") as logged:
            agente._run_logged_background("test worker", Mock(side_effect=RuntimeError("worker died")))
        logged.assert_called_once()

    def test_immediately_dying_worker_has_restart_cooldown(self):
        dead = Mock()
        dead.is_alive.return_value = False
        with patch.object(agente.time, "monotonic", return_value=100):
            _, _, starts = self._run_cycles(
                [(True, 200, "ok", {})] * 4, auto_update=True,
                update_workers=[dead, dead],
            )
        self.assertEqual(starts, 2)  # initial launch plus one guarded restart

    def test_network_exceptions_are_returned_as_report_failures(self):
        for error in (requests.Timeout(), requests.ConnectionError()):
            with self.subTest(error=type(error).__name__), patch.object(agente.requests, "post", side_effect=error):
                self.assertFalse(agente.send_metrics("https://example.invalid", "test", {}, 1)[0])


class IdleIntervalRegressionTests(unittest.TestCase):
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
        self.ctx = app.app_context()
        self.ctx.push()
        DailyUsageSummary.query.delete()
        UsageSession.query.delete()
        Device.query.delete()
        self.device = Device(uuid="idle-regression", hostname="PC", updated_at=datetime.now(timezone.utc))
        db.session.add(self.device)
        db.session.commit()

    def tearDown(self):
        db.session.rollback()
        self.ctx.pop()

    def _report(self, moment, idle, state="idle", active=False, app="Microsoft Excel"):
        process_device_usage_telemetry(self.device, {
            "session_state": state, "user_active": active,
            "idle_seconds": idle, "active_application": app,
            "windows_session_id": 1,
        }, moment)
        db.session.commit()

    def test_overnight_counter_starts_at_eight_am(self):
        now = datetime(2026, 9, 21, 11, 20, tzinfo=timezone.utc)  # 08:20 Sao Paulo
        observed = datetime(2026, 9, 21, 10, 0)
        self.assertEqual(current_idle_duration(now.replace(tzinfo=None), 18 * 3600, observed), 20 * 60)

    def test_lunch_counter_starts_at_two_pm_and_seven_minutes_is_not_nineteen_hours(self):
        start = datetime(2026, 9, 21, 17, 0, tzinfo=timezone.utc)  # 14:00 Sao Paulo
        for minute in range(8):
            self._report(start + timedelta(minutes=minute), 19 * 3600 + minute * 60)
        self.assertEqual(self.device.current_session_state, "idle")
        self.assertAlmostEqual(self.device.last_idle_seconds, 7 * 60, delta=1)
        summary = reconcile_daily_usage_for_date(self.device.id, start.date())
        self.assertEqual(summary.idle_seconds, 7 * 60)
        self.assertEqual(summary.active_seconds, 0)
        self.assertEqual(summary.active_percentage, 0)

    def test_reconnect_does_not_backfill_idle_counter(self):
        self._report(datetime(2026, 9, 21, 17, 7, tzinfo=timezone.utc), 19 * 3600)
        self.assertEqual(self.device.last_idle_seconds, 0)
        self.assertEqual(self.device.current_session_state, "idle")

    def test_app_presence_is_not_real_input_and_new_input_resets_idle(self):
        first = datetime(2026, 9, 21, 17, 0, tzinfo=timezone.utc)
        self._report(first, 3600)
        self._report(first + timedelta(minutes=1), 3660)
        self.assertEqual(self.device.current_session_state, "idle")
        self.assertEqual(self.device.last_idle_seconds, 60)
        self._report(first + timedelta(minutes=2), 2, state="active", active=True)
        self.assertEqual(self.device.current_session_state, "active")
        self.assertEqual(self.device.last_idle_seconds, 0)

    def test_lunch_and_overnight_inactivity_never_show_idle(self):
        for moment in (datetime(2026, 9, 21, 10, 30, tzinfo=timezone.utc),
                       datetime(2026, 9, 21, 15, 30, tzinfo=timezone.utc)):
            with self.subTest(moment=moment):
                self._report(moment, 18 * 3600)
                self.assertEqual(self.device.current_session_state, "off_hours")
                self.assertEqual(self.device.last_idle_seconds, 0)

    def test_device_today_totals_include_only_real_overtime_activity(self):
        start = datetime(2026, 9, 21, 10, 30)  # 07:30 Sao Paulo
        db.session.add(UsageSession(
            device_id=self.device.id, state="overtime",
            started_at=start, ended_at=start + timedelta(minutes=15),
            duration_seconds=900, is_open=False,
        ))
        db.session.add(UsageSession(
            device_id=self.device.id, state="off_hours",
            started_at=start + timedelta(minutes=15),
            ended_at=start + timedelta(minutes=30),
            duration_seconds=900, is_open=False,
        ))
        db.session.commit()
        today_usage = reconcile_daily_usage_for_date(self.device.id, start.date()).to_dict()
        self.assertEqual(today_usage["active_seconds"], 900)
        self.assertEqual(today_usage["idle_seconds"], 0)
        self.assertEqual(today_usage["active_percentage"], 100.0)


if __name__ == "__main__":
    unittest.main()
