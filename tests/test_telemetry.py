import json
import os
import unittest
from unittest.mock import MagicMock, patch

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AGENT_SECRET_TOKEN"] = "telemetry_test_token_123"
os.environ["SECRET_KEY"] = "telemetry-test-secret"
os.environ["FLASK_ENV"] = "testing"

from models import db
from servidor import app
from telemetry import telemetry, track_release_stream


class AggregatedTelemetryTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI="sqlite:///:memory:")
        with self.app.app_context():
            db.drop_all()
            db.create_all()
        telemetry.reset()
        self.client = self.app.test_client()

    def tearDown(self):
        telemetry.reset()

    def test_request_aggregate_counts_route_bytes_status_latency_and_sql(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

        snapshot = telemetry.snapshot()
        item = snapshot["endpoints"]["GET /health"]
        self.assertEqual(item["requests"], 1)
        self.assertEqual(item["request_bytes"], 0)
        self.assertEqual(item["response_bytes"], len(response.data))
        self.assertEqual(item["status_codes"], {"200": 1})
        self.assertGreaterEqual(item["sql_queries"], 1)
        self.assertGreaterEqual(item["duration_ms_avg"], 0)

    def test_aggregate_never_contains_headers_query_strings_or_payload(self):
        secret = "must-never-appear-in-telemetry"
        response = self.client.post(
            f"/api/agent/report?debug={secret}",
            json={"hostname": "PC-TELEMETRY", "private": secret},
            headers={"X-Agent-Token": secret},
        )
        self.assertEqual(response.status_code, 401)

        serialized = json.dumps(telemetry.snapshot())
        self.assertNotIn(secret, serialized)
        self.assertIn("POST /api/agent/report", serialized)

    def test_periodic_emit_is_one_aggregate_log_not_one_log_per_request(self):
        self.client.get("/health")
        fake_logger = MagicMock()
        with patch("telemetry.time.monotonic", return_value=10_000_000):
            telemetry.maybe_emit(fake_logger)
        fake_logger.info.assert_called_once()
        self.assertIn("TELEMETRY_AGGREGATE", fake_logger.info.call_args.args[0])

    def test_release_stream_counts_actual_yielded_bytes(self):
        telemetry.record_release_attempt("r2_stream")
        content = b"".join(track_release_stream([b"abc", b"defgh"], "r2_stream"))
        self.assertEqual(content, b"abcdefgh")
        release = telemetry.snapshot()["release_downloads"]["r2_stream"]
        self.assertEqual(release["requests"], 1)
        self.assertEqual(release["backend_bytes"], 8)


if __name__ == "__main__":
    unittest.main()
