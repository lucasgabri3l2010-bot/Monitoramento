"""
Suíte de Testes Automatizados - Monitoramento de Tempo de Uso Real e Atividade (v1.5.0)

Cobre:
1. Transições de estado de sessão: active, idle, locked, offline.
2. Clamp retroativo no cálculo de idle_started_at com início confiável.
3. Idempotência estrita: reenvio de reports idênticos não duplica segundos.
4. Compatibilidade com agentes legados v1.4.1 (sem payload de atividade).
5. Fechamento de sessão por gap prolongado (> MAX_USAGE_GAP_SECONDS).
6. Fechamento de sessão quando o dispositivo fica offline (close_stale_device_sessions).
7. Troca de Windows Session ID (troca de usuário / RDP).
8. Particionamento e agregação diária (DailyUsageSummary) com virada de meia-noite civil.
9. Rotas de API: /api/devices/<id>/usage e /api/settings/idle-threshold (GET e POST).
"""

import unittest
from datetime import datetime, timezone, timedelta, date
import json

from config import Config
from datetime_utils import (
    utc_now, ensure_utc, to_app_timezone, format_iso_utc,
    start_of_local_day_utc, start_of_next_local_day_utc, get_local_date
)
from models import (
    db, Device, User, UsageSession, DailyUsageSummary, SystemMetadata
)
from usage_service import (
    classify_work_activity_state,
    process_device_usage_telemetry,
    reconcile_daily_usage_for_date,
    close_stale_device_sessions,
    get_device_usage_data,
    cleanup_old_usage_data
)
from servidor import app


class TestUsageActivityService(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        app.config["APP_TIMEZONE"] = "America/Sao_Paulo"
        with app.app_context():
            db.create_all()

    @classmethod
    def tearDownClass(cls):
        with app.app_context():
            db.drop_all()

    def setUp(self):
        self.app_ctx = app.app_context()
        self.app_ctx.push()
        self.client = app.test_client()

        # Clean tables
        DailyUsageSummary.query.delete()
        UsageSession.query.delete()
        Device.query.delete()
        User.query.delete()
        SystemMetadata.query.delete()
        db.session.commit()

        # Create admin user for API testing
        self.admin = User(username="admin_test", role="admin")
        self.admin.set_password("AdminPass123!")
        db.session.add(self.admin)

        # Create base test device
        self.device = Device(
            uuid="test-uuid-001",
            hostname="WS-TEST-01",
            ip_address="192.168.1.100",
            os_name="Windows 11 Pro",
            agent_version="1.5.0",
            updated_at=utc_now()
        )
        db.session.add(self.device)
        db.session.commit()

    def tearDown(self):
        db.session.rollback()
        self.app_ctx.pop()

    def _login_admin(self):
        return self.client.post("/login", data={
            "username": "admin_test",
            "password": "AdminPass123!"
        }, follow_redirects=True)

    def test_01_initial_telemetry_creates_active_session(self):
        """Report inicial com usuário interagindo deve criar sessão 'active'."""
        t0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
        payload = {
            "session_state": "active",
            "idle_seconds": 5,
            "is_locked": False,
            "user_active": True,
            "windows_session_id": 1,
            "idle_threshold_seconds": 300,
        }

        process_device_usage_telemetry(self.device, payload, t0)
        db.session.commit()

        sessions = UsageSession.query.filter_by(device_id=self.device.id).all()
        self.assertEqual(len(sessions), 1)
        s = sessions[0]
        self.assertEqual(s.state, "active")
        self.assertEqual(s.started_at, t0.replace(tzinfo=None))
        self.assertEqual(s.ended_at, t0.replace(tzinfo=None))
        self.assertEqual(s.duration_seconds, 0)
        self.assertTrue(s.is_open)
        self.assertEqual(self.device.current_session_state, "active")
        self.assertTrue(self.device.user_active)

    def test_02_continuous_active_extends_session(self):
        """Reports subsequentes no mesmo estado 'active' estendem a sessão aberta."""
        t0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 9, 15, 12, 0, 30, tzinfo=timezone.utc)
        payload = {
            "session_state": "active",
            "idle_seconds": 10,
            "is_locked": False,
            "user_active": True,
            "windows_session_id": 1,
            "idle_threshold_seconds": 300,
        }

        process_device_usage_telemetry(self.device, payload, t0)
        self.device.updated_at = t0
        db.session.commit()

        process_device_usage_telemetry(self.device, payload, t1)
        self.device.updated_at = t1
        db.session.commit()

        sessions = UsageSession.query.filter_by(device_id=self.device.id).all()
        self.assertEqual(len(sessions), 1)
        s = sessions[0]
        self.assertEqual(s.started_at, t0.replace(tzinfo=None))
        self.assertEqual(s.ended_at, t1.replace(tzinfo=None))
        self.assertEqual(s.duration_seconds, 30)
        self.assertTrue(s.is_open)

    def test_03_transition_to_idle_with_retrospective_clamp(self):
        """
        Transição para idle aplica clamp retroativo:
        calculated_last_input = now - idle_seconds.
        A sessão anterior é encerrada no ponto exato de inatividade e a sessão 'idle' se inicia nele.
        """
        t0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

        # Simula reports periódicos a cada 60s (dentro do MAX_USAGE_GAP_SECONDS de 120s)
        for minute in range(5):
            t_report = t0 + timedelta(minutes=minute)
            process_device_usage_telemetry(self.device, {
                "session_state": "active",
                "idle_seconds": minute * 60,
                "is_locked": False,
                "user_active": True,
                "windows_session_id": 1
            }, t_report)
            self.device.updated_at = t_report
            db.session.commit()

        # No 5º minuto (12:05:00), threshold de 300s atingido -> transição para 'idle'
        t5 = t0 + timedelta(minutes=5)
        process_device_usage_telemetry(self.device, {
            "session_state": "idle",
            "idle_seconds": 300,
            "is_locked": False,
            "user_active": False,
            "windows_session_id": 1
        }, t5)
        self.device.updated_at = t5
        db.session.commit()

        sessions = UsageSession.query.filter_by(device_id=self.device.id).order_by(UsageSession.started_at).all()
        self.assertEqual(len(sessions), 2)

        s_active, s_idle = sessions[0], sessions[1]
        # Sessão ativa fechada às 12:00:00
        self.assertEqual(s_active.state, "active")
        self.assertFalse(s_active.is_open)
        self.assertEqual(s_active.ended_at, t0.replace(tzinfo=None))

        # Sessão idle começou retroativamente às 12:00:00 e vai até 12:05:00
        self.assertEqual(s_idle.state, "idle")
        self.assertEqual(s_idle.started_at, t0.replace(tzinfo=None))
        self.assertEqual(s_idle.ended_at, t5.replace(tzinfo=None))
        self.assertEqual(s_idle.duration_seconds, 300)
        self.assertEqual(self.device.current_session_state, "idle")
        self.assertFalse(self.device.user_active)

    def test_04_retrospective_clamp_cannot_predate_observation_start(self):
        """
        Se o idle_seconds for maior que o tempo de observação (ex: primeiro contato já com 30min idle),
        o clamp não retroage antes do início confiável (now_naive).
        """
        t0 = datetime(2026, 9, 15, 14, 0, 0, tzinfo=timezone.utc)
        payload = {
            "session_state": "idle",
            "idle_seconds": 1800,  # 30 minutos de ociosidade
            "is_locked": False,
            "user_active": False,
            "windows_session_id": 1
        }

        process_device_usage_telemetry(self.device, payload, t0)
        db.session.commit()

        sessions = UsageSession.query.filter_by(device_id=self.device.id).all()
        self.assertEqual(len(sessions), 1)
        s = sessions[0]
        self.assertEqual(s.state, "idle")
        self.assertEqual(s.started_at, t0.replace(tzinfo=None))
        self.assertEqual(s.ended_at, t0.replace(tzinfo=None))
        self.assertEqual(s.duration_seconds, 0)

    def test_05_locked_session_is_idle_during_work_hours(self):
        """A locked workstation is work-hours inactivity, not a fifth logical state."""
        t0 = datetime(2026, 9, 15, 15, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 9, 15, 15, 2, 0, tzinfo=timezone.utc)

        process_device_usage_telemetry(self.device, {
            "session_state": "active",
            "idle_seconds": 10,
            "is_locked": False,
            "user_active": True,
            "windows_session_id": 1
        }, t0)
        self.device.updated_at = t0
        db.session.commit()

        # Usuário pressiona Win+L (locked)
        process_device_usage_telemetry(self.device, {
            "session_state": "locked",
            "idle_seconds": 120,
            "is_locked": True,
            "user_active": False,
            "windows_session_id": 1
        }, t1)
        self.device.updated_at = t1
        db.session.commit()

        sessions = UsageSession.query.filter_by(device_id=self.device.id).order_by(UsageSession.started_at).all()
        self.assertEqual(len(sessions), 2)
        self.assertEqual(sessions[0].state, "active")
        self.assertFalse(sessions[0].is_open)
        self.assertEqual(sessions[1].state, "idle")
        self.assertEqual(self.device.current_session_state, "idle")
        self.assertFalse(self.device.user_active)

    def test_06_idempotency_duplicate_reports(self):
        """
        Reenvio idêntico de telemetria com mesmo timestamp não duplica segundos nem cria sessões.
        """
        t0 = datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc)
        payload = {
            "session_state": "active",
            "idle_seconds": 5,
            "is_locked": False,
            "user_active": True,
            "windows_session_id": 1
        }

        # Primeiro envio
        process_device_usage_telemetry(self.device, payload, t0)
        self.device.updated_at = t0
        db.session.commit()

        # Segundo envio idêntico no mesmo timestamp
        process_device_usage_telemetry(self.device, payload, t0)
        db.session.commit()

        sessions = UsageSession.query.filter_by(device_id=self.device.id).all()
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].duration_seconds, 0)

        # Avançar 10 segundos
        t1 = t0 + timedelta(seconds=10)
        process_device_usage_telemetry(self.device, payload, t1)
        self.device.updated_at = t1
        db.session.commit()

        # Reenviar t1
        process_device_usage_telemetry(self.device, payload, t1)
        db.session.commit()

        sessions = UsageSession.query.filter_by(device_id=self.device.id).all()
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].duration_seconds, 10)

    def test_07_gap_exceeded_closes_session_and_opens_new(self):
        """
        Se o intervalo entre reports ultrapassar MAX_USAGE_GAP_SECONDS (120s),
        a sessão antiga é fechada no último timestamp confiável e uma nova sessão é iniciada.
        """
        t0 = datetime(2026, 9, 15, 9, 0, 0, tzinfo=timezone.utc)
        t_gap = datetime(2026, 9, 15, 9, 10, 0, tzinfo=timezone.utc)  # Gap de 600 segundos (10 min)

        payload = {
            "session_state": "active",
            "idle_seconds": 0,
            "is_locked": False,
            "user_active": True,
            "windows_session_id": 1
        }

        process_device_usage_telemetry(self.device, payload, t0)
        self.device.updated_at = t0
        db.session.commit()

        process_device_usage_telemetry(self.device, payload, t_gap)
        self.device.updated_at = t_gap
        db.session.commit()

        sessions = UsageSession.query.filter_by(device_id=self.device.id).order_by(UsageSession.started_at).all()
        self.assertEqual(len(sessions), 2)
        # Sessão 1 fechou em t0
        self.assertFalse(sessions[0].is_open)
        self.assertEqual(sessions[0].ended_at, t0.replace(tzinfo=None))
        # Sessão 2 começou em t_gap
        self.assertTrue(sessions[1].is_open)
        self.assertEqual(sessions[1].started_at, t_gap.replace(tzinfo=None))

    def test_08_windows_session_id_change_closes_previous(self):
        """Troca de Windows Session ID (ex: switch de usuário / RDP) encerra a sessão anterior."""
        t0 = datetime(2026, 9, 15, 8, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 9, 15, 8, 1, 0, tzinfo=timezone.utc)

        process_device_usage_telemetry(self.device, {
            "session_state": "active",
            "idle_seconds": 5,
            "is_locked": False,
            "user_active": True,
            "windows_session_id": 1
        }, t0)
        self.device.updated_at = t0
        db.session.commit()

        # Troca de sessão para ID 2
        process_device_usage_telemetry(self.device, {
            "session_state": "active",
            "idle_seconds": 0,
            "is_locked": False,
            "user_active": True,
            "windows_session_id": 2
        }, t1)
        self.device.updated_at = t1
        db.session.commit()

        sessions = UsageSession.query.filter_by(device_id=self.device.id).order_by(UsageSession.started_at).all()
        self.assertEqual(len(sessions), 2)
        self.assertFalse(sessions[0].is_open)
        self.assertEqual(sessions[0].windows_session_id, 1)
        self.assertEqual(sessions[1].windows_session_id, 2)
        self.assertEqual(self.device.windows_session_id, 2)

    def test_09_backward_compatibility_v1_4_1_legacy_agent(self):
        """
        Agente legado v1.4.1 não envia 'idle_seconds' nem 'session_state'.
        O servidor deve definir current_session_state como 'unknown' e não abrir sessões corrompidas.
        """
        t0 = datetime(2026, 9, 15, 8, 0, 0, tzinfo=timezone.utc)
        legacy_payload = {
            "computador": "WS-LEGACY",
            "cpu": 25.0,
            "ram": 45.0
        }

        process_device_usage_telemetry(self.device, legacy_payload, t0)
        db.session.commit()

        self.assertEqual(self.device.current_session_state, "unknown")
        self.assertFalse(self.device.user_active)
        # Nenhuma sessão aberta
        sessions = UsageSession.query.filter_by(device_id=self.device.id).all()
        self.assertEqual(len(sessions), 0)

    def test_10_daily_summary_reconciliation(self):
        """
        Reconciliação diária agrega sessões com precisão e calcula percentual ativo.
        """
        target_d = date(2026, 9, 15)
        t0 = datetime(2026, 9, 15, 13, 0, 0, tzinfo=timezone.utc).replace(tzinfo=None)
        t1 = datetime(2026, 9, 15, 14, 0, 0, tzinfo=timezone.utc).replace(tzinfo=None)  # 3600s active
        t2 = datetime(2026, 9, 15, 14, 30, 0, tzinfo=timezone.utc).replace(tzinfo=None)  # 1800s idle

        s1 = UsageSession(
            device_id=self.device.id,
            state="active",
            started_at=t0,
            ended_at=t1,
            duration_seconds=3600,
            is_open=False
        )
        s2 = UsageSession(
            device_id=self.device.id,
            state="idle",
            started_at=t1,
            ended_at=t2,
            duration_seconds=1800,
            is_open=False
        )
        db.session.add_all([s1, s2])
        db.session.commit()

        summary = reconcile_daily_usage_for_date(self.device.id, target_d)
        db.session.commit()

        self.assertIsNotNone(summary)
        self.assertEqual(summary.active_seconds, 3600)
        self.assertEqual(summary.idle_seconds, 1800)
        self.assertEqual(summary.locked_seconds, 0)
        self.assertEqual(summary.online_seconds, 5400)
        # 3600 / 5400 = 66.7%
        self.assertAlmostEqual(summary.active_percentage, 66.7, places=1)

    def test_11_close_stale_device_sessions_when_offline(self):
        """Dispositivos offline encerram sessões abertas via close_stale_device_sessions."""
        t0 = datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc).replace(tzinfo=None)
        self.device.updated_at = t0 - timedelta(minutes=10)
        self.device.status = "offline"

        open_session = UsageSession(
            device_id=self.device.id,
            state="active",
            started_at=self.device.updated_at - timedelta(minutes=5),
            ended_at=self.device.updated_at,
            duration_seconds=300,
            is_open=True
        )
        db.session.add(open_session)
        db.session.commit()

        closed_count = close_stale_device_sessions(offline_threshold_seconds=120)
        self.assertEqual(closed_count, 1)

        reloaded = db.session.get(UsageSession, open_session.id)
        self.assertFalse(reloaded.is_open)
        self.assertEqual(reloaded.ended_at, self.device.updated_at)

    def test_12_api_device_usage_endpoint(self):
        """Rota /api/devices/<id>/usage retorna resumo de hoje e histórico."""
        self._login_admin()

        target_d = date(2026, 9, 15)
        t0 = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc).replace(tzinfo=None)
        t1 = datetime(2026, 9, 15, 13, 0, 0, tzinfo=timezone.utc).replace(tzinfo=None)

        s = UsageSession(
            device_id=self.device.id,
            state="active",
            started_at=t0,
            ended_at=t1,
            duration_seconds=3600,
            is_open=False
        )
        db.session.add(s)
        reconcile_daily_usage_for_date(self.device.id, target_d)
        db.session.commit()

        resp = self.client.get(f"/api/devices/{self.device.id}/usage?date=2026-09-15")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertEqual(data["device_id"], self.device.id)
        self.assertEqual(data["date"], "2026-09-15")
        self.assertIn("summary", data)
        self.assertIn("timeline", data)
        self.assertIn("history", data)
        self.assertEqual(data["summary"]["active_seconds"], 3600)

    def test_13_api_settings_idle_threshold_get_and_post(self):
        """Rotas GET e POST de /api/settings/idle-threshold atualizam configuração."""
        self._login_admin()

        # GET inicial
        resp = self.client.get("/api/settings/idle-threshold")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("idle_threshold_seconds", data)

        # POST para atualizar
        resp_post = self.client.post("/api/settings/idle-threshold", json={
            "idle_threshold_seconds": 600
        })
        self.assertEqual(resp_post.status_code, 200)
        data_post = resp_post.get_json()
        self.assertEqual(data_post.get("status"), "ok")
        self.assertEqual(data_post.get("idle_threshold_seconds"), 600)

        # POST com valor inválido deve falhar (ex: < 30)
        resp_bad = self.client.post("/api/settings/idle-threshold", json={
            "idle_threshold_seconds": 10
        })
        self.assertEqual(resp_bad.status_code, 400)

    def test_14_work_hours_state_matrix_uses_sao_paulo_time(self):
        cases = [
            # UTC timestamps below map to America/Sao_Paulo local wall time.
            (datetime(2026, 9, 15, 13, 0, tzinfo=timezone.utc), "active", 0, True, "active"),       # Tue 10:00
            (datetime(2026, 9, 15, 13, 0, tzinfo=timezone.utc), "active", 300, False, "idle"),     # Tue 10:00
            (datetime(2026, 9, 15, 20, 59, tzinfo=timezone.utc), "active", 300, False, "idle"),    # Tue 17:59
            (datetime(2026, 9, 15, 21, 0, tzinfo=timezone.utc), "idle", 300, False, "off_hours"),  # Tue 18:00
            (datetime(2026, 9, 15, 21, 30, tzinfo=timezone.utc), "active", 5, True, "overtime"),   # Tue 18:30
            (datetime(2026, 9, 15, 21, 30, tzinfo=timezone.utc), "active", 600, True, "off_hours"),# Tue 18:30
            (datetime(2026, 9, 15, 10, 0, tzinfo=timezone.utc), "active", 600, False, "off_hours"),# Tue 07:00
            (datetime(2026, 9, 15, 10, 0, tzinfo=timezone.utc), "active", 5, True, "overtime"),    # Tue 07:00
            (datetime(2026, 9, 19, 13, 0, tzinfo=timezone.utc), "active", 600, False, "off_hours"),# Sat 10:00
            (datetime(2026, 9, 19, 13, 0, tzinfo=timezone.utc), "active", 5, True, "overtime"),    # Sat 10:00
        ]
        for moment, reported, idle_seconds, user_active, expected in cases:
            with self.subTest(moment=moment, expected=expected):
                self.assertEqual(
                    classify_work_activity_state(moment, reported, idle_seconds, user_active),
                    expected,
                )

    def test_15_after_hours_activity_resumes_overtime(self):
        stale = datetime(2026, 9, 15, 21, 30, tzinfo=timezone.utc)  # 18:30 local
        resumed = stale + timedelta(minutes=1)
        process_device_usage_telemetry(self.device, {
            "session_state": "idle", "idle_seconds": 600,
            "user_active": False, "windows_session_id": 1,
        }, stale)
        self.device.updated_at = stale
        db.session.commit()
        self.assertEqual(self.device.current_session_state, "off_hours")

        process_device_usage_telemetry(self.device, {
            "session_state": "active", "idle_seconds": 0,
            "user_active": True, "windows_session_id": 1,
        }, resumed)
        db.session.commit()
        self.assertEqual(self.device.current_session_state, "overtime")

    def test_16_off_hours_do_not_increase_idle_or_productivity_totals(self):
        target_d = date(2026, 9, 15)
        off_start = datetime(2026, 9, 15, 21, 0)  # 18:00 America/Sao_Paulo
        off_end = off_start + timedelta(minutes=30)
        db.session.add(UsageSession(
            device_id=self.device.id,
            state="off_hours",
            started_at=off_start,
            ended_at=off_end,
            duration_seconds=1800,
            is_open=False,
        ))
        db.session.add(UsageSession(
            device_id=self.device.id,
            state="overtime",
            started_at=off_end,
            ended_at=off_end + timedelta(minutes=15),
            duration_seconds=900,
            is_open=False,
        ))
        db.session.commit()

        summary = reconcile_daily_usage_for_date(self.device.id, target_d)
        self.assertEqual(summary.idle_seconds, 0)
        self.assertEqual(summary.active_seconds, 0)
        self.assertEqual(summary.off_hours_seconds, 1800)
        self.assertEqual(summary.overtime_seconds, 900)
        self.assertEqual(summary.online_seconds, 2700)
        self.assertEqual(summary.active_percentage, 0.0)
        serialized = summary.to_dict()
        self.assertEqual(serialized["active_work_seconds"], 0)
        self.assertEqual(serialized["idle_work_seconds"], 0)

    def test_17_idle_session_stops_at_exact_end_of_workday(self):
        before_end = datetime(2026, 9, 15, 20, 59, 30, tzinfo=timezone.utc)
        after_end = before_end + timedelta(minutes=1)
        process_device_usage_telemetry(self.device, {
            "session_state": "idle", "idle_seconds": 300,
            "user_active": False, "windows_session_id": 1,
        }, before_end)
        self.device.updated_at = before_end
        db.session.commit()

        process_device_usage_telemetry(self.device, {
            "session_state": "idle", "idle_seconds": 360,
            "user_active": False, "windows_session_id": 1,
        }, after_end)
        db.session.commit()

        sessions = UsageSession.query.filter_by(device_id=self.device.id).order_by(UsageSession.started_at).all()
        self.assertEqual([(s.state, s.duration_seconds) for s in sessions], [
            ("idle", 30),
            ("off_hours", 30),
        ])


if __name__ == "__main__":
    unittest.main()
