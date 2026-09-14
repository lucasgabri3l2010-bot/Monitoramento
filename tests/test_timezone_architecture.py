"""
Suíte de Testes Automatizados da Arquitetura de Timezone & Timestamps
Valida:
1. Conversão exata de 11:41 UTC para 08:41 em America/Sao_Paulo.
2. Serialização canônica ISO 8601 UTC com 'Z' em todos os modelos.
3. Fallbacks legados formatados no timezone corporativo.
4. Invariância de timezone no cálculo de duration_seconds.
5. Transição na virada de meia-noite (fronteira de dia civil local vs UTC).
6. Intervalo semiaberto [start_of_day_utc, start_of_next_day_utc) para consultas diárias.
7. Comparação de threshold offline puramente em UTC.
8. Serialização de Device, MetricHistory, Alert, PolicyEvent, PolicyRule, PolicyAuditLog, AgentRelease.
9. Respostas das rotas de API com timestamps ISO canônicos terminando em 'Z'.
"""

import unittest
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
import os

from config import Config
from datetime_utils import (
    utc_now, ensure_utc, to_app_timezone, format_iso_utc,
    format_local_datetime, format_local_time, start_of_local_day_utc,
    start_of_next_local_day_utc, get_local_day_range_utc, get_app_timezone
)
from models import (
    db, Device, MetricHistory, Alert, PolicyRule, PolicyEvent,
    PolicyAllowlist, DomainClassification, PolicyAuditLog, AgentRelease
)
from servidor import app


class TestTimezoneArchitecture(unittest.TestCase):

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

    def tearDown(self):
        db.session.rollback()
        self.app_ctx.pop()

    def test_01_user_reported_bug_1141_utc_is_0841_local(self):
        """
        Cenário real confirmado pelo usuário:
        Acesso ao YouTube às 08:41 no horário local de São Paulo.
        Timestamp UTC correspondente: 11:41:00Z.
        A conversão deve produzir exatamente 08:41:00 local.
        """
        utc_time = datetime(2026, 9, 14, 11, 41, 0, tzinfo=timezone.utc)

        local_dt = to_app_timezone(utc_time, "America/Sao_Paulo")
        self.assertEqual(local_dt.hour, 8)
        self.assertEqual(local_dt.minute, 41)
        self.assertEqual(local_dt.second, 0)

        # Formatação completa e parcial
        fmt_full = format_local_datetime(utc_time)
        self.assertEqual(fmt_full, "14/09/2026 08:41:00")

        fmt_time = format_local_time(utc_time)
        self.assertEqual(fmt_time, "08:41:00")

        # ISO 8601 estrito com 'Z'
        iso_str = format_iso_utc(utc_time)
        self.assertEqual(iso_str, "2026-09-14T11:41:00Z")

    def test_02_policy_event_serialization_iso_and_local(self):
        """
        Valida que PolicyEvent.to_dict() gera first_seen_iso com 'Z'
        e first_seen legado formatado em America/Sao_Paulo.
        """
        ev_utc = datetime(2026, 9, 14, 11, 41, 0)  # Naive UTC como vem do banco
        event = PolicyEvent(
            id=1,
            device_id=1,
            event_type="domain",
            category="streaming",
            severity="warning",
            domain="youtube.com",
            first_seen=ev_utc,
            last_seen=ev_utc,
            duration_seconds=120,
            status="active"
        )

        d = event.to_dict()
        # Campo ISO estrito UTC (Fonte primária)
        self.assertEqual(d["first_seen_iso"], "2026-09-14T11:41:00Z")
        self.assertEqual(d["last_seen_iso"], "2026-09-14T11:41:00Z")

        # Campo formatado legado (Horário correto de São Paulo: 08:41:00)
        self.assertEqual(d["first_seen"], "14/09/2026 08:41:00")
        self.assertEqual(d["last_seen"], "14/09/2026 08:41:00")

    def test_03_duration_seconds_timezone_invariance(self):
        """
        duration_seconds é puramente a diferença entre dois instantes UTC.
        Não pode sofrer interferência de fuso horário.
        """
        start_utc = datetime(2026, 9, 14, 11, 41, 0, tzinfo=timezone.utc)
        end_utc = datetime(2026, 9, 14, 11, 46, 30, tzinfo=timezone.utc)

        duration = int((end_utc - start_utc).total_seconds())
        self.assertEqual(duration, 330)

        # Mesmo comparando os objetos convertidos para horário local, a duração é idêntica
        start_local = to_app_timezone(start_utc)
        end_local = to_app_timezone(end_utc)
        duration_local = int((end_local - start_local).total_seconds())
        self.assertEqual(duration_local, 330)

    def test_04_midnight_boundary_utc_vs_local(self):
        """
        Na virada de meia-noite:
        00:30 em São Paulo (UTC-3) em 14/09/2026 corresponde a 03:30 UTC em 14/09/2026.
        23:30 em São Paulo em 13/09/2026 corresponde a 02:30 UTC em 14/09/2026.
        start_of_local_day_utc deve marcar 03:00:00 UTC em 14/09/2026.
        """
        ref_local_mid = datetime(2026, 9, 14, 0, 30, 0, tzinfo=ZoneInfo("America/Sao_Paulo"))
        start_utc, next_start_utc = get_local_day_range_utc(ref_local_mid)

        # Início do dia civil em UTC: 14/09/2026 às 03:00:00
        self.assertEqual(start_utc, datetime(2026, 9, 14, 3, 0, 0))
        # Início do dia civil seguinte em UTC: 15/09/2026 às 03:00:00
        self.assertEqual(next_start_utc, datetime(2026, 9, 15, 3, 0, 0))

        # Evento de 13/09 às 23:30 local (02:30 UTC do dia 14) NÃO pertence ao dia 14
        event_yesterday_utc = datetime(2026, 9, 14, 2, 30, 0)
        self.assertFalse(start_utc <= event_yesterday_utc < next_start_utc)

        # Evento de 14/09 às 00:30 local (03:30 UTC do dia 14) PERTENCE ao dia 14
        event_today_utc = datetime(2026, 9, 14, 3, 30, 0)
        self.assertTrue(start_utc <= event_today_utc < next_start_utc)

        # Evento de 14/09 às 23:45 local (02:45 UTC do dia 15) PERTENCE ao dia 14
        event_tonight_utc = datetime(2026, 9, 15, 2, 45, 0)
        self.assertTrue(start_utc <= event_tonight_utc < next_start_utc)

        # Evento de 15/09 às 00:05 local (03:05 UTC do dia 15) NÃO pertence mais ao dia 14
        event_tomorrow_utc = datetime(2026, 9, 15, 3, 5, 0)
        self.assertFalse(start_utc <= event_tomorrow_utc < next_start_utc)

    def test_05_device_and_metric_history_serialization(self):
        """
        Valida que Device.to_dict() e MetricHistory.to_dict()
        usam campos ISO com 'Z' e campos formatados no fuso local.
        """
        now_utc = datetime(2026, 9, 14, 11, 41, 0)
        device = Device(
            uuid="dev-test-tz-01",
            hostname="PC-TEST-TZ",
            updated_at=now_utc,
            activity_updated_at=now_utc,
            last_update_check=now_utc,
            active_app="Google Chrome",
            last_cpu=15.0,
            last_ram=40.0
        )
        d_dict = device.to_dict()

        # ISO estrito com 'Z'
        self.assertEqual(d_dict["ultimo_contato_iso"], "2026-09-14T11:41:00Z")
        self.assertEqual(d_dict["activity_updated_at_iso"], "2026-09-14T11:41:00Z")
        self.assertEqual(d_dict["last_update_check_iso"], "2026-09-14T11:41:00Z")

        # Fallbacks locais legados
        self.assertEqual(d_dict["ultimo_contato"], "14/09/2026 08:41:00")
        self.assertEqual(d_dict["activity_updated_at"], "08:41:00")
        self.assertEqual(d_dict["last_update_check"], "14/09/2026 08:41:00")

        # Métrica histórica
        metric = MetricHistory(
            device_id=1,
            timestamp=now_utc,
            cpu_percent=25.0,
            ram_percent=50.0,
            disk_percent=30.0
        )
        m_dict = metric.to_dict()
        self.assertEqual(m_dict["timestamp_iso"], "2026-09-14T11:41:00Z")
        self.assertEqual(m_dict["timestamp"], "08:41:00")

    def test_06_offline_threshold_pure_utc_comparison(self):
        """
        Valida que get_status() compara now UTC com last_seen UTC,
        garantindo que um dispositivo não seja marcado como offline por erro de timezone.
        """
        device = Device(uuid="dev-online-01", hostname="PC-ONLINE")
        now = utc_now()
        # Atualizado há 10 segundos
        device.updated_at = (now - timedelta(seconds=10)).replace(tzinfo=None)

        status = device.get_status(offline_threshold_seconds=30)
        self.assertEqual(status, "online")

        # Atualizado há 60 segundos
        device.updated_at = (now - timedelta(seconds=60)).replace(tzinfo=None)
        status_off = device.get_status(offline_threshold_seconds=30)
        self.assertEqual(status_off, "offline")

    def test_07_alert_and_audit_log_serialization(self):
        """
        Valida que Alert e PolicyAuditLog serializam ISO com 'Z' e horário local.
        """
        now_utc = datetime(2026, 9, 14, 11, 41, 0)
        alert = Alert(
            device_id=1,
            severity="warning",
            alert_type="cpu_high",
            message="CPU 92%",
            created_at=now_utc,
            is_resolved=True,
            resolved_at=now_utc + timedelta(minutes=5)
        )
        a_dict = alert.to_dict()
        self.assertEqual(a_dict["created_at_iso"], "2026-09-14T11:41:00Z")
        self.assertEqual(a_dict["created_at"], "14/09/2026 08:41:00")
        self.assertEqual(a_dict["resolved_at_iso"], "2026-09-14T11:46:00Z")
        self.assertEqual(a_dict["resolved_at"], "14/09/2026 08:46:00")

        audit = PolicyAuditLog(
            user_name="admin",
            action="RULE_CREATED",
            details="Nova regra youtube.com",
            created_at=now_utc
        )
        log_dict = audit.to_dict()
        self.assertEqual(log_dict["created_at_iso"], "2026-09-14T11:41:00Z")
        self.assertEqual(log_dict["created_at"], "14/09/2026 08:41:00")

    def test_08_api_endpoints_return_iso_utc_with_z(self):
        """
        Valida que /health e /health/db retornam timestamps ISO com 'Z'.
        """
        res_health = self.client.get("/health")
        self.assertEqual(res_health.status_code, 200)
        data = res_health.get_json()
        self.assertTrue(data["timestamp"].endswith("Z"))

        res_db = self.client.get("/health/db")
        self.assertEqual(res_db.status_code, 200)
        data_db = res_db.get_json()
        self.assertTrue(data_db["timestamp"].endswith("Z"))

    def test_09_ensure_utc_and_timezone_conversions(self):
        """
        Testa robustez de ensure_utc() e format_iso_utc()
        com datetimes naive, aware UTC e aware em fusos internacionais (ex: Tóquio UTC+9).
        """
        # Naive datetime
        naive = datetime(2026, 9, 14, 11, 41, 0)
        iso_from_naive = format_iso_utc(naive)
        self.assertEqual(iso_from_naive, "2026-09-14T11:41:00Z")

        # Tokyo datetime (20:41 JST = 11:41 UTC)
        tokyo_tz = ZoneInfo("Asia/Tokyo")
        tokyo_dt = datetime(2026, 9, 14, 20, 41, 0, tzinfo=tokyo_tz)
        iso_from_tokyo = format_iso_utc(tokyo_dt)
        self.assertEqual(iso_from_tokyo, "2026-09-14T11:41:00Z")

        # Conversão de Tóquio para São Paulo
        sp_from_tokyo = to_app_timezone(tokyo_dt)
        self.assertEqual(sp_from_tokyo.hour, 8)
        self.assertEqual(sp_from_tokyo.minute, 41)

    def test_10_today_violations_database_query_semi_open_interval(self):
        """
        Valida que o cálculo de today_violations via intervalo semiaberto no banco
        distingue corretamente eventos ocorridos hoje em São Paulo daqueles de ontem.
        """
        device = Device(uuid="dev-today-test", hostname="PC-TODAY-TEST")
        db.session.add(device)
        db.session.commit()

        # Data de referência: 14/09/2026 às 12:00 local (15:00 UTC)
        ref_dt = datetime(2026, 9, 14, 15, 0, 0, tzinfo=timezone.utc)
        start_utc, next_start_utc = get_local_day_range_utc(ref_dt)

        # Evento A: Ontem às 23:30 local (14/09 02:30 UTC)
        ev_yesterday = PolicyEvent(
            device_id=device.id,
            event_type="domain",
            category="adult",
            severity="critical",
            domain="adult-site.com",
            first_seen=datetime(2026, 9, 14, 2, 30, 0),
            last_seen=datetime(2026, 9, 14, 2, 35, 0),
            status="closed"
        )
        # Evento B: Hoje às 00:30 local (14/09 03:30 UTC)
        ev_today_early = PolicyEvent(
            device_id=device.id,
            event_type="domain",
            category="gambling",
            severity="critical",
            domain="bet365.com",
            first_seen=datetime(2026, 9, 14, 3, 30, 0),
            last_seen=datetime(2026, 9, 14, 3, 35, 0),
            status="active"
        )
        # Evento C: Hoje às 08:41 local (14/09 11:41 UTC)
        ev_today_youtube = PolicyEvent(
            device_id=device.id,
            event_type="domain",
            category="streaming",
            severity="warning",
            domain="youtube.com",
            first_seen=datetime(2026, 9, 14, 11, 41, 0),
            last_seen=datetime(2026, 9, 14, 11, 45, 0),
            status="active"
        )

        db.session.add_all([ev_yesterday, ev_today_early, ev_today_youtube])
        db.session.commit()

        # Query com intervalo semiaberto
        today_count = PolicyEvent.query.filter(
            PolicyEvent.first_seen >= start_utc,
            PolicyEvent.first_seen < next_start_utc
        ).count()

        # Deve encontrar exatamente os 2 eventos de hoje (B e C), ignorando o de ontem (A)
        self.assertEqual(today_count, 2)


if __name__ == "__main__":
    unittest.main()
