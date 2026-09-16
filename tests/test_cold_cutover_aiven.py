"""
Givova Transportes - Testes Automatizados de Cold Cutover (Aiven + Cloudflare R2)
Simulação completa:
1. PostgreSQL/base completamente vazia.
2. Execução de migrations e bootstrap de produção.
3. Agente v1.4.1 reportando e reconstruindo o Device automaticamente.
4. Proteção contra sobrescrita de campos administrativos configurados.
5. Proteção anti-spoofing de tokens.
6. Consulta de atualização para v1.5.0.
7. Redirecionamento 302 para Cloudflare R2 com hash SHA-256 oficial preservado.
8. Report de agente v1.5.0 já atualizado.
9. Dashboard administrativo e login.
10. Políticas e telemetria UsageSession iniciando do cutover em diante.
11. Zero dados fictícios ou computadores inventados.
"""

import os
import sys
import unittest
import json
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Força ambiente isolado de teste
os.environ["FLASK_ENV"] = "testing"
os.environ["SECRET_KEY"] = "cutover_secret_key_test_12345"
os.environ["AGENT_SECRET_TOKEN"] = "givova_fleet_secret_token_cutover_2026"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "AdminPassCutover@2026!"
os.environ["R2_ENDPOINT_URL"] = "https://test-account.r2.cloudflarestorage.com"
os.environ["R2_ACCESS_KEY_ID"] = "test_r2_access_key"
os.environ["R2_SECRET_ACCESS_KEY"] = "test_r2_secret_key"
os.environ["R2_BUCKET_NAME"] = "givova-monitor-releases"
os.environ["R2_REGION"] = "auto"
os.environ["R2_DOWNLOAD_STRATEGY"] = "redirect"

from config import Config
from models import (
    db, User, Device, MetricHistory, Alert, PolicyRule, PolicyEvent,
    AgentRelease, UsageSession, DailyUsageSummary, SystemMetadata
)
from servidor import app
from migrate import run_migrations
import scripts.bootstrap_production_database as bootstrap_module


class TestColdCutoverAiven(unittest.TestCase):
    def setUp(self):
        self.test_db_path = os.path.join(BASE_DIR, "test_cutover_temp.db")
        if os.path.exists(self.test_db_path):
            try:
                os.remove(self.test_db_path)
            except Exception:
                pass

        self.db_uri = f"sqlite:///{self.test_db_path}"
        app.config["SQLALCHEMY_DATABASE_URI"] = self.db_uri
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        Config.SQLALCHEMY_DATABASE_URI = self.db_uri
        Config.AGENT_SECRET_TOKEN = "givova_fleet_secret_token_cutover_2026"
        Config.ADMIN_USERNAME = "admin"
        Config.ADMIN_PASSWORD = "AdminPassCutover@2026!"
        Config.DOMAIN_CLASSIFICATION_ENABLED = False

        self.client = app.test_client()

        with app.app_context():
            db.drop_all()
            db.create_all()
            Device.query.delete()
            MetricHistory.query.delete()
            UsageSession.query.delete()
            DailyUsageSummary.query.delete()
            Alert.query.delete()
            AgentRelease.query.delete()
            User.query.delete()
            PolicyRule.query.delete()
            PolicyEvent.query.delete()
            SystemMetadata.query.delete()
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()
        if os.path.exists(self.test_db_path):
            try:
                os.remove(self.test_db_path)
            except Exception:
                pass

    def test_01_empty_database_and_bootstrap(self):
        """1. Simula base vazia -> Executa bootstrap de produção."""
        with patch.object(bootstrap_module.storage_service, "is_r2_configured", return_value=True), \
             patch.object(bootstrap_module.storage_service, "object_exists", return_value=True), \
             patch.object(bootstrap_module.storage_service, "get_object_metadata", return_value={"size": 13724916}):
            
            success = bootstrap_module.bootstrap_database(
                db_url=self.db_uri,
                admin_user="admin",
                admin_pass="AdminPassCutover@2026!",
                verify_r2=True
            )
            self.assertTrue(success)

        with app.app_context():
            # Verifica que o admin foi criado
            admin = User.query.filter_by(username="admin").first()
            self.assertIsNotNone(admin)
            self.assertTrue(admin.check_password("AdminPassCutover@2026!"))

            # Verifica que a release 1.5.0 foi registrada com R2 global
            rel = AgentRelease.query.filter_by(version="1.5.0").first()
            self.assertIsNotNone(rel)
            self.assertEqual(rel.storage_type, "r2")
            self.assertEqual(rel.object_key, "agents/1.5.0/GivovaMonitorAgent.exe")
            self.assertEqual(rel.file_size, 13724916)
            self.assertEqual(rel.sha256, "fbaf61d253c9b9fe5ea5f813dabe473b622dd4eb90aa99e0129edba62ffe1743")
            self.assertEqual(rel.release_channel, "stable")
            self.assertEqual(rel.rollout_scope, "global")
            self.assertEqual(rel.status, "active")

            # Verifica ausência estrita de computadores ou históricos fictícios
            self.assertEqual(Device.query.count(), 0)
            self.assertEqual(MetricHistory.query.count(), 0)
            self.assertEqual(UsageSession.query.count(), 0)
            self.assertGreater(PolicyRule.query.count(), 0)

    def test_02_agent_1_4_1_reports_and_reconstructs_device(self):
        """2. Agent 1.4.1 reporta para a base vazia -> Device é criado legitimamente."""
        with patch.object(bootstrap_module.storage_service, "is_r2_configured", return_value=True):
            bootstrap_module.bootstrap_database(db_url=self.db_uri, verify_r2=False)

        headers = {
            "Content-Type": "application/json",
            "X-Agent-Token": "givova_fleet_secret_token_cutover_2026",
            "X-Device-UUID": "node-aa11bb22cc33",
            "User-Agent": "GivovaMonitorAgent/1.4.1"
        }
        payload = {
            "uuid": "node-aa11bb22cc33",
            "computador": "DESKTOP-LOGISTICA-01",
            "hostname": "DESKTOP-LOGISTICA-01",
            "usuario": "carlos.silva",
            "ip": "192.168.1.105",
            "os_name": "Windows 11 Pro",
            "os_arch": "x64",
            "processador": "Intel Core i5-11400",
            "cpu_cores": 6,
            "cpu": 25.4,
            "ram": 58.2,
            "ram_total_gb": 16.0,
            "ram_used_gb": 9.3,
            "disco": 45.0,
            "disk_total_gb": 480.0,
            "disk_used_gb": 216.0,
            "uptime_seconds": 3600,
            "active_application": "EXCEL.EXE",
            "active_domain": None,
            "agent_version": "1.4.1",
            "idle_seconds": 12.0,
            "session_state": "active",
            "user_active": True,
            "windows_session_id": 1
        }

        resp = self.client.post("/api/agent/report", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")

        with app.app_context():
            dev = Device.query.filter_by(uuid="node-aa11bb22cc33").first()
            self.assertIsNotNone(dev)
            self.assertEqual(dev.hostname, "DESKTOP-LOGISTICA-01")
            self.assertEqual(dev.display_name, "DESKTOP-LOGISTICA-01")
            self.assertEqual(dev.department, "Não informado")
            self.assertEqual(dev.user_name, "carlos.silva")
            self.assertEqual(dev.ip_address, "192.168.1.105")
            self.assertEqual(dev.agent_version, "1.4.1")
            self.assertEqual(MetricHistory.query.count(), 1)
            self.assertEqual(UsageSession.query.count(), 1)

    def test_03_protect_administrative_fields_against_agent_overwrite(self):
        """3. Campos administrativos configurados pela TI não são sobrescritos pelo agente."""
        with patch.object(bootstrap_module.storage_service, "is_r2_configured", return_value=True):
            bootstrap_module.bootstrap_database(db_url=self.db_uri, verify_r2=False)

        with app.app_context():
            dev = Device(
                uuid="node-admin-edit-test",
                hostname="PC-DIRETORIA-01",
                display_name="PC Diretor Operações",
                department="Diretoria",
                agent_version="1.4.1"
            )
            db.session.add(dev)
            db.session.commit()

        # Agente reporta com setor "Não informado" ou vazio
        headers = {
            "Content-Type": "application/json",
            "X-Agent-Token": "givova_fleet_secret_token_cutover_2026",
            "X-Device-UUID": "node-admin-edit-test",
            "User-Agent": "GivovaMonitorAgent/1.4.1"
        }
        payload = {
            "uuid": "node-admin-edit-test",
            "computador": "PC-DIRETORIA-01",
            "hostname": "PC-DIRETORIA-01",
            "usuario": "roberto",
            "setor": "TI",  # Tentativa de sobrescrever
            "display_name": "PC-DIRETORIA-01",  # Tentativa de sobrescrever
            "cpu": 10.0,
            "ram": 30.0,
            "agent_version": "1.4.1"
        }
        resp = self.client.post("/api/agent/report", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 200)

        with app.app_context():
            reloaded = Device.query.filter_by(uuid="node-admin-edit-test").first()
            self.assertEqual(reloaded.display_name, "PC Diretor Operações")
            self.assertEqual(reloaded.department, "Diretoria")

    def test_04_anti_spoofing_device_token(self):
        """4. Proteção anti-spoofing: Token individual divergente é rejeitado."""
        with patch.object(bootstrap_module.storage_service, "is_r2_configured", return_value=True):
            bootstrap_module.bootstrap_database(db_url=self.db_uri, verify_r2=False)

        with app.app_context():
            dev = Device(
                uuid="node-secure-device",
                hostname="PC-FINANCEIRO-02",
                device_token="device_secret_token_abc123"
            )
            db.session.add(dev)
            db.session.commit()

        # Tentativa de spoofing enviando token de dispositivo errado
        headers = {
            "Content-Type": "application/json",
            "X-Agent-Token": "givova_fleet_secret_token_cutover_2026",
            "X-Device-Token": "wrong_device_token_xyz999",
            "X-Device-UUID": "node-secure-device"
        }
        payload = {"uuid": "node-secure-device", "hostname": "PC-FINANCEIRO-02", "cpu": 5.0}
        resp = self.client.post("/api/agent/report", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 401)

        # Acesso legítimo com o token correto do dispositivo
        headers["X-Device-Token"] = "device_secret_token_abc123"
        resp_legit = self.client.post("/api/agent/report", json=payload, headers=headers)
        self.assertEqual(resp_legit.status_code, 200)

    def test_05_agent_queries_update_and_receives_r2_release(self):
        """5. Agent 1.4.1 consulta /api/agent/update e é direcionado para a release 1.5.0."""
        with patch.object(bootstrap_module.storage_service, "is_r2_configured", return_value=True):
            bootstrap_module.bootstrap_database(db_url=self.db_uri, verify_r2=False)

        headers = {
            "X-Agent-Token": "givova_fleet_secret_token_cutover_2026",
            "X-Device-UUID": "node-update-query-test"
        }
        params = {
            "current_version": "1.4.1",
            "uuid": "node-update-query-test"
        }
        resp = self.client.get("/api/agent/update", headers=headers, query_string=params)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertTrue(data.get("update_available"))
        self.assertEqual(data.get("target_version"), "1.5.0")
        self.assertEqual(data.get("sha256"), "fbaf61d253c9b9fe5ea5f813dabe473b622dd4eb90aa99e0129edba62ffe1743")
        self.assertIn("/api/agent/download/1.5.0", data.get("download_url"))

    def test_06_r2_download_302_redirect(self):
        """6. Download da release v1.5.0 redireciona para Cloudflare R2 via HTTP 302."""
        with patch.object(bootstrap_module.storage_service, "is_r2_configured", return_value=True):
            bootstrap_module.bootstrap_database(db_url=self.db_uri, verify_r2=False)

        presigned_target = "https://test-account.r2.cloudflarestorage.com/givova-monitor-releases/agents/1.5.0/GivovaMonitorAgent.exe?sig=123"

        with patch("storage_service.is_r2_configured", return_value=True), \
             patch("storage_service.generate_presigned_download_url", return_value=presigned_target) as mock_url:

            headers = {"X-Agent-Token": "givova_fleet_secret_token_cutover_2026"}
            resp = self.client.get("/api/agent/download/1.5.0", headers=headers)
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.headers.get("Location"), presigned_target)
            mock_url.assert_called_once()

    def test_07_agent_1_5_0_reports_up_to_date(self):
        """7. Agent v1.5.0 já atualizado reporta e é reconhecido como up_to_date."""
        with patch.object(bootstrap_module.storage_service, "is_r2_configured", return_value=True):
            bootstrap_module.bootstrap_database(db_url=self.db_uri, verify_r2=False)

        headers = {
            "Content-Type": "application/json",
            "X-Agent-Token": "givova_fleet_secret_token_cutover_2026",
            "X-Device-UUID": "node-150-test"
        }
        payload = {
            "uuid": "node-150-test",
            "computador": "PC-TI-01",
            "usuario": "victor",
            "agent_version": "1.5.0",
            "cpu": 12.0,
            "ram": 40.0
        }
        resp = self.client.post("/api/agent/report", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 200)

        # Consulta de update pelo 1.5.0 não deve oferecer atualização
        resp_upd = self.client.get("/api/agent/update", headers=headers, query_string={"current_version": "1.5.0", "uuid": "node-150-test"})
        self.assertEqual(resp_upd.status_code, 200)
        self.assertFalse(resp_upd.get_json().get("update_available", False))

    def test_08_admin_login_and_dashboard_access(self):
        """8. Login de administrador e endpoints de painel funcionam normalmente pós-cutover."""
        with patch.object(bootstrap_module.storage_service, "is_r2_configured", return_value=True):
            bootstrap_module.bootstrap_database(
                db_url=self.db_uri,
                admin_user="admin",
                admin_pass="AdminPassCutover@2026!",
                verify_r2=False
            )

        # Login admin
        login_resp = self.client.post("/login", data={
            "username": "admin",
            "password": "AdminPassCutover@2026!"
        }, follow_redirects=False)
        self.assertEqual(login_resp.status_code, 302)

        # Consulta /api/devices com sessão autenticada
        devices_resp = self.client.get("/api/devices")
        self.assertEqual(devices_resp.status_code, 200)
        self.assertIsInstance(devices_resp.get_json(), list)

        # Consulta /dados retrocompatível
        dados_resp = self.client.get("/dados")
        self.assertEqual(dados_resp.status_code, 200)
        self.assertIsInstance(dados_resp.get_json(), dict)

    def test_09_policy_and_usage_sessions_clean_collection(self):
        """9. Políticas funcionam sem crash e UsageSession coleta a partir do cutover."""
        with patch.object(bootstrap_module.storage_service, "is_r2_configured", return_value=True):
            bootstrap_module.bootstrap_database(db_url=self.db_uri, verify_r2=False)

        headers = {
            "Content-Type": "application/json",
            "X-Agent-Token": "givova_fleet_secret_token_cutover_2026",
            "X-Device-UUID": "node-session-test"
        }
        payload = {
            "uuid": "node-session-test",
            "computador": "PC-OP-01",
            "usuario": "operador",
            "agent_version": "1.5.0",
            "active_application": "chrome.exe",
            "active_domain": "google.com",
            "session_state": "active",
            "user_active": True,
            "idle_seconds": 0.0,
            "cpu": 20.0,
            "ram": 50.0
        }
        resp = self.client.post("/api/agent/report", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 200)

        with app.app_context():
            dev = Device.query.filter_by(uuid="node-session-test").first()
            self.assertIsNotNone(dev)
            self.assertEqual(dev.current_session_state, "active")
            
            sessions = UsageSession.query.filter_by(device_id=dev.id).all()
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0].state, "active")
            self.assertTrue(sessions[0].is_open)

            # Garante que nenhum histórico anterior ao cutover existe
            self.assertEqual(UsageSession.query.count(), 1)


if __name__ == "__main__":
    unittest.main()
