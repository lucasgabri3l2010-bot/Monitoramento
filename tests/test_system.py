import os
import unittest
import json
from datetime import datetime, timezone

# Configura ambiente de teste
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AGENT_SECRET_TOKEN"] = "test_secret_token_123"
os.environ["ADMIN_USERNAME"] = "testadmin"
os.environ["ADMIN_PASSWORD"] = "TestAdminPass123!"
os.environ["OFFLINE_THRESHOLD_SECONDS"] = "10"
os.environ["CPU_ALERT_PERCENT"] = "90.0"
os.environ["RAM_ALERT_PERCENT"] = "90.0"
os.environ["DISK_ALERT_PERCENT"] = "90.0"

from servidor import app, db
from models import User, Device, Alert, MetricHistory

class SystemMonitoringTestCase(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()
            # Garante que o usuário de teste existe com a senha correta
            admin = User.query.filter_by(username="testadmin").first()
            if not admin:
                admin = User(username="testadmin", role="admin")
                admin.set_password("TestAdminPass123!")
                db.session.add(admin)
            else:
                admin.set_password("TestAdminPass123!")
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_01_health_check(self):
        """Testa o endpoint público de checagem de saúde e erro 404 seguro"""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["database"], "connected")

        # Testa tratamento de rota 404 segura para API
        res_404_api = self.client.get("/api/rota_inexistente")
        self.assertEqual(res_404_api.status_code, 404)
        self.assertEqual(res_404_api.get_json()["code"], "NOT_FOUND")


    def test_02_login_and_protected_routes(self):
        """Testa o fluxo de autenticação e proteção de rotas"""
        # Acesso anônimo ao dashboard deve redirecionar para /login
        res_anon = self.client.get("/")
        self.assertEqual(res_anon.status_code, 302)
        self.assertIn("/login", res_anon.headers["Location"])

        # Tentativa com senha errada
        res_fail = self.client.post("/login", data={"username": "testadmin", "password": "wrongpassword"})
        self.assertEqual(res_fail.status_code, 200)

        # Login correto
        res_ok = self.client.post("/login", data={"username": "testadmin", "password": "TestAdminPass123!"}, follow_redirects=True)
        self.assertEqual(res_ok.status_code, 200)

        # Acesso autenticado à rota de dados da API
        res_devices = self.client.get("/api/devices")
        self.assertEqual(res_devices.status_code, 200)

    def test_03_agent_ingest_without_and_with_token(self):
        """Testa segurança do endpoint de ingestão de métricas com token de agente"""
        payload = {
            "uuid": "test-uuid-001",
            "computador": "PC-EXPEDICAO",
            "usuario": "carlos.transporte",
            "setor": "Logística",
            "ip": "192.168.1.50",
            "os_name": "Windows 11 Pro",
            "cpu": 45.0,
            "ram": 60.0,
            "disco": 35.0,
            "ram_total_gb": 16.0,
            "ram_used_gb": 9.6,
            "disk_total_gb": 512.0,
            "disk_used_gb": 179.2,
            "uptime_seconds": 3600
        }

        # Sem token -> Deve ser rejeitado com 401
        res_no_token = self.client.post("/api/agent/report", json=payload)
        self.assertEqual(res_no_token.status_code, 401)

        # Com token inválido -> Deve ser rejeitado com 401
        res_bad_token = self.client.post(
            "/api/agent/report",
            json=payload,
            headers={"X-Agent-Token": "token_incorreto"}
        )
        self.assertEqual(res_bad_token.status_code, 401)

        # Com token correto -> Deve ser aceito com 200
        res_valid = self.client.post(
            "/api/agent/report",
            json=payload,
            headers={"X-Agent-Token": "test_secret_token_123"}
        )
        self.assertEqual(res_valid.status_code, 200)
        res_data = res_valid.get_json()
        self.assertEqual(res_data["status"], "ok")

        with self.app.app_context():
            dev = Device.query.filter_by(hostname="PC-EXPEDICAO").first()
            self.assertIsNotNone(dev)
            self.assertEqual(dev.department, "Logística")
            self.assertEqual(dev.last_cpu, 45.0)

    def test_04_alerts_generation_and_auto_resolution(self):
        """Testa detecção automática de sobrecarga e resolução de alertas"""
        # Envia métrica com sobrecarga de CPU (96%)
        overload_payload = {
            "uuid": "test-uuid-alert",
            "computador": "PC-FATURAMENTO-01",
            "setor": "Faturamento",
            "cpu": 96.0,
            "ram": 50.0,
            "disco": 40.0
        }

        res = self.client.post(
            "/api/agent/report",
            json=overload_payload,
            headers={"X-Agent-Token": "test_secret_token_123"}
        )
        self.assertEqual(res.status_code, 200)

        with self.app.app_context():
            alerts = Alert.query.filter_by(is_resolved=False).all()
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].alert_type, "cpu_high")
            self.assertEqual(alerts[0].severity, "critical")

        # Envia métrica normalizada (CPU 30%) -> Alerta deve auto-resolver
        normal_payload = {
            "uuid": "test-uuid-alert",
            "computador": "PC-FATURAMENTO-01",
            "setor": "Faturamento",
            "cpu": 30.0,
            "ram": 50.0,
            "disco": 40.0
        }

        self.client.post(
            "/api/agent/report",
            json=normal_payload,
            headers={"X-Agent-Token": "test_secret_token_123"}
        )

        with self.app.app_context():
            unresolved = Alert.query.filter_by(is_resolved=False).count()
            self.assertEqual(unresolved, 0)
            resolved = Alert.query.filter_by(is_resolved=True).count()
            self.assertEqual(resolved, 1)

    def test_05_device_edit_and_removal(self):
        """Testa edição de apelido/setor e exclusão de dispositivo"""
        # Login
        self.client.post("/login", data={"username": "testadmin", "password": "TestAdminPass123!"})

        # Cria dispositivo via agente
        payload = {
            "uuid": "test-uuid-edit",
            "computador": "PC-FINANCEIRO-01",
            "setor": "Financeiro",
            "cpu": 20.0,
            "ram": 40.0,
            "disco": 30.0
        }
        self.client.post("/api/agent/report", json=payload, headers={"X-Agent-Token": "test_secret_token_123"})

        with self.app.app_context():
            dev = Device.query.filter_by(hostname="PC-FINANCEIRO-01").first()
            dev_id = dev.id

        # Edita apelido e setor
        res_edit = self.client.post(
            f"/api/devices/{dev_id}/edit",
            json={"display_name": "Financeiro - Caixa Principal", "department": "Diretoria"}
        )
        self.assertEqual(res_edit.status_code, 200)

        with self.app.app_context():
            dev_updated = db.session.get(Device, dev_id)
            self.assertEqual(dev_updated.display_name, "Financeiro - Caixa Principal")
            self.assertEqual(dev_updated.department, "Diretoria")

        # Exclui dispositivo
        res_del = self.client.delete(f"/api/devices/{dev_id}")
        self.assertEqual(res_del.status_code, 200)

        with self.app.app_context():
            dev_deleted = db.session.get(Device, dev_id)
            self.assertIsNone(dev_deleted)

    def test_06_activity_monitoring_ingest_and_formatting(self):
        """Testa ingestão de aplicativo em primeiro plano e domínio ativo com formatação"""
        # Login
        self.client.post("/login", data={"username": "testadmin", "password": "TestAdminPass123!"})

        # 1. Envia atividade com Excel
        payload_excel = {
            "uuid": "test-uuid-activity-1",
            "computador": "PC-CONTABILIDADE",
            "setor": "Financeiro",
            "cpu": 15.0,
            "ram": 45.0,
            "disco": 30.0,
            "active_application": "Microsoft Excel",
            "active_domain": None
        }
        res1 = self.client.post("/api/agent/report", json=payload_excel, headers={"X-Agent-Token": "test_secret_token_123"})
        self.assertEqual(res1.status_code, 200)

        with self.app.app_context():
            dev = Device.query.filter_by(hostname="PC-CONTABILIDADE").first()
            self.assertIsNotNone(dev)
            self.assertEqual(dev.active_app, "Microsoft Excel")
            self.assertIsNone(dev.active_domain)
            self.assertIn("Microsoft Excel", dev.get_formatted_activity())

        # 2. Envia atividade com Google Chrome e domínio corporativo
        payload_chrome = {
            "uuid": "test-uuid-activity-2",
            "computador": "PC-OPERACIONAL",
            "setor": "Logística",
            "cpu": 25.0,
            "ram": 55.0,
            "disco": 20.0,
            "active_application": "Google Chrome",
            "active_domain": "givovatransportes.com.br"
        }
        res2 = self.client.post("/api/agent/report", json=payload_chrome, headers={"X-Agent-Token": "test_secret_token_123"})
        self.assertEqual(res2.status_code, 200)

        with self.app.app_context():
            dev2 = Device.query.filter_by(hostname="PC-OPERACIONAL").first()
            self.assertIsNotNone(dev2)
            self.assertEqual(dev2.active_app, "Google Chrome")
            self.assertEqual(dev2.active_domain, "givovatransportes.com.br")
            self.assertEqual(dev2.get_formatted_activity(), "🌐 givovatransportes.com.br")

        # 3. Consulta API de dispositivos e estatísticas do dashboard
        res_devs = self.client.get("/api/devices")
        self.assertEqual(res_devs.status_code, 200)
        devs_data = res_devs.get_json()
        target = next((d for d in devs_data if d["hostname"] == "PC-OPERACIONAL"), None)
        self.assertIsNotNone(target)
        self.assertEqual(target["active_domain"], "givovatransportes.com.br")
        self.assertEqual(target["active_activity_formatted"], "🌐 givovatransportes.com.br")

        res_stats = self.client.get("/api/stats")
        self.assertEqual(res_stats.status_code, 200)
        stats_data = res_stats.get_json()
        self.assertTrue(stats_data["activity_monitoring_enabled"])
        self.assertTrue(len(stats_data["recent_activities"]) >= 2)


if __name__ == "__main__":
    unittest.main()
