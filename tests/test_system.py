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

from config import Config
from servidor import app, db
from models import (
    User, Device, Alert, MetricHistory,
    PolicyRule, PolicyEvent, PolicyAuditLog, AgentRelease,
    parse_semver, compare_versions, normalize_domain,
    match_domain_secure, match_application_secure
)
from services import get_active_policy_rules, invalidate_policy_rules_cache

class SystemMonitoringTestCase(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        Config.POLICY_MONITORING_ENABLED = True
        Config.ACTIVITY_MONITORING_ENABLED = True
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

            # Semeia regras corporativas padrão para os testes
            if PolicyRule.query.count() == 0:
                default_rules = [
                    PolicyRule(name="Jogos Steam", rule_type="application", pattern="steam.exe", category="Jogos", severity="warning", scope_type="global", enabled=True),
                    PolicyRule(name="Jogos Valorant", rule_type="application", pattern="valorant.exe", category="Jogos", severity="critical", scope_type="global", enabled=True),
                    PolicyRule(name="Jogos Roblox", rule_type="application", pattern="robloxplayerbeta.exe", category="Jogos", severity="warning", scope_type="global", enabled=True),
                    PolicyRule(name="Apostas Bet365", rule_type="domain", pattern="bet365.com", category="Apostas", severity="critical", scope_type="global", enabled=True),
                    PolicyRule(name="Apostas Betano", rule_type="domain", pattern="betano.com", category="Apostas", severity="critical", scope_type="global", enabled=True),
                    PolicyRule(name="Streaming Netflix", rule_type="domain", pattern="netflix.com", category="Streaming", severity="warning", scope_type="global", enabled=True),
                    PolicyRule(name="Redes Sociais Instagram", rule_type="domain", pattern="instagram.com", category="Redes Sociais", severity="warning", scope_type="global", enabled=False),
                    PolicyRule(name="Redes Sociais TikTok", rule_type="domain", pattern="tiktok.com", category="Redes Sociais", severity="warning", scope_type="global", enabled=True)
                ]
                db.session.add_all(default_rules)

            db.session.commit()
            invalidate_policy_rules_cache()

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

    def test_07_demo_mode(self):
        """Testa o Modo de Demonstração (DEMO_MODE): isolamento em memória, flags is_demo e proteção de integridade"""
        # Login
        self.client.post("/login", data={"username": "testadmin", "password": "TestAdminPass123!"})

        # Registra um computador REAL no banco
        real_payload = {
            "uuid": "real-uuid-pc-matriz",
            "computador": "PC-REAL-MATRIZ",
            "setor": "TI",
            "cpu": 22.0,
            "ram": 48.0,
            "disco": 35.0,
            "active_application": "Visual Studio Code",
            "active_domain": None
        }
        self.client.post("/api/agent/report", json=real_payload, headers={"X-Agent-Token": "test_secret_token_123"})

        # 1. Com DEMO_MODE = False (Padrão)
        Config.DEMO_MODE = False

        res_stats_off = self.client.get("/api/stats")
        self.assertEqual(res_stats_off.status_code, 200)
        stats_off = res_stats_off.get_json()
        self.assertFalse(stats_off["demo_mode_active"])
        self.assertEqual(stats_off["total_devices"], 1)

        res_devs_off = self.client.get("/api/devices")
        self.assertEqual(res_devs_off.status_code, 200)
        devs_off = res_devs_off.get_json()
        self.assertEqual(len(devs_off), 1)
        self.assertEqual(devs_off[0]["hostname"], "PC-REAL-MATRIZ")
        self.assertFalse(devs_off[0]["is_demo"])

        # 2. Habilita DEMO_MODE = True
        Config.DEMO_MODE = True
        try:
            res_stats_on = self.client.get("/api/stats")
            self.assertEqual(res_stats_on.status_code, 200)
            stats_on = res_stats_on.get_json()
            self.assertTrue(stats_on["demo_mode_active"])
            # 1 real + 9 demo = 10 dispositivos
            self.assertEqual(stats_on["total_devices"], 10)

            # Valida que todos os 6 setores solicitados estão representados
            expected_sectors = {"Logística", "Faturamento", "Financeiro", "Jurídico", "Monitoramento", "TI"}
            actual_sectors = set(stats_on["departments"].keys())
            for sec in expected_sectors:
                self.assertIn(sec, actual_sectors)

            # Valida lista de dispositivos
            res_devs_on = self.client.get("/api/devices")
            self.assertEqual(res_devs_on.status_code, 200)
            devs_on = res_devs_on.get_json()
            self.assertEqual(len(devs_on), 10)

            # Valida que o computador real NÃO tem badge/is_demo=False
            real_dev = next(d for d in devs_on if d["hostname"] == "PC-REAL-MATRIZ")
            self.assertFalse(real_dev["is_demo"])

            # Valida que os computadores de demonstração possuem is_demo=True
            demo_devs = [d for d in devs_on if d["is_demo"] is True]
            self.assertEqual(len(demo_devs), 9)

            # Consulta detalhes do dispositivo demo 90001
            res_detail = self.client.get("/api/devices/90001")
            self.assertEqual(res_detail.status_code, 200)
            demo_detail = res_detail.get_json()
            self.assertTrue(demo_detail["device"]["is_demo"])
            self.assertEqual(demo_detail["device"]["hostname"], "PC-EXPEDICAO-01")
            self.assertTrue(len(demo_detail["metrics"]) > 0)

            # Consulta histórico de métricas demo
            res_metrics = self.client.get("/api/devices/90001/metrics")
            self.assertEqual(res_metrics.status_code, 200)
            metrics_data = res_metrics.get_json()
            self.assertTrue(len(metrics_data) > 0)

            # Tenta editar dispositivo demo -> Deve ser bloqueado com 400
            res_edit_demo = self.client.post("/api/devices/90001/edit", json={"display_name": "Novo Nome"})
            self.assertEqual(res_edit_demo.status_code, 400)
            self.assertEqual(res_edit_demo.get_json()["code"], "DEMO_DEVICE_READONLY")

            # Tenta excluir dispositivo demo -> Deve ser bloqueado com 400
            res_del_demo = self.client.delete("/api/devices/90001")
            self.assertEqual(res_del_demo.status_code, 400)
            self.assertEqual(res_del_demo.get_json()["code"], "DEMO_DEVICE_READONLY")

            # Valida alertas com dados de demonstração
            res_alerts = self.client.get("/api/alerts")
            self.assertEqual(res_alerts.status_code, 200)
            alerts_list = res_alerts.get_json()
            demo_alerts = [a for a in alerts_list if a.get("is_demo")]
            self.assertTrue(len(demo_alerts) > 0)

            # Tenta resolver alerta demo -> Sucesso virtual sem erro
            res_resolve_demo = self.client.post("/api/alerts/90001/resolve")
            self.assertEqual(res_resolve_demo.status_code, 200)

            # 3. VERIFICAÇÃO CRUCIAL DE BANCO: NENHUM dado demo persistido no PostgreSQL/SQLite
            with self.app.app_context():
                # No banco deve haver APENAS 1 dispositivo (o real)
                db_device_count = Device.query.count()
                self.assertEqual(db_device_count, 1)

                # Busca nominal de máquinas demo no banco
                db_demo_device = Device.query.filter_by(hostname="PC-EXPEDICAO-01").first()
                self.assertIsNone(db_demo_device)

                # Nenhum alerta no banco
                db_alerts_count = Alert.query.count()
                self.assertEqual(db_alerts_count, 0)

        finally:
            # Restaura DEMO_MODE = False
            Config.DEMO_MODE = False

        # Valida que após desativar, os dados somem instantaneamente sem limpeza de banco
        res_after = self.client.get("/api/devices")
        self.assertEqual(len(res_after.get_json()), 1)
        self.assertEqual(res_after.get_json()[0]["hostname"], "PC-REAL-MATRIZ")

    def test_08_semantic_versioning_and_update_manifest(self):
        """Valida comparação de SemVer e consulta do manifesto de auto-update"""
        # 1. Testes de semver
        self.assertEqual(parse_semver("1.4.0"), (1, 4, 0))
        self.assertEqual(parse_semver("v2.1.3"), (2, 1, 3))
        self.assertEqual(parse_semver("invalid"), (0, 0, 0))
        self.assertGreater(compare_versions("1.4.0", "1.3.0"), 0)
        self.assertEqual(compare_versions("1.4.0", "1.4.0"), 0)
        self.assertLess(compare_versions("1.3.0", "1.4.0"), 0)
        self.assertGreater(compare_versions("2.0.0", "1.9.9"), 0)

        # 2. Requisição sem autenticação deve falhar
        res_unauth = self.client.get("/api/agent/update?agent_version=1.3.0")
        self.assertEqual(res_unauth.status_code, 401)

        # 3. Requisição com versão desatualizada (1.3.0 < 1.4.0)
        headers = {"X-Agent-Token": "test_secret_token_123"}
        res_update = self.client.get(
            "/api/agent/update?agent_version=1.3.0&uuid=uuid-update-test&hostname=PC-UPDATE-TEST",
            headers=headers
        )
        self.assertEqual(res_update.status_code, 200)
        data = res_update.get_json()
        self.assertTrue(data["update_available"])
        self.assertEqual(data["target_version"], Config.LATEST_AGENT_VERSION)
        self.assertIn("sha256", data)
        self.assertIn("download_url", data)

        # 4. Requisição com agente já atualizado (1.4.0 == 1.4.0)
        res_current = self.client.get(
            f"/api/agent/update?agent_version={Config.LATEST_AGENT_VERSION}&uuid=uuid-update-test",
            headers=headers
        )
        self.assertEqual(res_current.status_code, 200)
        data_curr = res_current.get_json()
        self.assertFalse(data_curr["update_available"])

    def test_09_download_endpoint_security_and_integrity(self):
        """Valida segurança, sanitização contra path-traversal e integridade no download do agente"""
        # 1. Sem token -> 401
        res_no_tok = self.client.get(f"/api/agent/download/{Config.LATEST_AGENT_VERSION}")
        self.assertEqual(res_no_tok.status_code, 401)

        headers = {"X-Agent-Token": "test_secret_token_123"}

        # 2. Path traversal -> Deve ser bloqueado com 400
        res_traversal = self.client.get("/api/agent/download/..%2F..%2Fconfig.py", headers=headers)
        self.assertEqual(res_traversal.status_code, 400)
        self.assertEqual(res_traversal.get_json()["code"], "INVALID_VERSION")

        # 3. Teste de download via AgentRelease no banco (estratégia primária para Render/Neon)
        test_version = "1.4.0"
        dummy_content = b"MZ\x90\x00\x03\x00\x00\x00GIVOVA_MONITOR_TEST_BINARY"
        with self.app.app_context():
            rel = AgentRelease(
                version=test_version,
                sha256="test_sha256_hash",
                download_url=f"/api/agent/download/{test_version}",
                storage_type="database",
                binary_data=dummy_content
            )
            db.session.add(rel)
            db.session.commit()

        res_dl = self.client.get(f"/api/agent/download/{test_version}", headers=headers)
        self.assertEqual(res_dl.status_code, 200)
        self.assertEqual(res_dl.data, dummy_content)
        self.assertIn("application/octet-stream", res_dl.headers.get("Content-Type", ""))
        res_dl.close()

    def test_10_corporate_policy_monitoring_and_domain_matching(self):
        """Valida matching canônico de domínios/apps, deduplicação e fechamento de ocorrências"""
        # 1. Normalização e Matching Canônico
        self.assertEqual(normalize_domain("HTTPS://WWW.BET365.COM:443/sports"), "bet365.com")
        self.assertEqual(normalize_domain("globo.com."), "globo.com")
        self.assertEqual(normalize_domain("www.uol.com.br"), "uol.com.br")

        # Subdomínios são correspondidos corretamente
        self.assertTrue(match_domain_secure("bet365.com", "bet365.com"))
        self.assertTrue(match_domain_secure("m.bet365.com", "bet365.com"))
        self.assertTrue(match_domain_secure("sports.bet365.com", "bet365.com"))

        # Proteção contra falsos positivos de substring
        self.assertFalse(match_domain_secure("notbet365.com", "bet365.com"))
        self.assertFalse(match_domain_secure("fakebet365.com", "bet365.com"))
        self.assertFalse(match_domain_secure("bet365.corporate.net", "bet365.com"))

        # Executáveis
        self.assertTrue(match_application_secure("utorrent.exe", "uTorrent.exe"))
        self.assertFalse(match_application_secure("utorrent.exe", "bittorrent.exe"))

        # 2. Ingestão com domínio que viola política corporativa (bet365.com)
        headers = {"X-Agent-Token": "test_secret_token_123"}
        payload_violation = {
            "uuid": "test-uuid-policy-01",
            "computador": "PC-POLICY-TEST",
            "usuario": "rodrigo.silva",
            "setor": "Logística",
            "ip": "192.168.1.60",
            "cpu": 20.0,
            "ram": 35.0,
            "disco": 40.0,
            "active_app": "Google Chrome",
            "active_domain": "bet365.com"
        }

        res1 = self.client.post("/api/agent/report", json=payload_violation, headers=headers)
        self.assertEqual(res1.status_code, 200)

        with self.app.app_context():
            # Deve haver 1 evento de política ativo para este dispositivo
            events = PolicyEvent.query.filter_by(status="active").all()
            self.assertEqual(len(events), 1)
            event = events[0]
            self.assertEqual(event.domain, "bet365.com")
            self.assertEqual(event.category, "Apostas")
            self.assertEqual(event.severity, "critical")

        # 3. Deduplicação: Envio subsequente da mesma violação não cria duplicata
        res2 = self.client.post("/api/agent/report", json=payload_violation, headers=headers)
        self.assertEqual(res2.status_code, 200)

        with self.app.app_context():
            events = PolicyEvent.query.filter_by(status="active").all()
            self.assertEqual(len(events), 1)

        # 4. Usuário navega para site permitido -> Ocorrência anterior deve ser fechada
        payload_compliant = payload_violation.copy()
        payload_compliant["active_domain"] = "givovatransportes.com.br"

        res3 = self.client.post("/api/agent/report", json=payload_compliant, headers=headers)
        self.assertEqual(res3.status_code, 200)

        with self.app.app_context():
            active_events = PolicyEvent.query.filter_by(status="active").all()
            self.assertEqual(len(active_events), 0)
            closed_events = PolicyEvent.query.filter_by(status="closed").all()
            self.assertEqual(len(closed_events), 1)
            self.assertIsNotNone(closed_events[0].resolved_at)

    def test_11_admin_alerts_security_and_device_authorization(self):
        """Valida que apenas terminais com is_admin_device=True conseguem consumir alertas de TI"""
        headers = {"X-Agent-Token": "test_secret_token_123"}
        uuid_normal = "uuid-normal-terminal"
        uuid_admin = "uuid-admin-terminal"

        # Registra terminal normal
        self.client.post("/api/agent/report", json={
            "uuid": uuid_normal, "computador": "PC-NORMAL", "usuario": "user", "setor": "RH", "cpu": 10.0, "ram": 10.0, "disco": 10.0
        }, headers=headers)

        # Registra terminal de TI
        self.client.post("/api/agent/report", json={
            "uuid": uuid_admin, "computador": "PC-TI-ADMIN", "usuario": "admin.ti", "setor": "TI", "cpu": 10.0, "ram": 10.0, "disco": 10.0
        }, headers=headers)

        with self.app.app_context():
            dev_admin = Device.query.filter_by(uuid=uuid_admin).first()
            dev_admin.is_admin_device = True
            db.session.commit()

        # Terminal normal tenta acessar -> 403 Forbidden
        res_forbidden = self.client.get(f"/api/agent/admin-alerts?uuid={uuid_normal}", headers=headers)
        self.assertEqual(res_forbidden.status_code, 403)
        self.assertIn(res_forbidden.get_json()["code"], ("ADMIN_DEVICE_UNAUTHORIZED", "ADMIN_DEVICE_REQUIRED"))

        # Terminal TI autorizado acessa -> 200 OK
        res_allowed = self.client.get(f"/api/agent/admin-alerts?uuid={uuid_admin}", headers=headers)
        self.assertEqual(res_allowed.status_code, 200)
        data = res_allowed.get_json()
        self.assertIn("alerts", data)

    def test_12_policy_rules_crud_and_in_memory_cache_invalidation(self):
        """Testa CRUD de regras de uso corporativo e invalidação atômica do cache em memória"""
        # Login como administrador
        self.client.post("/login", data={"username": "testadmin", "password": "TestAdminPass123!"})

        # 1. Criação de nova regra
        rule_payload = {
            "name": "Bloqueio de Poker Online",
            "rule_type": "domain",
            "pattern": "pokerstars.com",
            "category": "Jogos",
            "severity": "critical",
            "scope_type": "global"
        }
        res_create = self.client.post("/api/policies/rules", json=rule_payload)
        self.assertEqual(res_create.status_code, 201)
        created_rule = res_create.get_json()["rule"]
        rule_id = created_rule["id"]

        # Cache em memória deve refletir a nova regra imediatamente
        with self.app.app_context():
            active_rules = get_active_policy_rules()
            patterns = [r.pattern for r in active_rules]
            self.assertIn("pokerstars.com", patterns)

        # 2. Desativação rápida (toggle)
        res_toggle = self.client.post(f"/api/policies/rules/{rule_id}/toggle")
        self.assertEqual(res_toggle.status_code, 200)
        self.assertFalse(res_toggle.get_json()["enabled"])

        # Cache em memória deve ter sido invalidado e regra desativada removida
        with self.app.app_context():
            active_rules = get_active_policy_rules()
            patterns = [r.pattern for r in active_rules]
            self.assertNotIn("pokerstars.com", patterns)

        # 3. Exclusão da regra
        res_del = self.client.delete(f"/api/policies/rules/{rule_id}")
        self.assertEqual(res_del.status_code, 200)

    def test_13_demo_mode_policy_isolation(self):
        """Valida que no modo DEMO regras e ocorrências são 100% virtuais sem escrita no banco"""
        self.client.post("/login", data={"username": "testadmin", "password": "TestAdminPass123!"})

        Config.DEMO_MODE = True
        try:
            # 1. Listagem de ocorrências contém dados demo
            res_events = self.client.get("/api/policies/events")
            self.assertEqual(res_events.status_code, 200)
            events = res_events.get_json()
            demo_events = [e for e in events if e.get("is_demo") is True]
            self.assertTrue(len(demo_events) > 0)

            # 2. Tentar alterar ou excluir regras virtuais de demonstração deve ser bloqueado
            res_edit_demo = self.client.post("/api/policies/rules/9001/edit", json={"name": "Alterado"})
            self.assertEqual(res_edit_demo.status_code, 400)
            self.assertEqual(res_edit_demo.get_json()["code"], "DEMO_RULE_READONLY")

            # 3. Reconhecimento de evento demo responde com sucesso virtual
            res_ack_demo = self.client.post("/api/policies/events/9001/acknowledge")
            self.assertEqual(res_ack_demo.status_code, 200)

            # 4. Verificação de integridade no banco de dados real
            with self.app.app_context():
                db_demo_events = PolicyEvent.query.filter(PolicyEvent.id >= 9000).count()
                self.assertEqual(db_demo_events, 0)
                db_demo_rules = PolicyRule.query.filter(PolicyRule.id >= 9000).count()
                self.assertEqual(db_demo_rules, 0)
        finally:
            Config.DEMO_MODE = False


if __name__ == "__main__":
    unittest.main()

