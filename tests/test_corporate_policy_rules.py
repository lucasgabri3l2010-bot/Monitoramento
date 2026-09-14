import os
import unittest
import json
import io

# Setup test environment
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AGENT_SECRET_TOKEN"] = "test_corporate_token_xyz"
os.environ["ADMIN_USERNAME"] = "testadmin"
os.environ["ADMIN_PASSWORD"] = "TestAdminPass123!"

from config import Config
from servidor import app, db
from models import (
    User, Device, PolicyRule, PolicyEvent, PolicyAllowlist,
    SystemMetadata, normalize_domain, match_domain_secure
)
from corporate_rules_data import CORPORATE_DEFAULT_RULES
from migrate import seed_default_policy_rules, run_migrations
from services import process_agent_payload, invalidate_policy_rules_cache


class CorporatePolicyRulesTestCase(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        Config.AGENT_SECRET_TOKEN = "test_corporate_token_xyz"
        Config.POLICY_MONITORING_ENABLED = True
        Config.ACTIVITY_MONITORING_ENABLED = True
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()
            # Garante usuário admin
            admin = User.query.filter_by(username="testadmin").first()
            if not admin:
                admin = User(username="testadmin", role="admin")
                admin.set_password("TestAdminPass123!")
                db.session.add(admin)
                db.session.commit()
            
            # Limpa tabelas de políticas para testes limpos
            PolicyEvent.query.delete()
            PolicyAllowlist.query.delete()
            PolicyRule.query.delete()
            SystemMetadata.query.filter_by(key="corporate_rules_seed_version").delete()
            db.session.commit()
            invalidate_policy_rules_cache()

    def _login_admin(self):
        return self.client.post("/login", data={
            "username": "testadmin",
            "password": "TestAdminPass123!"
        }, follow_redirects=True)

    def test_01_seed_creates_over_100_rules(self):
        """Cenário 1: Seed cria mais de 100 regras corporativas organizadas por categoria"""
        self.assertGreater(len(CORPORATE_DEFAULT_RULES), 100)
        with self.app.app_context():
            seeded = seed_default_policy_rules(force=False)
            self.assertGreater(seeded, 100)
            total_rules = PolicyRule.query.count()
            self.assertGreaterEqual(total_rules, 130)

            # Valida categorias essenciais presentes
            categories = {r.category for r in PolicyRule.query.all()}
            for expected_cat in ["adult", "games", "social_media", "gambling", "streaming", "torrent", "vpn_proxy", "file_sharing", "dating"]:
                self.assertIn(expected_cat, categories)

    def test_02_seed_idempotency_and_no_resurrection(self):
        """Cenário 2: Seed é idempotente e não ressuscita regras deletadas conscientemente"""
        with self.app.app_context():
            seed_default_policy_rules(force=False)
            initial_count = PolicyRule.query.count()
            self.assertGreater(initial_count, 100)

            # Executa novamente sem force - não deve adicionar nada
            added = seed_default_policy_rules(force=False)
            self.assertEqual(added, 0)
            self.assertEqual(PolicyRule.query.count(), initial_count)

            # Admin conscientemente deleta uma regra (ex: youtube.com)
            rule = PolicyRule.query.filter_by(pattern="youtube.com").first()
            self.assertIsNotNone(rule)
            db.session.delete(rule)
            db.session.commit()
            count_after_del = PolicyRule.query.count()
            self.assertEqual(count_after_del, initial_count - 1)

            # Reinício da aplicação / nova migração não deve ressuscitar a regra deletada
            added_again = seed_default_policy_rules(force=False)
            self.assertEqual(added_again, 0)
            self.assertEqual(PolicyRule.query.count(), count_after_del)
            self.assertIsNone(PolicyRule.query.filter_by(pattern="youtube.com").first())

    def test_03_preserves_custom_admin_modifications(self):
        """Cenário 3: Seed não sobrescreve personalizações feitas por administradores"""
        with self.app.app_context():
            seed_default_policy_rules(force=False)
            rule = PolicyRule.query.filter_by(pattern="steamcommunity.com").first()
            self.assertIsNotNone(rule)
            # Admin altera severidade para critical e desativa
            rule.severity = "critical"
            rule.enabled = False
            db.session.commit()

            # Executa seed forçado com force=True
            seed_default_policy_rules(force=True)

            refreshed = PolicyRule.query.filter_by(pattern="steamcommunity.com").first()
            self.assertEqual(refreshed.severity, "critical", "Severidade alterada pelo admin deve ser preservada")
            self.assertFalse(refreshed.enabled, "Status desativado pelo admin deve ser preservado")

    def test_04_subdomain_matching(self):
        """Cenário 4: Subdomínios válidos correspondem à regra corporativa"""
        with self.app.app_context():
            # sub.pornhub.com corresponde a pornhub.com
            self.assertTrue(match_domain_secure("sub.pornhub.com", "pornhub.com"))
            self.assertTrue(match_domain_secure("m.twitch.tv", "twitch.tv"))
            self.assertTrue(match_domain_secure("api.steampowered.com", "steampowered.com"))
            self.assertTrue(match_domain_secure("web.facebook.com", "facebook.com"))

    def test_05_no_false_positives_for_substrings(self):
        """Cenário 5: Domínios com sufixos ou substrings não sofrem falsos positivos"""
        with self.app.app_context():
            # fakepornhub.com NÃO é pornhub.com
            self.assertFalse(match_domain_secure("fakepornhub.com", "pornhub.com"))
            # pornhub.com.fake.com NÃO é pornhub.com
            self.assertFalse(match_domain_secure("pornhub.com.fake.com", "pornhub.com"))
            # steamfake.org NÃO é steampowered.com
            self.assertFalse(match_domain_secure("steamfake.org", "steampowered.com"))
            # myinstagram.com NÃO é instagram.com
            self.assertFalse(match_domain_secure("myinstagram.com", "instagram.com"))

    def test_06_global_allowlist_precedence(self):
        """Cenário 6: Allowlist global tem precedência absoluta sobre regras corporativas proibidas"""
        with self.app.app_context():
            seed_default_policy_rules(force=False)
            invalidate_policy_rules_cache()

    def test_06_global_allowlist_precedence(self):
        """Cenário 6: Allowlist global tem precedência absoluta sobre regras corporativas proibidas"""
        with self.app.app_context():
            seed_default_policy_rules(force=False)
            invalidate_policy_rules_cache()

            # Adiciona youtube.com na allowlist global
            al = PolicyAllowlist(pattern="youtube.com", scope_type="global", scope_target="Todos", enabled=True)
            db.session.add(al)
            db.session.commit()

            # Agente reporta navegação no youtube.com
            payload = {
                "uuid": "pc-mkt-uuid",
                "hostname": "PC-MARKETING-01",
                "computador": "PC-MARKETING-01",
                "os": "Windows 11",
                "active_domain": "youtube.com",
                "active_app": "chrome.exe",
                "cpu_percent": 10.0,
                "ram_percent": 20.0,
                "disk_free_gb": 100.0
            }
            process_agent_payload(payload)

            # Nenhum PolicyEvent deve ser aberto para youtube.com
            events = PolicyEvent.query.filter_by(domain="youtube.com", status="active").all()
            self.assertEqual(len(events), 0)

    def test_07_department_allowlist_precedence(self):
        """Cenário 7: Allowlist por departamento libera apenas membros daquele departamento"""
        with self.app.app_context():
            seed_default_policy_rules(force=False)
            invalidate_policy_rules_cache()

            # Libera instagram.com apenas para o setor 'Marketing'
            al = PolicyAllowlist(pattern="instagram.com", scope_type="department", scope_target="Marketing", enabled=True)
            db.session.add(al)
            
            # Cria dispositivo de Marketing
            dev_mkt = Device(uuid="dev-mkt-uuid", hostname="PC-MKT-01", department="Marketing")
            # Cria dispositivo de Financeiro
            dev_fin = Device(uuid="dev-fin-uuid", hostname="PC-FIN-01", department="Financeiro")
            db.session.add_all([dev_mkt, dev_fin])
            db.session.commit()

            # Marketing acessa instagram.com -> Liberado
            process_agent_payload({
                "uuid": "dev-mkt-uuid",
                "hostname": "PC-MKT-01",
                "computador": "PC-MKT-01",
                "department": "Marketing",
                "setor": "Marketing",
                "active_domain": "instagram.com",
                "active_app": "chrome.exe"
            })
            mkt_events = PolicyEvent.query.filter_by(device_id=dev_mkt.id, status="active").all()
            self.assertEqual(len(mkt_events), 0)

            # Financeiro acessa instagram.com -> Violação registrada
            process_agent_payload({
                "uuid": "dev-fin-uuid",
                "hostname": "PC-FIN-01",
                "computador": "PC-FIN-01",
                "department": "Financeiro",
                "setor": "Financeiro",
                "active_domain": "instagram.com",
                "active_app": "chrome.exe"
            })
            fin_events = PolicyEvent.query.filter_by(device_id=dev_fin.id, status="active").all()
            self.assertEqual(len(fin_events), 1)
            self.assertEqual(fin_events[0].category, "social_media")

    def test_08_device_allowlist_precedence(self):
        """Cenário 8: Allowlist por dispositivo específico tem precedência soberana"""
        with self.app.app_context():
            seed_default_policy_rules(force=False)
            invalidate_policy_rules_cache()

            dev_esp = Device(uuid="dev-esp-uuid", hostname="PC-DEV-ESPECIAL", department="TI")
            dev_out = Device(uuid="dev-out-uuid", hostname="PC-OUTRO", department="TI")
            db.session.add_all([dev_esp, dev_out])
            db.session.commit()

            # Libera bet365.com especificamente para PC-DEV-ESPECIAL
            al = PolicyAllowlist(pattern="bet365.com", scope_type="device", scope_target="PC-DEV-ESPECIAL", enabled=True)
            db.session.add(al)
            db.session.commit()

            process_agent_payload({
                "uuid": "dev-esp-uuid",
                "hostname": "PC-DEV-ESPECIAL",
                "computador": "PC-DEV-ESPECIAL",
                "active_domain": "bet365.com",
                "active_app": "chrome.exe"
            })
            events = PolicyEvent.query.filter_by(device_id=dev_esp.id, status="active").all()
            self.assertEqual(len(events), 0)

            # Outro computador sofre violação crítica imediata
            process_agent_payload({
                "uuid": "dev-out-uuid",
                "hostname": "PC-OUTRO",
                "computador": "PC-OUTRO",
                "active_domain": "bet365.com",
                "active_app": "chrome.exe"
            })
            other_events = PolicyEvent.query.filter_by(device_id=dev_out.id, status="active").all()
            self.assertEqual(len(other_events), 1)
            self.assertEqual(other_events[0].severity, "critical")

    def test_09_to_13_category_severities(self):
        """Cenários 9 a 13: Severidade das categorias corporativas (adult=critical, gambling=critical, games=warning, social_media=warning, vpn_proxy=critical)"""
        with self.app.app_context():
            seed_default_policy_rules(force=False)
            invalidate_policy_rules_cache()

            rule_adult = PolicyRule.query.filter_by(pattern="xvideos.com").first()
            self.assertIsNotNone(rule_adult)
            self.assertEqual(rule_adult.category, "adult")
            self.assertEqual(rule_adult.severity, "critical")

            rule_gambling = PolicyRule.query.filter_by(pattern="betano.com").first()
            self.assertIsNotNone(rule_gambling)
            self.assertEqual(rule_gambling.category, "gambling")
            self.assertEqual(rule_gambling.severity, "critical")

            rule_games = PolicyRule.query.filter_by(pattern="steampowered.com").first()
            self.assertIsNotNone(rule_games)
            self.assertEqual(rule_games.category, "games")
            self.assertEqual(rule_games.severity, "warning")

            rule_social = PolicyRule.query.filter_by(pattern="tiktok.com").first()
            self.assertIsNotNone(rule_social)
            self.assertEqual(rule_social.category, "social_media")
            self.assertEqual(rule_social.severity, "warning")

            rule_vpn = PolicyRule.query.filter_by(pattern="nordvpn.com").first()
            self.assertIsNotNone(rule_vpn)
            self.assertEqual(rule_vpn.category, "vpn_proxy")
            self.assertEqual(rule_vpn.severity, "critical")

    def test_14_event_deduplication(self):
        """Cenário 14: Telemetria contínua no mesmo alvo proibido não cria eventos duplicados"""
        with self.app.app_context():
            seed_default_policy_rules(force=False)
            invalidate_policy_rules_cache()

            dev = Device(uuid="pc-repetido-uuid", hostname="PC-REPETIDO", department="TI")
            db.session.add(dev)
            db.session.commit()

            # Envia múltiplos reports consecutivos no mesmo domínio proibido
            for _ in range(5):
                process_agent_payload({
                    "uuid": "pc-repetido-uuid",
                    "hostname": "PC-REPETIDO",
                    "computador": "PC-REPETIDO",
                    "active_domain": "pornhub.com",
                    "active_app": "edge.exe"
                })

            events = PolicyEvent.query.filter_by(device_id=dev.id).all()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].status, "active")

    def test_15_closed_event_remains_in_history(self):
        """Cenário 15: Evento é encerrado quando o usuário sai do site, mas permanece salvo no histórico"""
        with self.app.app_context():
            seed_default_policy_rules(force=False)
            invalidate_policy_rules_cache()

            dev = Device(uuid="pc-historico-uuid", hostname="PC-HISTORICO", department="TI")
            db.session.add(dev)
            db.session.commit()

            # Usuário entra no site proibido
            process_agent_payload({
                "uuid": "pc-historico-uuid",
                "hostname": "PC-HISTORICO",
                "computador": "PC-HISTORICO",
                "active_domain": "twitch.tv",
                "active_app": "chrome.exe"
            })
            active_events = PolicyEvent.query.filter_by(device_id=dev.id, status="active").all()
            self.assertEqual(len(active_events), 1)
            event_id = active_events[0].id

            # Usuário sai para site neutro
            process_agent_payload({
                "uuid": "pc-historico-uuid",
                "hostname": "PC-HISTORICO",
                "computador": "PC-HISTORICO",
                "active_domain": "google.com.br",
                "active_app": "chrome.exe"
            })

            # Evento mudou para closed mas continua existindo no banco
            closed_event = db.session.get(PolicyEvent, event_id)
            self.assertEqual(closed_event.status, "closed")
            self.assertIsNotNone(closed_event.last_seen)

            # Continua visível no endpoint de listagem
            self._login_admin()
            resp = self.client.get("/api/policies/events?status=all")
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            events_list = data["items"] if isinstance(data, dict) and "items" in data else data
            ids = [e["id"] for e in events_list]
            self.assertIn(event_id, ids)

    def test_16_bulk_actions_api(self):
        """Cenário 16: API de ações em massa para regras (activate, deactivate, set_severity, set_category, delete)"""
        self._login_admin()
        with self.app.app_context():
            seed_default_policy_rules(force=False)
            invalidate_policy_rules_cache()

            rule1 = PolicyRule.query.filter_by(pattern="netflix.com").first()
            rule2 = PolicyRule.query.filter_by(pattern="disneyplus.com").first()
            ids = [rule1.id, rule2.id]

        # 1. Desativar
        res = self.client.post("/api/policies/rules/bulk-action", json={
            "rule_ids": ids,
            "action": "deactivate"
        })
        self.assertEqual(res.status_code, 200)
        with self.app.app_context():
            r1 = db.session.get(PolicyRule, ids[0])
            self.assertFalse(r1.enabled)

        # 2. Ativar
        res = self.client.post("/api/policies/rules/bulk-action", json={
            "rule_ids": ids,
            "action": "activate"
        })
        self.assertEqual(res.status_code, 200)
        with self.app.app_context():
            r1 = db.session.get(PolicyRule, ids[0])
            self.assertTrue(r1.enabled)

        # 3. Alterar severidade
        res = self.client.post("/api/policies/rules/bulk-action", json={
            "rule_ids": ids,
            "action": "set_severity",
            "value": "critical"
        })
        self.assertEqual(res.status_code, 200)
        with self.app.app_context():
            r1 = db.session.get(PolicyRule, ids[0])
            self.assertEqual(r1.severity, "critical")

        # 4. Alterar categoria
        res = self.client.post("/api/policies/rules/bulk-action", json={
            "rule_ids": ids,
            "action": "set_category",
            "value": "other"
        })
        self.assertEqual(res.status_code, 200)
        with self.app.app_context():
            r1 = db.session.get(PolicyRule, ids[0])
            self.assertEqual(r1.category, "other")

        # 5. Excluir selecionadas
        res = self.client.post("/api/policies/rules/bulk-action", json={
            "rule_ids": ids,
            "action": "delete"
        })
        self.assertEqual(res.status_code, 200)
        with self.app.app_context():
            self.assertIsNone(db.session.get(PolicyRule, ids[0]))
            self.assertIsNone(db.session.get(PolicyRule, ids[1]))

    def test_17_csv_import_api(self):
        """Cenário 17: Importação de regras em lote via CSV com validação e integridade"""
        self._login_admin()

        csv_text = (
            "domain,category,severity,action,scope\n"
            "novositeproibido1.com,adult,critical,alert,global\n"
            "jogosnovos.gg,games,warning,alert,global\n"
            "novositeproibido1.com,adult,critical,alert,global\n"  # duplicado intencional
            "invalid domain name with spaces,other,info,log,global\n"  # domínio inválido
        )

        res = self.client.post("/api/policies/rules/import-csv", json={
            "csv_content": csv_text
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["import_count"], 2)
        self.assertEqual(data["skipped_duplicates"], 1)
        self.assertGreater(len(data["errors"]), 0)

        with self.app.app_context():
            r = PolicyRule.query.filter_by(pattern="novositeproibido1.com").first()
            self.assertIsNotNone(r)
            self.assertEqual(r.category, "adult")
            self.assertEqual(r.severity, "critical")
            self.assertEqual(r.source_provider, "import")

    def test_18_demo_mode_isolation(self):
        """Cenário 18: Isolamento do DEMO_MODE - regras de demonstração (id >= 9000) não sofrem bulk-action"""
        self._login_admin()
        with self.app.app_context():
            demo_rule = PolicyRule(id=9099, name="Regra Demo Imutavel", rule_type="domain", pattern="demo.com", category="other", severity="info", scope_type="global", enabled=True)
            db.session.add(demo_rule)
            db.session.commit()

        # Tentativa de deletar regra demo via bulk action
        res = self.client.post("/api/policies/rules/bulk-action", json={
            "rule_ids": [9099],
            "action": "delete"
        })
        self.assertEqual(res.status_code, 403)

        with self.app.app_context():
            # Regra demo continua intacta
            self.assertIsNotNone(db.session.get(PolicyRule, 9099))


if __name__ == "__main__":
    unittest.main()
