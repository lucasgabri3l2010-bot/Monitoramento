import os
import unittest
import json
import io
import hashlib
from datetime import datetime, timezone

# Setup test environment
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AGENT_SECRET_TOKEN"] = "test_canary_secret_xyz"
os.environ["ADMIN_USERNAME"] = "testadmin"
os.environ["ADMIN_PASSWORD"] = "TestAdminPass123!"

from config import Config
from servidor import app, db
from models import (
    User, Device, AgentRelease, ReleaseTargetDevice, PolicyAuditLog, compare_versions
)


class CanaryRolloutTestCase(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        Config.AGENT_SECRET_TOKEN = "test_canary_secret_xyz"
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

            # Limpa tabelas de teste
            PolicyAuditLog.query.delete()
            ReleaseTargetDevice.query.delete()
            AgentRelease.query.delete()
            Device.query.delete()
            db.session.commit()

            # Cria dispositivos para teste
            now_utc = datetime.now(timezone.utc)
            # Dispositivo 1: PC Victor (Canary target)
            self.dev_victor = Device(
                uuid="node-e0282f022d",
                hostname="DESKTOP-1E340V5",
                display_name="PC Victor - TI",
                department="TI",
                ip_address="192.168.1.100",
                agent_version="1.4.1",
                device_token="token_victor_123",
                updated_at=now_utc
            )
            # Dispositivo 2: Outro PC da frota
            self.dev_frota = Device(
                uuid="node-9988776655",
                hostname="DESKTOP-EXPED01",
                display_name="PC Expedição 01",
                department="Logística",
                ip_address="192.168.1.101",
                agent_version="1.4.1",
                device_token="token_frota_456",
                updated_at=now_utc
            )
            # Dispositivo 3: PC já atualizado
            self.dev_updated = Device(
                uuid="node-1122334455",
                hostname="DESKTOP-FIN01",
                display_name="PC Financeiro 01",
                department="Financeiro",
                ip_address="192.168.1.102",
                agent_version="1.5.0",
                device_token="token_fin_789",
                updated_at=now_utc
            )
            db.session.add_all([self.dev_victor, self.dev_frota, self.dev_updated])
            db.session.commit()

            self.dev_victor_id = self.dev_victor.id
            self.dev_frota_id = self.dev_frota.id
            self.dev_updated_id = self.dev_updated.id

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()

    def _login_admin(self):
        return self.client.post("/login", data={
            "username": "testadmin",
            "password": "TestAdminPass123!"
        }, follow_redirects=True)

    def test_01_update_check_unauthenticated_rejected(self):
        """Cenário 1: Checagem de update sem token ou com token inválido retorna 401"""
        # GET sem token
        resp_get = self.client.get("/api/agent/update?uuid=node-e0282f022d&current_version=1.4.1")
        self.assertEqual(resp_get.status_code, 401)

        # POST sem token
        resp_post = self.client.post("/api/agent/update", json={
            "uuid": "node-e0282f022d",
            "current_version": "1.4.1"
        })
        self.assertEqual(resp_post.status_code, 401)

        # Token incorreto
        resp_invalid = self.client.get(
            "/api/agent/update?uuid=node-e0282f022d&current_version=1.4.1",
            headers={"X-Agent-Token": "token_falso_errado"}
        )
        self.assertEqual(resp_invalid.status_code, 401)

    def test_02_draft_release_not_offered(self):
        """Cenário 2: Release com status='draft' nunca é distribuída para nenhum agente"""
        fake_binary = b"DRAFT_BINARY_CONTENT"
        fake_sha = hashlib.sha256(fake_binary).hexdigest()

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                download_url="/api/agent/update/download/1.5.0",
                sha256=fake_sha,
                binary_data=fake_binary,
                storage_type="database",
                release_channel="canary",
                rollout_scope="devices",
                status="draft",
                created_by="testadmin"
            )
            db.session.add(rel)
            db.session.commit()

        resp = self.client.get(
            "/api/agent/update?uuid=node-e0282f022d&current_version=1.4.1",
            headers={
                "X-Agent-Token": Config.AGENT_SECRET_TOKEN,
                "X-Device-UUID": "node-e0282f022d"
            }
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data.get("update_available"))

    def test_03_canary_release_offered_only_to_targeted_device(self):
        """Cenário 3: Release Canary ativa é oferecida com sucesso para o dispositivo alvo"""
        fake_binary = b"CANARY_BINARY_1.5.0"
        fake_sha = hashlib.sha256(fake_binary).hexdigest()

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                download_url="/api/agent/update/download/1.5.0",
                sha256=fake_sha,
                binary_data=fake_binary,
                storage_type="database",
                release_channel="canary",
                rollout_scope="devices",
                status="active",
                created_by="testadmin"
            )
            db.session.add(rel)
            db.session.flush()

            # Associa Victor como alvo Canary
            target = ReleaseTargetDevice(release_id=rel.id, device_id=self.dev_victor_id)
            db.session.add(target)
            db.session.commit()

        # Victor faz check de update
        resp = self.client.get(
            "/api/agent/update?uuid=node-e0282f022d&current_version=1.4.1",
            headers={
                "X-Agent-Token": Config.AGENT_SECRET_TOKEN,
                "X-Device-UUID": "node-e0282f022d"
            }
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("update_available"))
        self.assertEqual(data.get("version"), "1.5.0")
        self.assertEqual(data.get("sha256"), fake_sha)
        self.assertIn("/api/agent/update/download/1.5.0", data.get("download_url"))

    def test_04_canary_release_not_offered_to_non_targeted_device(self):
        """Cenário 4: Outro computador da frota recebe update_available: false em release Canary"""
        fake_binary = b"CANARY_BINARY_1.5.0"
        fake_sha = hashlib.sha256(fake_binary).hexdigest()

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                download_url="/api/agent/update/download/1.5.0",
                sha256=fake_sha,
                binary_data=fake_binary,
                storage_type="database",
                release_channel="canary",
                rollout_scope="devices",
                status="active",
                created_by="testadmin"
            )
            db.session.add(rel)
            db.session.flush()

            target = ReleaseTargetDevice(release_id=rel.id, device_id=self.dev_victor_id)
            db.session.add(target)
            db.session.commit()

        # Dispositivo da expedição faz check de update
        resp = self.client.get(
            "/api/agent/update?uuid=node-9988776655&current_version=1.4.1",
            headers={
                "X-Agent-Token": Config.AGENT_SECRET_TOKEN,
                "X-Device-UUID": "node-9988776655"
            }
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data.get("update_available"))

    def test_05_cross_device_token_spoofing_rejected(self):
        """Cenário 5: Device A token + UUID Device B NÃO pode receber Canary destinado ao Device B"""
        fake_binary = b"CANARY_BINARY_1.5.0"
        fake_sha = hashlib.sha256(fake_binary).hexdigest()

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                download_url="/api/agent/update/download/1.5.0",
                sha256=fake_sha,
                binary_data=fake_binary,
                storage_type="database",
                release_channel="canary",
                rollout_scope="devices",
                status="active",
                created_by="testadmin"
            )
            db.session.add(rel)
            db.session.flush()

            # Apenas Victor é alvo
            target = ReleaseTargetDevice(release_id=rel.id, device_id=self.dev_victor_id)
            db.session.add(target)
            db.session.commit()

        # Atacante usa Token do PC Frota (token_frota_456) mas declara UUID do Victor (node-e0282f022d)
        resp = self.client.get(
            "/api/agent/update?uuid=node-e0282f022d&current_version=1.4.1",
            headers={
                "X-Device-Token": "token_frota_456",
                "X-Device-UUID": "node-e0282f022d"
            }
        )
        data = resp.get_json() or {}
        self.assertFalse(data.get("update_available", False))

    def test_06_v1_4_1_agent_protocol_compatibility(self):
        """Cenário 6: Protocolo nativo do Agent 1.4.1 é 100% suportado e recebe resposta com campos esperados"""
        fake_binary = b"CANARY_BINARY_1.5.0"
        fake_sha = hashlib.sha256(fake_binary).hexdigest()

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                download_url="/api/agent/update/download/1.5.0",
                sha256=fake_sha,
                binary_data=fake_binary,
                storage_type="database",
                release_channel="canary",
                rollout_scope="devices",
                status="active",
                created_by="testadmin"
            )
            db.session.add(rel)
            db.session.flush()
            target = ReleaseTargetDevice(release_id=rel.id, device_id=self.dev_victor_id)
            db.session.add(target)
            db.session.commit()

        # Request idêntico ao emitido pelo agente v1.4.1 (GET com query params)
        resp = self.client.get(
            "/api/agent/update?current_version=1.4.1&channel=stable&uuid=node-e0282f022d",
            headers={
                "X-Agent-Token": Config.AGENT_SECRET_TOKEN,
                "X-Device-UUID": "node-e0282f022d",
                "User-Agent": "GivovaMonitorAgent/1.4.1"
            }
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("update_available"))
        self.assertEqual(data.get("version"), "1.5.0")
        self.assertIn("download_url", data)
        self.assertEqual(data.get("sha256"), fake_sha)
        self.assertIn("update_id", data)

        # Valida download do binário pelo endpoint
        dl_resp = self.client.get(
            f"/api/agent/update/download/1.5.0",
            headers={
                "X-Agent-Token": Config.AGENT_SECRET_TOKEN,
                "X-Device-UUID": "node-e0282f022d"
            }
        )
        self.assertEqual(dl_resp.status_code, 200)
        self.assertEqual(dl_resp.data, fake_binary)

    def test_07_deterministic_semver_candidate_selection(self):
        """Cenário 7: Comparação de versão determinística (1.10.0 > 1.9.0 e 1.10.0 > 1.9.5)"""
        self.assertEqual(compare_versions("1.10.0", "1.9.0"), 1)
        self.assertEqual(compare_versions("1.9.5", "1.10.0"), -1)
        self.assertEqual(compare_versions("1.5.0", "1.5.0"), 0)
        self.assertEqual(compare_versions("1.4.1", "1.5.0"), -1)

        fake_b1 = b"B1_9"
        fake_b2 = b"B1_10"
        with self.app.app_context():
            r1 = AgentRelease(
                version="1.9.0",
                download_url="/api/agent/update/download/1.9.0",
                sha256=hashlib.sha256(fake_b1).hexdigest(),
                binary_data=fake_b1,
                storage_type="database",
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            r2 = AgentRelease(
                version="1.10.0",
                download_url="/api/agent/update/download/1.10.0",
                sha256=hashlib.sha256(fake_b2).hexdigest(),
                binary_data=fake_b2,
                storage_type="database",
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            db.session.add_all([r1, r2])
            db.session.commit()

        # Agente em 1.9.5 deve receber 1.10.0 (mesmo que por string "1.9.5" > "1.10.0")
        resp = self.client.get(
            "/api/agent/update?uuid=node-9988776655&current_version=1.9.5",
            headers={
                "X-Agent-Token": Config.AGENT_SECRET_TOKEN,
                "X-Device-UUID": "node-9988776655"
            }
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("update_available"))
        self.assertEqual(data.get("version"), "1.10.0")

    def test_08_invariant_validation_on_publish(self):
        """Cenário 8: Invariantes estritas (canary+global e stable+devices retornam 400)"""
        self._login_admin()

        binary = b"VALID_BIN_CONTENT"
        sha = hashlib.sha256(binary).hexdigest()

        # Inválido: canary + global
        resp = self.client.post(
            "/api/admin/releases/publish",
            data={
                "version": "1.5.0",
                "release_channel": "canary",
                "rollout_scope": "global",
                "status": "active",
                "sha256": sha,
                "file": (io.BytesIO(binary), "GivovaMonitorAgent.exe")
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

        # Inválido: stable + devices
        resp2 = self.client.post(
            "/api/admin/releases/publish",
            data={
                "version": "1.5.0",
                "release_channel": "stable",
                "rollout_scope": "devices",
                "status": "active",
                "sha256": sha,
                "file": (io.BytesIO(binary), "GivovaMonitorAgent.exe")
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(resp2.status_code, 400)
        self.assertIn("error", resp2.get_json())

    def test_09_immutability_of_active_releases(self):
        """Cenário 9: Releases ativas são imutáveis (tentativa de sobrescrever binário/SHA retorna 400)"""
        self._login_admin()

        binary = b"ACTIVE_BINARY_ORIGINAL"
        sha = hashlib.sha256(binary).hexdigest()

        # Publica v1.5.0 ativo
        resp1 = self.client.post(
            "/api/admin/releases/publish",
            data={
                "version": "1.5.0",
                "release_channel": "canary",
                "rollout_scope": "devices",
                "status": "active",
                "target_device_ids": json.dumps([self.dev_victor_id]),
                "sha256": sha,
                "file": (io.BytesIO(binary), "GivovaMonitorAgent.exe")
            },
            content_type="multipart/form-data"
        )
        self.assertIn(resp1.status_code, [200, 201])

        # Tentativa de sobrescrever com binário modificado
        binary_modified = b"ACTIVE_BINARY_MODIFIED_HACK"
        sha_modified = hashlib.sha256(binary_modified).hexdigest()

        resp2 = self.client.post(
            "/api/admin/releases/publish",
            data={
                "version": "1.5.0",
                "release_channel": "canary",
                "rollout_scope": "devices",
                "status": "active",
                "sha256": sha_modified,
                "file": (io.BytesIO(binary_modified), "GivovaMonitorAgent.exe")
            },
            content_type="multipart/form-data"
        )
        self.assertEqual(resp2.status_code, 400)
        error_msg = resp2.get_json().get("error", "").lower()
        self.assertIn("imutável", error_msg)

    def test_10_promotion_preserves_sha256_and_binary(self):
        """Cenário 10: Promoção de Canary para Stable/Global preserva o exato mesmo binário e hash SHA-256"""
        self._login_admin()

        binary = b"OFFICIAL_FROZEN_BINARY_1.5.0"
        sha = hashlib.sha256(binary).hexdigest()

        resp_pub = self.client.post(
            "/api/admin/releases/publish",
            data={
                "version": "1.5.0",
                "release_channel": "canary",
                "rollout_scope": "devices",
                "status": "active",
                "target_device_ids": json.dumps([self.dev_victor_id]),
                "sha256": sha,
                "file": (io.BytesIO(binary), "GivovaMonitorAgent.exe")
            },
            content_type="multipart/form-data"
        )
        self.assertIn(resp_pub.status_code, [200, 201])
        rel_id = resp_pub.get_json()["release"]["id"]

        # Promove para Stable/Global
        resp_prom = self.client.post(f"/api/admin/releases/{rel_id}/promote")
        self.assertEqual(resp_prom.status_code, 200)
        promoted = resp_prom.get_json()["release"]

        self.assertEqual(promoted["release_channel"], "stable")
        self.assertEqual(promoted["rollout_scope"], "global")
        self.assertEqual(promoted["sha256"], sha)

        with self.app.app_context():
            db_rel = db.session.get(AgentRelease, rel_id)
            self.assertEqual(db_rel.binary_data, binary)
            self.assertEqual(db_rel.sha256, sha)

    def test_11_after_promotion_all_eligible_devices_receive_update(self):
        """Cenário 11: Após promoção global, toda a frota elegível passa a receber o update"""
        self._login_admin()

        binary = b"OFFICIAL_BINARY_1.5.0"
        sha = hashlib.sha256(binary).hexdigest()

        resp_pub = self.client.post(
            "/api/admin/releases/publish",
            data={
                "version": "1.5.0",
                "release_channel": "canary",
                "rollout_scope": "devices",
                "status": "active",
                "target_device_ids": json.dumps([self.dev_victor_id]),
                "sha256": sha,
                "file": (io.BytesIO(binary), "GivovaMonitorAgent.exe")
            },
            content_type="multipart/form-data"
        )
        rel_id = resp_pub.get_json()["release"]["id"]

        # Antes da promoção: Frota recebe update_available = false
        resp_before = self.client.get(
            "/api/agent/update?uuid=node-9988776655&current_version=1.4.1",
            headers={"X-Agent-Token": Config.AGENT_SECRET_TOKEN, "X-Device-UUID": "node-9988776655"}
        )
        self.assertFalse(resp_before.get_json()["update_available"])

        # Promove para global
        self.client.post(f"/api/admin/releases/{rel_id}/promote")

        # Depois da promoção: Frota recebe update_available = true
        resp_after = self.client.get(
            "/api/agent/update?uuid=node-9988776655&current_version=1.4.1",
            headers={"X-Agent-Token": Config.AGENT_SECRET_TOKEN, "X-Device-UUID": "node-9988776655"}
        )
        data = resp_after.get_json()
        self.assertTrue(data["update_available"])
        self.assertEqual(data["version"], "1.5.0")

    def test_12_device_already_on_target_version_receives_no_update(self):
        """Cenário 12: Dispositivo já na versão 1.5.0 recebe update_available: false (sem loop de update)"""
        binary = b"GLOBAL_BINARY_1.5.0"
        sha = hashlib.sha256(binary).hexdigest()

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                download_url="/api/agent/update/download/1.5.0",
                sha256=sha,
                binary_data=binary,
                storage_type="database",
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            db.session.add(rel)
            db.session.commit()

        # Dispositivo na v1.5.0 checa update
        resp = self.client.get(
            "/api/agent/update?uuid=node-1122334455&current_version=1.5.0",
            headers={"X-Agent-Token": Config.AGENT_SECRET_TOKEN, "X-Device-UUID": "node-1122334455"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()["update_available"])

    def test_13_paused_release_behavior(self):
        """Cenário 13: Release pausada não é oferecida a novos clientes e não faz downgrade dos já atualizados"""
        self._login_admin()

        binary = b"PAUSABLE_BINARY_1.5.0"
        sha = hashlib.sha256(binary).hexdigest()

        resp_pub = self.client.post(
            "/api/admin/releases/publish",
            data={
                "version": "1.5.0",
                "release_channel": "canary",
                "rollout_scope": "devices",
                "status": "active",
                "target_device_ids": json.dumps([self.dev_victor_id]),
                "sha256": sha,
                "file": (io.BytesIO(binary), "GivovaMonitorAgent.exe")
            },
            content_type="multipart/form-data"
        )
        rel_id = resp_pub.get_json()["release"]["id"]

        # Pausa o rollout
        resp_pause = self.client.post(f"/api/admin/releases/{rel_id}/pause")
        self.assertEqual(resp_pause.status_code, 200)
        self.assertEqual(resp_pause.get_json()["release"]["status"], "paused")

        # Victor checa update -> pausado não oferece binário
        resp_check1 = self.client.get(
            "/api/agent/update?uuid=node-e0282f022d&current_version=1.4.1",
            headers={"X-Agent-Token": Config.AGENT_SECRET_TOKEN, "X-Device-UUID": "node-e0282f022d"}
        )
        self.assertFalse(resp_check1.get_json()["update_available"])

        # Dispositivo já na v1.5.0 checa update -> sem downgrade
        resp_check2 = self.client.get(
            "/api/agent/update?uuid=node-1122334455&current_version=1.5.0",
            headers={"X-Agent-Token": Config.AGENT_SECRET_TOKEN, "X-Device-UUID": "node-1122334455"}
        )
        self.assertFalse(resp_check2.get_json()["update_available"])

        # Retoma o rollout
        resp_resume = self.client.post(f"/api/admin/releases/{rel_id}/resume")
        self.assertEqual(resp_resume.status_code, 200)
        self.assertEqual(resp_resume.get_json()["release"]["status"], "active")

        # Victor checa update novamente -> oferecido
        resp_check3 = self.client.get(
            "/api/agent/update?uuid=node-e0282f022d&current_version=1.4.1",
            headers={"X-Agent-Token": Config.AGENT_SECRET_TOKEN, "X-Device-UUID": "node-e0282f022d"}
        )
        self.assertTrue(resp_check3.get_json()["update_available"])

    def test_14_admin_required_on_all_release_endpoints(self):
        """Cenário 14: Rotas administrativas exigem autenticação de administrador"""
        endpoints = [
            ("GET", "/api/admin/releases"),
            ("POST", "/api/admin/releases/1/promote"),
            ("POST", "/api/admin/releases/1/pause"),
            ("POST", "/api/admin/releases/1/resume"),
            ("POST", "/api/admin/releases/1/targets"),
            ("GET", "/api/admin/releases/1/rollout-progress"),
        ]
        for method, ep in endpoints:
            if method == "GET":
                resp = self.client.get(ep)
            else:
                resp = self.client.post(ep, json={})
            # Deve redirecionar para /login (302) ou retornar não autorizado (401/403)
            self.assertIn(resp.status_code, [302, 401, 403], f"Falhou na rota {ep}")

    def test_15_audit_log_tracking(self):
        """Cenário 15: Operações de targets e promoção gravam auditoria em PolicyAuditLog"""
        self._login_admin()

        binary = b"AUDIT_BIN_1.5.0"
        sha = hashlib.sha256(binary).hexdigest()

        resp_pub = self.client.post(
            "/api/admin/releases/publish",
            data={
                "version": "1.5.0",
                "release_channel": "canary",
                "rollout_scope": "devices",
                "status": "active",
                "target_device_ids": json.dumps([self.dev_victor_id]),
                "sha256": sha,
                "file": (io.BytesIO(binary), "GivovaMonitorAgent.exe")
            },
            content_type="multipart/form-data"
        )
        rel_id = resp_pub.get_json()["release"]["id"]

        # Modifica alvos Canary
        resp_targets = self.client.post(
            f"/api/admin/releases/{rel_id}/targets",
            json={"device_ids": [self.dev_victor_id, self.dev_frota_id]}
        )
        self.assertEqual(resp_targets.status_code, 200)

        # Promove release
        resp_promote = self.client.post(f"/api/admin/releases/{rel_id}/promote")
        self.assertEqual(resp_promote.status_code, 200)

        # Valida logs gerados
        with self.app.app_context():
            logs = PolicyAuditLog.query.order_by(PolicyAuditLog.id.asc()).all()
            actions = [l.action for l in logs]
            self.assertIn("agent_release_canary_enabled", actions)
            self.assertIn("agent_release_targets_updated", actions)
            self.assertIn("agent_release_promoted_global", actions)


if __name__ == "__main__":
    unittest.main()
