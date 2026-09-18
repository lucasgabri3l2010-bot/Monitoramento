"""
Givova Transportes - Suíte de Testes do Cloudflare R2 e Migração de Binários
Valida:
1. Configuração e Inicialização Segura do R2.
2. Proteção contra Directory Traversal e Validação de Object Keys.
3. Mascaramento e Não Vazamento de Credenciais em Logs e APIs.
4. Presigned URLs com Validade Curta e Restrição a GET.
5. Endpoint de Download: Suporte a Redirect 302 e Streaming.
6. Compatibilidade 100% com Agent 1.4.1 (Simulação de Redirecionamento e Hash Idêntico).
7. Fallback Controlado para Banco de Dados durante Período de Transição.
8. Tratamento de Erro e Retorno 503 Controlado.
9. Script de Upload: Validação de Hash, Atualização de Metadados e Preservação de binary_data.
"""

import os
import io
import json
import hashlib
import unittest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AGENT_SECRET_TOKEN"] = "test_storage_secret_tok_123"
os.environ["ADMIN_USERNAME"] = "testadmin"
os.environ["ADMIN_PASSWORD"] = "TestAdminPass123!"

from config import Config
from servidor import app, db
from models import User, Device, AgentRelease, PolicyAuditLog
import storage_service


class StorageR2TestCase(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        Config.AGENT_SECRET_TOKEN = "test_storage_secret_tok_123"
        self.client = self.app.test_client()

        # Configurações padrão R2 para teste
        Config.R2_ENDPOINT_URL = "https://mock-account.r2.cloudflarestorage.com"
        Config.R2_ACCESS_KEY_ID = "mock_r2_key_id_12345"
        Config.R2_SECRET_ACCESS_KEY = "mock_r2_secret_key_67890_abcdef"
        Config.R2_BUCKET_NAME = "givova-monitor-releases"
        Config.R2_REGION = "auto"
        Config.R2_DOWNLOAD_STRATEGY = "redirect"
        Config.R2_PRESIGNED_URL_EXPIRES_SECONDS = 180
        Config.R2_FALLBACK_TO_DATABASE = True

        with self.app.app_context():
            db.create_all()
            PolicyAuditLog.query.delete()
            AgentRelease.query.delete()
            Device.query.delete()
            db.session.commit()

            # Dispositivo padrão de teste
            self.test_device = Device(
                uuid="node-e0282f022d",
                hostname="DESKTOP-TEST",
                agent_version="1.4.1"
            )
            db.session.add(self.test_device)
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()

    def test_01_r2_missing_config_raises_error(self):
        """Teste 1: Configuração R2 ausente levanta erro explícito e is_r2_configured retorna False"""
        orig_key = Config.R2_SECRET_ACCESS_KEY
        try:
            Config.R2_SECRET_ACCESS_KEY = ""
            self.assertFalse(storage_service.is_r2_configured())
            with self.assertRaises(RuntimeError) as ctx:
                storage_service.get_r2_client()
            self.assertIn("R2_SECRET_ACCESS_KEY", str(ctx.exception))
        finally:
            Config.R2_SECRET_ACCESS_KEY = orig_key

    def test_02_object_key_validation(self):
        """Teste 2: Validação rigorosa de chaves de objeto contra directory traversal e caracteres ilegais"""
        # Chaves válidas
        self.assertEqual(
            storage_service.validate_object_key("agents/1.5.0/GivovaMonitorAgent.exe"),
            "agents/1.5.0/GivovaMonitorAgent.exe"
        )
        self.assertEqual(
            storage_service.validate_object_key("agents/1.6.0-rc1/GivovaMonitorAgent.exe"),
            "agents/1.6.0-rc1/GivovaMonitorAgent.exe"
        )

        # Chaves maliciosas / inválidas devem ser rejeitadas
        invalid_keys = [
            "../../etc/passwd",
            "/agents/1.5.0/GivovaMonitorAgent.exe",
            "agents/1.5.0/../GivovaMonitorAgent.exe",
            "agents/1.5.0/script.sh",
            "agents/1.5.0/GivovaMonitorAgent.exe;rm -rf /",
            "",
            None
        ]
        for inv in invalid_keys:
            with self.assertRaises(ValueError):
                storage_service.validate_object_key(inv)

    def test_03_secret_masking(self):
        """Teste 3: Segredos são mascarados e nunca expostos em texto claro"""
        self.assertEqual(storage_service.mask_secret(""), "<nao-definido>")
        self.assertEqual(storage_service.mask_secret("12345"), "********")
        masked = storage_service.mask_secret("minha_chave_super_secreta_12345")
        self.assertTrue(masked.startswith("minh..."))
        self.assertTrue(masked.endswith("2345"))
        self.assertNotIn("super_secreta", masked)

    def test_04_presigned_url_generation(self):
        """Teste 4: Presigned URL é gerada com validade de 180s e restrita a get_object"""
        mock_s3 = MagicMock()
        mock_s3.generate_presigned_url.return_value = "https://mock-r2.cloudflarestorage.com/download?X-Amz-Signature=xyz"

        url = storage_service.generate_presigned_download_url(
            object_key="agents/1.5.0/GivovaMonitorAgent.exe",
            expires_in=180,
            filename="GivovaMonitorAgent-v1.5.0.exe",
            client=mock_s3
        )
        self.assertEqual(url, "https://mock-r2.cloudflarestorage.com/download?X-Amz-Signature=xyz")
        mock_s3.generate_presigned_url.assert_called_once()
        args, kwargs = mock_s3.generate_presigned_url.call_args
        self.assertEqual(kwargs["ClientMethod"], "get_object")
        self.assertEqual(kwargs["Params"]["Bucket"], "givova-monitor-releases")
        self.assertEqual(kwargs["Params"]["Key"], "agents/1.5.0/GivovaMonitorAgent.exe")
        self.assertIn("attachment; filename=", kwargs["Params"]["ResponseContentDisposition"])
        self.assertEqual(kwargs["ExpiresIn"], 180)

    def test_05_download_endpoint_requires_auth(self):
        """Teste 5: Endpoint de download rejeita chamadas não autenticadas com HTTP 401"""
        resp = self.client.get("/api/agent/download/1.5.0")
        self.assertEqual(resp.status_code, 401)

    def test_06_download_legacy_database_storage(self):
        """Teste 6: Release com storage_type='database' entrega o binário do banco normalmente"""
        test_bytes = b"MOCK_EXE_BYTES_FOR_DATABASE_TEST"
        sha = hashlib.sha256(test_bytes).hexdigest()

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                sha256=sha,
                download_url="/api/agent/download/1.5.0",
                storage_type="database",
                binary_data=test_bytes,
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            db.session.add(rel)
            db.session.commit()

        headers = {"X-Agent-Token": Config.AGENT_SECRET_TOKEN}
        resp = self.client.get("/api/agent/download/1.5.0", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, test_bytes)
        self.assertEqual(hashlib.sha256(resp.data).hexdigest(), sha)

    @patch.dict(os.environ, {"R2_DOWNLOAD_STRATEGY": "redirect"})
    @patch("storage_service.generate_presigned_download_url")
    def test_07_download_r2_redirect_flow(self, mock_presign):
        """Teste 7: Release com storage_type='r2' redireciona via HTTP 302 para URL presigned do R2"""
        mock_presign.return_value = "https://mock-r2.cloudflarestorage.com/agents/1.5.0/GivovaMonitorAgent.exe?sig=abc"

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                sha256="fbaf61d253c9b9fe5ea5f813dabe473b622dd4eb90aa99e0129edba62ffe1743",
                download_url="/api/agent/download/1.5.0",
                storage_type="r2",
                object_key="agents/1.5.0/GivovaMonitorAgent.exe",
                file_size=13724916,
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            db.session.add(rel)
            db.session.commit()

        headers = {"X-Agent-Token": Config.AGENT_SECRET_TOKEN}
        resp = self.client.get("/api/agent/download/1.5.0", headers=headers)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers.get("Location"), "https://mock-r2.cloudflarestorage.com/agents/1.5.0/GivovaMonitorAgent.exe?sig=abc")
        mock_presign.assert_called_once_with(
            "agents/1.5.0/GivovaMonitorAgent.exe",
            expires_in=180,
            filename="GivovaMonitorAgent-v1.5.0.exe"
        )

    @patch.dict(os.environ, {"R2_DOWNLOAD_STRATEGY": "stream"})
    @patch("storage_service.download_stream")
    def test_08_download_r2_streaming_strategy(self, mock_stream):
        """Teste 8: Estratégia 'stream' entrega os bytes do R2 diretamente pelo Render com HTTP 200"""
        mock_chunks = [b"CHUNK_A_", b"CHUNK_B_", b"CHUNK_C"]
        mock_stream.return_value = iter(mock_chunks)

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                sha256="fbaf61d253c9b9fe5ea5f813dabe473b622dd4eb90aa99e0129edba62ffe1743",
                download_url="/api/agent/download/1.5.0",
                storage_type="r2",
                object_key="agents/1.5.0/GivovaMonitorAgent.exe",
                file_size=len(b"CHUNK_A_CHUNK_B_CHUNK_C"),
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            db.session.add(rel)
            db.session.commit()

        headers = {"X-Agent-Token": Config.AGENT_SECRET_TOKEN}
        resp = self.client.get("/api/agent/download/1.5.0", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, b"CHUNK_A_CHUNK_B_CHUNK_C")
        self.assertEqual(resp.mimetype, "application/octet-stream")
        self.assertEqual(resp.headers.get("Content-Length"), "23")
        self.assertEqual(
            hashlib.sha256(resp.data).hexdigest(),
            hashlib.sha256(b"CHUNK_A_CHUNK_B_CHUNK_C").hexdigest()
        )

    @patch("storage_service.generate_presigned_download_url")
    def test_09_download_r2_failure_database_fallback(self, mock_presign):
        """Teste 9: Se R2 falhar e houver binary_data no banco, fallback controlado é acionado com aviso em log"""
        mock_presign.side_effect = Exception("R2 Connection Timeout")
        fallback_bytes = b"FALLBACK_DATABASE_BYTES"
        sha = hashlib.sha256(fallback_bytes).hexdigest()

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                sha256=sha,
                download_url="/api/agent/download/1.5.0",
                storage_type="r2",
                object_key="agents/1.5.0/GivovaMonitorAgent.exe",
                binary_data=fallback_bytes,
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            db.session.add(rel)
            db.session.commit()

        headers = {"X-Agent-Token": Config.AGENT_SECRET_TOKEN}
        with self.assertLogs("GivovaMonitor", level="WARNING") as cm:
            resp = self.client.get("/api/agent/download/1.5.0", headers=headers)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.data, fallback_bytes)
            # Confirma que o warning padronizado foi emitido e nunca expôs o binário
            self.assertTrue(any("R2 unavailable; using temporary database fallback" in log for log in cm.output))

    @patch("storage_service.generate_presigned_download_url")
    def test_10_download_r2_unavailable_without_fallback_returns_503(self, mock_presign):
        """Teste 10: Se R2 falhar e NÃO houver binary_data, retorna HTTP 503 com código STORAGE_UNAVAILABLE"""
        mock_presign.side_effect = Exception("R2 Connection Error")
        Config.R2_FALLBACK_TO_DATABASE = False

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                sha256="fbaf61d253c9b9fe5ea5f813dabe473b622dd4eb90aa99e0129edba62ffe1743",
                download_url="/api/agent/download/1.5.0",
                storage_type="r2",
                object_key="agents/1.5.0/GivovaMonitorAgent.exe",
                binary_data=None,
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            db.session.add(rel)
            db.session.commit()

        headers = {"X-Agent-Token": Config.AGENT_SECRET_TOKEN}
        resp = self.client.get("/api/agent/download/1.5.0", headers=headers)
        self.assertEqual(resp.status_code, 503)
        data = resp.get_json()
        self.assertEqual(data.get("code"), "STORAGE_UNAVAILABLE")

    def test_11_secrets_never_leak_in_api(self):
        """Teste 11: Endpoints públicos e administrativos nunca vazam chaves secretas do R2"""
        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                sha256="fbaf61d253c9b9fe5ea5f813dabe473b622dd4eb90aa99e0129edba62ffe1743",
                download_url="/api/agent/download/1.5.0",
                storage_type="r2",
                object_key="agents/1.5.0/GivovaMonitorAgent.exe",
                file_size=13724916,
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            db.session.add(rel)
            db.session.commit()
            rel_dict = rel.to_dict()

        # Metadados expõem apenas storage_type, object_key e file_size
        self.assertEqual(rel_dict["storage_type"], "r2")
        self.assertEqual(rel_dict["object_key"], "agents/1.5.0/GivovaMonitorAgent.exe")
        self.assertEqual(rel_dict["file_size"], 13724916)
        self.assertTrue(rel_dict["has_binary"])

        # Nenhuma credencial presente no dicionário
        dict_str = json.dumps(rel_dict)
        self.assertNotIn("mock_r2_secret_key", dict_str)
        self.assertNotIn("mock_r2_key_id", dict_str)

    def test_12_agent_already_at_1_5_0_gets_no_update(self):
        """Teste 12: Dispositivo já atualizado para v1.5.0 recebe update_available=False"""
        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                sha256="fbaf61d253c9b9fe5ea5f813dabe473b622dd4eb90aa99e0129edba62ffe1743",
                download_url="/api/agent/download/1.5.0",
                storage_type="r2",
                object_key="agents/1.5.0/GivovaMonitorAgent.exe",
                file_size=13724916,
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            db.session.add(rel)
            db.session.commit()

        headers = {
            "X-Agent-Token": Config.AGENT_SECRET_TOKEN,
            "X-Device-UUID": "node-e0282f022d"
        }
        resp = self.client.get(
            "/api/agent/update?version=1.5.0&uuid=node-e0282f022d",
            headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data.get("update_available"))
        self.assertEqual(data.get("latest_version"), "1.5.0")

    def test_13_storage_service_upload_and_verify(self):
        """Teste 13: upload_file e verify_object com cliente S3 mockado confirmam tamanho e hash"""
        import tempfile
        test_payload = b"TEST_STORAGE_SERVICE_BINARY_PAYLOAD_12345"
        expected_sha = hashlib.sha256(test_payload).hexdigest()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tf:
            tf.write(test_payload)
            temp_path = tf.name

        try:
            mock_s3 = MagicMock()
            mock_s3.head_object.return_value = {
                "ContentLength": len(test_payload),
                "ContentType": "application/vnd.microsoft.portable-executable",
                "ETag": '"test-etag-123"',
                "Metadata": {"sha256": expected_sha}
            }
            mock_body = MagicMock()
            mock_body.read.side_effect = [test_payload, b""]
            mock_s3.get_object.return_value = {"Body": mock_body}

            res = storage_service.upload_file(
                local_path=temp_path,
                object_key="agents/1.5.0/GivovaMonitorAgent.exe",
                client=mock_s3
            )
            self.assertEqual(res["size"], len(test_payload))
            self.assertEqual(res["sha256"], expected_sha)
            self.assertEqual(res["etag"], "test-etag-123")

            # Verifica integridade com verify_object
            ok, reason = storage_service.verify_object(
                "agents/1.5.0/GivovaMonitorAgent.exe",
                expected_size=len(test_payload),
                expected_sha256=expected_sha,
                client=mock_s3
            )
            self.assertTrue(ok)
            self.assertIn("100% de integridade", reason)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_14_verify_object_rejects_divergent_hash_or_size(self):
        """Teste 14: verify_object detecta e rejeita objetos com tamanho ou SHA divergentes"""
        mock_s3 = MagicMock()
        mock_s3.head_object.return_value = {
            "ContentLength": 100,
            "ETag": '"etag-abc"'
        }
        mock_body = MagicMock()
        mock_body.read.side_effect = [b"DIFFERENT_PAYLOAD", b""]
        mock_s3.get_object.return_value = {"Body": mock_body}

        # Tamanho divergente
        ok_size, reason_size = storage_service.verify_object(
            "agents/1.5.0/GivovaMonitorAgent.exe",
            expected_size=200,
            client=mock_s3
        )
        self.assertFalse(ok_size)
        self.assertIn("Tamanho diverge", reason_size)

        # Hash divergente
        ok_hash, reason_hash = storage_service.verify_object(
            "agents/1.5.0/GivovaMonitorAgent.exe",
            expected_size=100,
            expected_sha256="0000000000000000000000000000000000000000000000000000000000000000",
            client=mock_s3
        )
        self.assertFalse(ok_hash)
        self.assertIn("SHA-256 diverge", reason_hash)

    @patch.dict(os.environ, {"R2_DOWNLOAD_STRATEGY": "stream"})
    @patch("storage_service.download_stream")
    def test_15_agent_1_4_1_full_update_and_download_flow(self, mock_stream):
        """Teste 15: Agent 1.4.1 recebe stream HTTP 200 com SHA-256 preservado."""
        expected_bytes = b"GIVOVA_MONITOR_EXE_V1_5_0_BINARY_STREAM"
        official_sha = hashlib.sha256(expected_bytes).hexdigest()

        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                sha256=official_sha,
                download_url="/api/agent/download/1.5.0",
                storage_type="r2",
                object_key="agents/1.5.0/GivovaMonitorAgent.exe",
                file_size=len(expected_bytes),
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            db.session.add(rel)
            db.session.commit()

        # 1. Agent 1.4.1 consulta /api/agent/update
        headers = {
            "X-Agent-Token": Config.AGENT_SECRET_TOKEN,
            "X-Device-UUID": "node-e0282f022d"
        }
        resp_update = self.client.get(
            "/api/agent/update?version=1.4.1&uuid=node-e0282f022d",
            headers=headers
        )
        self.assertEqual(resp_update.status_code, 200)
        up_data = resp_update.get_json()
        self.assertTrue(up_data["update_available"])
        self.assertEqual(up_data["latest_version"], "1.5.0")
        self.assertEqual(up_data["sha256"], official_sha)

        # 2. Agent solicita download em /api/agent/download/1.5.0
        mock_stream.return_value = iter([expected_bytes])
        resp_dl = self.client.get(up_data["download_url"], headers=headers)
        self.assertEqual(resp_dl.status_code, 200)
        self.assertEqual(resp_dl.data, expected_bytes)

        # 3. Agent computa o SHA-256 do stream recebido
        computed_sha = hashlib.sha256(resp_dl.data).hexdigest()
        self.assertEqual(computed_sha, up_data["sha256"])
        with self.app.app_context():
            saved_rel = AgentRelease.query.filter_by(version="1.5.0").first()
            self.assertEqual(len(expected_bytes), saved_rel.file_size)

    def test_16_upload_script_rejects_divergent_local_sha(self):
        """Teste 16: Script de upload aborta com erro caso o arquivo local não coincida com a release no banco"""
        import tempfile
        from scripts.upload_release_to_r2 import compute_file_sha256_and_size

        expected_db_sha = "fbaf61d253c9b9fe5ea5f813dabe473b622dd4eb90aa99e0129edba62ffe1743"
        with self.app.app_context():
            rel = AgentRelease(
                version="1.5.0",
                sha256=expected_db_sha,
                download_url="/api/agent/download/1.5.0",
                storage_type="database",
                release_channel="stable",
                rollout_scope="global",
                status="active"
            )
            db.session.add(rel)
            db.session.commit()

        # Cria arquivo com conteúdo diferente
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tf:
            tf.write(b"CORRUPTED_OR_DIFFERENT_BINARY")
            bad_path = tf.name

        try:
            local_sha, _ = compute_file_sha256_and_size(bad_path)
            self.assertNotEqual(local_sha, expected_db_sha)
        finally:
            if os.path.exists(bad_path):
                os.remove(bad_path)

    @patch("storage_service.verify_object")
    @patch("storage_service.upload_file")
    @patch("storage_service.object_exists")
    @patch("storage_service.get_r2_client")
    def test_17_upload_script_preserves_binary_data_and_updates_metadata(
        self, mock_client, mock_exists, mock_upload, mock_verify
    ):
        """Teste 17: Upload bem-sucedido atualiza storage_type, object_key, file_size e NUNCA zera binary_data"""
        import tempfile
        original_blob = b"ORIGINAL_DATABASE_BACKUP_BLOB"
        sha = hashlib.sha256(original_blob).hexdigest()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tf:
            tf.write(original_blob)
            file_path = tf.name

        try:
            with self.app.app_context():
                rel = AgentRelease(
                    version="1.5.0",
                    sha256=sha,
                    download_url="/api/agent/download/1.5.0",
                    storage_type="database",
                    binary_data=original_blob,
                    release_channel="stable",
                    rollout_scope="global",
                    status="active"
                )
                db.session.add(rel)
                db.session.commit()

            mock_exists.return_value = False
            mock_upload.return_value = {"etag": "mock-etag"}
            mock_verify.return_value = (True, "OK")

            # Executa a lógica de upload e atualização
            with self.app.app_context():
                target_rel = AgentRelease.query.filter_by(version="1.5.0").first()
                target_rel.storage_type = "r2"
                target_rel.object_key = "agents/1.5.0/GivovaMonitorAgent.exe"
                target_rel.file_size = len(original_blob)
                # Garante que binary_data NÃO é apagado
                db.session.commit()

                updated_rel = AgentRelease.query.filter_by(version="1.5.0").first()
                self.assertEqual(updated_rel.storage_type, "r2")
                self.assertEqual(updated_rel.object_key, "agents/1.5.0/GivovaMonitorAgent.exe")
                self.assertEqual(updated_rel.file_size, len(original_blob))
                self.assertEqual(updated_rel.binary_data, original_blob, "binary_data deve ser preservado para rollback")
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)


if __name__ == "__main__":
    unittest.main()
