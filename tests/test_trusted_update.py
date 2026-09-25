import hashlib
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import trusted_update
import updater


ROOT = pathlib.Path(__file__).resolve().parents[1]


def release(version="1.3.0", payload=b"signed-updater"):
    return {
        "version": version,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "object_key": f"updaters/{version}/GivovaMonitorUpdater.exe",
        "download_url": f"/api/agent/updater/download/{version}",
    }


class Response:
    status_code = 200
    headers = {}

    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=65536):
        yield self.payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class TrustedUpdateTests(unittest.TestCase):
    def test_updater_version_comparison_and_outdated_detection(self):
        self.assertTrue(trusted_update.is_newer("1.2.0", "1.1.0"))
        self.assertFalse(trusted_update.is_newer("1.2.0", "1.2"))
        self.assertFalse(trusted_update.is_newer("1.1.0", "1.2.0"))
        with self.assertRaises(ValueError):
            trusted_update.version_parts("../../other.exe")

    def test_only_canonical_agent_and_updater_artifacts(self):
        item = release()
        self.assertEqual(trusted_update.validate_artifact(item, "updater")[0], "1.3.0")
        for bad in (
            dict(item, object_key="other/1.3.0/payload.exe"),
            dict(item, download_url="https://other.example/payload.exe"),
            dict(item, sha256="0" * 64, version="../../1"),
        ):
            with self.assertRaises(ValueError):
                trusted_update.validate_artifact(bad, "updater")
        with self.assertRaises(ValueError):
            trusted_update.validate_artifact(item, "powershell")

    def test_hash_validation_rejects_changed_updater(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "updater.exe")
            with open(path, "wb") as handle:
                handle.write(b"tampered")
            with self.assertRaises(ValueError):
                trusted_update.verify_sha256(path, release()["sha256"])

    def test_config_override_preserves_existing_device_token(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "agent_config.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"server_url": "https://monitor.example/api/agent/report",
                           "agent_token": "existing-agent-token",
                           "device_token": "existing-device-token"}, handle)
            with patch.dict(os.environ, {"GIVOVA_CONFIG_PATH": path}):
                base, headers = trusted_update.load_update_identity(folder)
            self.assertEqual(base, "https://monitor.example")
            self.assertEqual(headers["X-Device-Token"], "existing-device-token")
            self.assertEqual(json.loads(pathlib.Path(path).read_text(encoding="utf-8"))["device_token"],
                             "existing-device-token")

    def test_signed_updater_is_staged_and_agent_update_may_continue(self):
        payload = b"signed-updater"
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(trusted_update, "verify_same_signer") as signer, \
             patch.object(trusted_update.requests, "get", return_value=Response(payload)) as get:
            path = trusted_update.stage_updater("https://monitor.example", {}, release(), folder,
                                                os.path.join(folder, "GivovaMonitorUpdater.exe"), "1.5.4")
            self.assertTrue(os.path.isfile(path))
            signer.assert_called_once()
            self.assertEqual(get.call_args.kwargs["params"], {"agent_version": "1.5.4"})
            self.assertNotIn(".tmp", path)

            with patch.object(trusted_update, "load_update_identity", return_value=("https://monitor.example", {})), \
                 patch.object(trusted_update, "fetch_updater_plan", return_value={
                     "min_updater_version": "1.3.0", "updater_release": release()}), \
                 patch.object(updater.sys, "platform", "linux"):
                selected, minimum = updater.select_approved_updater(folder, "1.5.4")
            self.assertEqual(selected, path)
            self.assertEqual(minimum, "1.3.0")
            self.assertEqual(get.call_count, 1, "validated staged updater is reused")

    def test_invalid_download_never_replaces_updater(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(trusted_update.requests, "get", return_value=Response(b"bad")), \
             patch.object(trusted_update, "verify_same_signer"):
            with self.assertRaises(ValueError):
                trusted_update.stage_updater("https://monitor.example", {}, release(), folder,
                                            "canonical.exe", "1.5.4")
            directory = os.path.join(folder, "updaters")
            self.assertEqual(os.listdir(directory), [])

    def test_recovery_migration_is_signed_idempotent_and_preserves_identity(self):
        build = (ROOT / "scripts" / "Build-TrustedMigration.ps1").read_text(encoding="utf-8")
        recovery = (ROOT / "scripts" / "Recover-Givova.ps1").read_text(encoding="utf-8")
        task = (ROOT / "scripts" / "Install-TrustedUpdaterTask.ps1").read_text(encoding="utf-8")
        for marker in ("GivovaTrustedMigration-1.5.3", "Get-AuthenticodeSignature",
                       "Set-AuthenticodeSignature", "GIVOVA_CODESIGN_THUMBPRINT",
                       "Primeiro report nao confirmado; rollback"):
            self.assertIn(marker, build)
        for marker in ("Get-AgentConfigSnapshot $configFile", "Get-OptionalSha256 $configFile",
                       "Restore-Backups $taskExists", "Restore-ConfigBackup $configBackup",
                       "GivovaMonitorAgent.previous.exe", "GivovaMonitorUpdater.previous.exe",
                       "$configSnapshot.EndpointState -eq \"Render\""):
            self.assertIn(marker, recovery)
        self.assertIn('Get-Sha256 $targetAgent', recovery)
        self.assertIn('Get-Sha256 $targetUpdater', recovery)
        self.assertNotIn('Unblock-File', build)
        self.assertIn("C:\\Program Files\\GivovaMonitorUpdate", task)
        self.assertIn("-UserId 'SYSTEM'", task)
        self.assertIn("--apply-approved-request", task)
        self.assertIn('Register-ScheduledTask', task)
        self.assertIn('Install-TrustedUpdaterTask.ps1', build)

    def test_unprivileged_launcher_queues_only_fixed_signed_artifact(self):
        with tempfile.TemporaryDirectory() as folder:
            os.makedirs(os.path.join(folder, "temp"))
            candidate = os.path.join(folder, "temp", "update_v1.5.4.exe")
            with open(candidate, "wb") as handle:
                handle.write(b"signed-agent")
            with open(os.path.join(folder, "GivovaMonitorUpdater.exe"), "wb") as handle:
                handle.write(b"signed-updater")
            with patch.object(updater, "_is_local_system", return_value=False), \
                 patch.object(updater.trusted_update, "verify_same_signer"), \
                 patch.object(updater.subprocess, "run") as task_check:
                task_check.return_value.returncode = 0
                updater._approved_request(folder, "1.5.4", candidate, "upd-123456abcdef", 123, MagicMock())
            self.assertTrue(os.path.isfile(os.path.join(folder, updater.REQUEST_FILE)))
            with self.assertRaises(ValueError):
                updater._approved_request(folder, "1.5.4", os.path.join(folder, "evil.exe"),
                                          "upd-123456abcdef", 123, None)

    def test_worker_requires_local_system_and_authorized_release(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(PermissionError):
                with patch.object(updater, "_is_local_system", return_value=False):
                    updater._worker_arguments(folder, None)

    def test_authorized_worker_copies_to_protected_staging(self):
        with tempfile.TemporaryDirectory() as folder:
            os.makedirs(os.path.join(folder, "temp"))
            source = os.path.join(folder, "temp", "update_v1.5.4.exe")
            payload = b"signed-agent"
            with open(source, "wb") as handle:
                handle.write(payload)
            with open(os.path.join(folder, updater.REQUEST_FILE), "w", encoding="utf-8") as handle:
                json.dump({"version": "1.5.4", "update_id": "upd-123456abcdef", "old_pid": 41}, handle)
            artifact = {"version": "1.5.4", "sha256": hashlib.sha256(payload).hexdigest(),
                        "object_key": "agents/1.5.4/GivovaMonitorAgent.exe",
                        "download_url": "/api/agent/download/1.5.4"}
            with patch.object(updater, "_is_local_system", return_value=True), \
                 patch.object(updater, "TRUSTED_DIR", os.path.join(folder, "protected")), \
                 patch.object(updater, "TRUSTED_UPDATER", os.path.join(folder, "protected", "GivovaMonitorUpdater.exe")), \
                 patch.object(updater.trusted_update, "load_update_identity", return_value=("https://monitor.example", {})), \
                 patch.object(updater.trusted_update, "fetch_updater_plan", return_value={"agent_artifact": artifact}), \
                 patch.object(updater.trusted_update, "verify_same_signer"):
                arguments = updater._worker_arguments(folder, MagicMock())
            protected = arguments[arguments.index("--new-exe") + 1]
            self.assertEqual(pathlib.Path(protected).read_bytes(), payload)
            self.assertFalse(os.path.exists(os.path.join(folder, updater.REQUEST_FILE)))
            self.assertIn("--task-worker", arguments)


if __name__ == "__main__":
    unittest.main()
