import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import agente
import agent_startup_repair as repair


class AgentStartupRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.install_dir = self.temp.name
        self.logger = SimpleNamespace(warning=lambda *a: None, error=lambda *a: None)

    def test_correct_task_is_idempotent_without_uac(self):
        with patch.object(repair.sys, "platform", "win32"), \
             patch.object(repair.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, \
             patch.object(repair.subprocess, "Popen") as popen:
            self.assertTrue(repair.ensure_startup_task(self.install_dir, "1.5.2", self.logger))
        self.assertEqual(run.call_count, 1)
        popen.assert_not_called()

    def test_151_to_152_requests_uac_then_repairs_existing_task(self):
        results = [SimpleNamespace(returncode=1), SimpleNamespace(returncode=0)]
        with patch.object(repair.sys, "platform", "win32"), \
             patch.object(repair.subprocess, "run", side_effect=results) as run:
            self.assertTrue(repair.ensure_startup_task(self.install_dir, "1.5.2", self.logger))
        self.assertEqual(run.call_count, 2)
        outer = base64.b64decode(run.call_args.args[0][-1]).decode("utf-16le")
        self.assertIn("-Verb RunAs", outer)
        self.assertIn("-EncodedCommand", outer)
        self.assertIn("Set-ScheduledTask", repair._REPAIR_TASK)
        self.assertIn("RestartCount 3", repair._REPAIR_TASK)
        self.assertIn("New-TimeSpan -Minutes 1", repair._REPAIR_TASK)
        self.assertIn("MultipleInstances IgnoreNew", repair._REPAIR_TASK)
        self.assertIn("Delay'].Value = 'PT45S'", repair._REPAIR_TASK)
        self.assertNotIn("Register-ScheduledTask", repair._REPAIR_TASK)

    def test_uac_denial_withholds_confirmation_and_preserves_identity(self):
        original = {"uuid": "existing-uuid", "device_token": "existing-device-token", "server_url": "https://example.test"}
        config_path = os.path.join(self.install_dir, "agent_config.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(original, handle)
        with open(os.path.join(self.install_dir, "pending_update.json"), "w", encoding="utf-8") as handle:
            json.dump({"target_version": "1.5.2", "update_id": "upd-0123456789ab"}, handle)

        results = [SimpleNamespace(returncode=1), SimpleNamespace(returncode=1)]
        with patch.object(repair.sys, "platform", "win32"), \
             patch.object(repair.subprocess, "run", side_effect=results), \
             patch.object(repair.subprocess, "Popen") as guardian:
            self.assertFalse(repair.ensure_startup_task(self.install_dir, "1.5.2", self.logger))
        guardian.assert_called_once()
        self.assertEqual(guardian.call_args.kwargs["env"]["GIVOVA_REPAIR_UPDATE_ID"], "upd-0123456789ab")
        with open(config_path, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), original)
        self.assertFalse(os.path.exists(os.path.join(self.install_dir, "update_confirmed.json")))

    def test_retry_cleanup_waits_for_byte_identical_rollback(self):
        script = repair._RETRY_AFTER_ROLLBACK
        self.assertIn("Get-FileHash -LiteralPath $current", script)
        self.assertIn("Get-FileHash -LiteralPath $previous", script)
        self.assertIn("Where-Object { $_.version -ne $version }", script)
        self.assertIn("$updateId", script)

    @unittest.skipUnless(sys.platform == "win32", "Windows PowerShell syntax")
    def test_embedded_powershell_helpers_parse(self):
        for script in (repair._READ_TASK, repair._REPAIR_TASK, repair._RETRY_AFTER_ROLLBACK):
            with self.subTest(helper=script[:30]):
                encoded = repair._encoded(script)
                parse_only = ("[ScriptBlock]::Create([Text.Encoding]::Unicode.GetString("
                              f"[Convert]::FromBase64String('{encoded}'))) | Out-Null")
                result = subprocess.run(repair._command(parse_only), timeout=15, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    @unittest.skipUnless(sys.platform == "win32", "Windows PowerShell helper")
    def test_retry_cleanup_removes_only_152_after_restored_binary(self):
        for name in ("GivovaMonitorAgent.exe", "GivovaMonitorAgent.previous.exe"):
            with open(os.path.join(self.install_dir, name), "wb") as handle:
                handle.write(b"original-1.5.1-agent")
        failed_path = os.path.join(self.install_dir, "failed_updates.json")
        with open(failed_path, "w", encoding="utf-8") as handle:
            json.dump([{"version": "1.5.2"}, {"version": "1.4.0", "reason": "keep"}], handle)
        with open(os.path.join(self.install_dir, "pending_update.json"), "w", encoding="utf-8") as handle:
            json.dump({"target_version": "1.5.2", "update_id": "upd-0123456789ab"}, handle)
        env = {"SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
               "GIVOVA_REPAIR_TARGET": self.install_dir,
               "GIVOVA_REPAIR_UPDATE_ID": "upd-0123456789ab"}
        result = subprocess.run(repair._command(repair._RETRY_AFTER_ROLLBACK),
                                env=env, timeout=15, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        with open(failed_path, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), [{"version": "1.4.0", "reason": "keep"}])

    def test_current_agent_no_longer_requires_elevated_startup_repair(self):
        self.assertEqual(agente.VERSION, "1.5.3")
        self.assertFalse(hasattr(agente, "ensure_startup_task"))

    def test_release_artifact_matches_draft_metadata_without_activation(self):
        root = Path(__file__).resolve().parents[1]
        artifact = root / "releases" / "1.5.2" / "GivovaMonitorAgent.exe"
        draft = json.loads((root / "releases" / "1.5.2" / "release.draft.json").read_text(encoding="utf-8"))
        self.assertEqual(draft["version"], "1.5.2")
        self.assertEqual(draft["status"], "draft")
        self.assertEqual(draft["file_size"], artifact.stat().st_size)
        self.assertEqual(draft["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
        self.assertEqual(json.loads((root / "releases" / "manifest.json").read_text(encoding="utf-8"))["version"], "1.5.1")


if __name__ == "__main__":
    unittest.main()
