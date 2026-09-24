import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

import agente
import updater


class FakeResponse:
    def __init__(self, payload=None, content=b"", status_code=200):
        self.payload = payload or {}
        self.content = content
        self.status_code = status_code

    def json(self):
        return self.payload

    def iter_content(self, chunk_size=65536):
        for start in range(0, len(self.content), chunk_size):
            yield self.content[start:start + chunk_size]


class AutoUpdateShutdownTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.app_dir = self.temp_dir.name
        self.app_dir_patch = patch.object(agente, "APP_DIR", self.app_dir)
        self.app_dir_patch.start()
        self.addCleanup(self.app_dir_patch.stop)
        agente._shutdown_event.clear()
        self.addCleanup(agente._shutdown_event.clear)

    def _update_config(self):
        return {
            "server_url": "https://monitor.example/api/agent/report",
            "agent_token": "test-token",
            "device_token": None,
        }

    def test_non_elevating_monitoring_release_is_1_5_3(self):
        self.assertEqual(agente.VERSION, "1.5.3")
        self.assertFalse(hasattr(agente, "ensure_startup_task"))
        root = os.path.dirname(os.path.dirname(__file__))
        self.assertFalse(os.path.exists(os.path.join(root, "agent_startup_repair.py")))
        for name in ("agente.py", "updater.py"):
            with open(os.path.join(root, name), encoding="utf-8") as handle:
                source = handle.read().lower()
            self.assertNotIn("runas", source)
            self.assertNotIn("ensure_startup_task", source)

    def test_unpublished_1_5_3_artifact_matches_draft(self):
        release_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "releases", "1.5.3")
        with open(os.path.join(release_dir, "release.draft.json"), encoding="utf-8") as handle:
            draft = json.load(handle)
        with open(os.path.join(release_dir, "GivovaMonitorAgent.exe"), "rb") as handle:
            binary = handle.read()
        self.assertEqual(draft["version"], agente.VERSION)
        self.assertEqual(draft["status"], "draft")
        self.assertEqual(draft["file_size"], len(binary))
        self.assertEqual(draft["sha256"], hashlib.sha256(binary).hexdigest())
        self.assertEqual(draft["object_key"], "agents/1.5.3/GivovaMonitorAgent.exe")

    def _valid_update_responses(self, version="2.0.0", payload=b"new-agent-binary"):
        digest = hashlib.sha256(payload).hexdigest()
        return [
            FakeResponse({
                "update_available": True,
                "latest_version": version,
                "sha256": digest,
                "download_url": f"/api/agent/download/{version}",
            }),
            FakeResponse(content=payload),
        ]

    def test_valid_update_spawns_updater_before_global_shutdown(self):
        updater_script = os.path.join(self.app_dir, "updater.py")
        open(updater_script, "wb").close()
        process = MagicMock()
        process.poll.return_value = None
        process.pid = 5678

        with patch.object(agente.requests, "get", side_effect=self._valid_update_responses()), \
             patch.object(agente, "get_machine_uuid", return_value="device-1"), \
             patch.object(agente.os, "getpid", return_value=4321), \
             patch.object(agente, "logger"), \
             patch.object(agente.subprocess, "Popen", return_value=process) as popen:
            self.assertTrue(agente._check_and_apply_update(self._update_config()))

        self.assertTrue(agente._shutdown_event.is_set())
        cmd = popen.call_args.args[0]
        self.assertEqual(cmd[0], sys.executable)
        self.assertIn("--old-pid", cmd)
        self.assertEqual(cmd[cmd.index("--old-pid") + 1], "4321")
        self.assertIn("--new-exe", cmd)
        self.assertIn("--target-dir", cmd)
        self.assertIn("--version", cmd)
        self.assertEqual(cmd[cmd.index("--version") + 1], "2.0.0")
        self.assertIn("--update-id", cmd)
        self.assertIsNotNone(popen.call_args.kwargs["stdin"])
        self.assertTrue(popen.call_args.kwargs["close_fds"])

    def test_1_5_1_to_1_5_3_is_silent_and_preserves_identity(self):
        updater_script = os.path.join(self.app_dir, "updater.py")
        open(updater_script, "wb").close()
        config_file = os.path.join(self.app_dir, "agent_config.json")
        original_config = b'{"uuid":"existing-uuid","device_token":"existing-device-token"}'
        with open(config_file, "wb") as handle:
            handle.write(original_config)
        os.makedirs(os.path.join(self.app_dir, "logs"))
        os.makedirs(os.path.join(self.app_dir, "extension"))
        for directory in ("logs", "extension"):
            with open(os.path.join(self.app_dir, directory, "keep.txt"), "wb") as handle:
                handle.write(b"preserve")
        process = MagicMock(pid=1234)
        process.poll.return_value = None
        config = dict(self._update_config(), device_token="existing-device-token")

        with patch.object(agente, "VERSION", "1.5.1"), \
             patch.object(agente.requests, "get", side_effect=self._valid_update_responses("1.5.3")) as get, \
             patch.object(agente, "get_machine_uuid", return_value="existing-uuid"), \
             patch.object(agente.subprocess, "Popen", return_value=process) as popen:
            self.assertTrue(agente._check_and_apply_update(config))

        self.assertEqual(get.call_args_list[0].kwargs["headers"]["X-Device-UUID"], "existing-uuid")
        self.assertEqual(get.call_args_list[0].kwargs["headers"]["X-Device-Token"], "existing-device-token")
        command = popen.call_args.args[0]
        self.assertEqual(command[command.index("--version") + 1], "1.5.3")
        self.assertNotIn("runas", " ".join(command).lower())
        self.assertTrue(agente._shutdown_event.is_set())
        with open(config_file, "rb") as handle:
            self.assertEqual(handle.read(), original_config)
        for directory in ("logs", "extension"):
            with open(os.path.join(self.app_dir, directory, "keep.txt"), "rb") as handle:
                self.assertEqual(handle.read(), b"preserve")

    def test_update_worker_exits_after_requesting_process_shutdown(self):
        def apply_update(_config):
            agente.request_agent_shutdown("test")
            return True

        with patch.object(agente.random, "randint", return_value=0), \
             patch.object(agente, "_check_and_apply_update", side_effect=apply_update):
            worker = threading.Thread(target=agente._auto_update_loop, args=(self._update_config(),))
            worker.start()
            worker.join(timeout=1)

        self.assertFalse(worker.is_alive())
        self.assertTrue(agente._shutdown_event.is_set())

    def test_updater_that_exits_immediately_does_not_shutdown_agent(self):
        updater_script = os.path.join(self.app_dir, "updater.py")
        open(updater_script, "wb").close()
        process = MagicMock()
        process.poll.return_value = 1

        with patch.object(agente.requests, "get", side_effect=self._valid_update_responses()), \
             patch.object(agente, "get_machine_uuid", return_value="device-1"), \
             patch.object(agente, "logger"), \
             patch.object(agente.subprocess, "Popen", return_value=process):
            self.assertFalse(agente._check_and_apply_update(self._update_config()))

        self.assertFalse(agente._shutdown_event.is_set())

    def test_no_update_keeps_agent_running(self):
        with patch.object(agente.requests, "get", return_value=FakeResponse({"update_available": False})), \
             patch.object(agente, "get_machine_uuid", return_value="device-1"):
            self.assertIsNone(agente._check_and_apply_update(self._update_config()))

        self.assertFalse(agente._shutdown_event.is_set())

    def test_expired_or_missing_direct_download_keeps_current_agent(self):
        for status_code in (403, 404):
            with self.subTest(status_code=status_code):
                responses = self._valid_update_responses()
                responses[1] = FakeResponse(status_code=status_code)
                with patch.object(agente.requests, "get", side_effect=responses), \
                     patch.object(agente, "get_machine_uuid", return_value="device-1"), \
                     patch.object(agente.subprocess, "Popen") as popen:
                    self.assertIsNone(agente._check_and_apply_update(self._update_config()))
                popen.assert_not_called()
                self.assertFalse(agente._shutdown_event.is_set())

    def test_direct_download_timeout_keeps_current_agent(self):
        update_response = self._valid_update_responses()[0]
        with patch.object(
            agente.requests,
            "get",
            side_effect=[update_response, agente.requests.Timeout("R2 timeout")],
        ), patch.object(agente, "get_machine_uuid", return_value="device-1"), \
             patch.object(agente.subprocess, "Popen") as popen:
            self.assertIsNone(agente._check_and_apply_update(self._update_config()))

        popen.assert_not_called()
        self.assertFalse(agente._shutdown_event.is_set())

    def test_failed_version_does_not_spawn_updater(self):
        with open(os.path.join(self.app_dir, "failed_updates.json"), "w", encoding="utf-8") as f:
            json.dump([{"version": "2.0.0"}], f)

        response = FakeResponse({
            "update_available": True,
            "latest_version": "2.0.0",
            "download_url": "/api/agent/download/2.0.0",
        })
        with patch.object(agente.requests, "get", return_value=response), \
             patch.object(agente, "get_machine_uuid", return_value="device-1"), \
             patch.object(agente.subprocess, "Popen") as popen:
            self.assertIsNone(agente._check_and_apply_update(self._update_config()))

        popen.assert_not_called()
        self.assertFalse(agente._shutdown_event.is_set())

    def test_healthy_agent_confirms_matching_pending_update(self):
        pending_file = os.path.join(self.app_dir, "pending_update.json")
        with open(pending_file, "w", encoding="utf-8") as f:
            json.dump({"target_version": agente.VERSION, "update_id": "upd-test"}, f)

        agente.emit_health_confirmation()

        with open(os.path.join(self.app_dir, "update_confirmed.json"), encoding="utf-8") as f:
            confirmed = json.load(f)
        self.assertEqual(confirmed["version"], agente.VERSION)
        self.assertEqual(confirmed["update_id"], "upd-test")
        self.assertFalse(os.path.exists(pending_file))

    def test_shutdown_cleanup_releases_global_mutex(self):
        kernel32 = MagicMock()
        fake_ctypes = MagicMock()
        fake_ctypes.windll.kernel32 = kernel32
        agente._single_instance_mutex = 123

        with patch.object(agente.platform, "system", return_value="Windows"), \
             patch.object(agente, "ctypes", fake_ctypes, create=True):
            agente.release_single_instance_mutex()

        kernel32.ReleaseMutex.assert_called_once_with(123)
        kernel32.CloseHandle.assert_called_once_with(123)
        self.assertIsNone(agente._single_instance_mutex)

    def test_updater_replaces_binary_and_accepts_health_confirmation(self):
        target = os.path.join(self.app_dir, "GivovaMonitorAgent.exe")
        previous = os.path.join(self.app_dir, "GivovaMonitorAgent.previous.exe")
        new_file = os.path.join(self.app_dir, "update_v2.0.0.exe")
        with open(target, "wb") as f:
            f.write(b"old-agent")
        with open(new_file, "wb") as f:
            f.write(b"new-agent")
        config_file = os.path.join(self.app_dir, "agent_config.json")
        with open(config_file, "wb") as f:
            f.write(b'{"uuid":"existing-uuid","device_token":"existing-token"}')
        os.makedirs(os.path.join(self.app_dir, "logs"))
        os.makedirs(os.path.join(self.app_dir, "extension"))
        with open(os.path.join(self.app_dir, "logs", "keep.txt"), "wb") as f:
            f.write(b"old-log")
        with open(os.path.join(self.app_dir, "extension", "keep.txt"), "wb") as f:
            f.write(b"extension")

        def start_and_confirm(target_dir, _current_exe, _task_name, _logger):
            with open(os.path.join(target_dir, "update_confirmed.json"), "w", encoding="utf-8") as f:
                json.dump({"status": "confirmed", "version": "2.0.0", "update_id": "upd-test"}, f)
            return True

        argv = [
            "updater.py", "--target-dir", self.app_dir, "--new-exe", new_file,
            "--old-pid", "999999", "--version", "2.0.0", "--update-id", "upd-test", "--timeout", "1",
        ]
        with patch.object(sys, "argv", argv), \
             patch.object(updater, "start_agent", side_effect=start_and_confirm), \
             patch.object(updater, "setup_logging", return_value=MagicMock()), \
             patch.object(updater.time, "sleep", return_value=None):
            with self.assertRaises(SystemExit) as exit_context:
                updater.run_updater()

        self.assertEqual(exit_context.exception.code, 0)
        with open(target, "rb") as f:
            self.assertEqual(f.read(), b"new-agent")
        with open(previous, "rb") as f:
            self.assertEqual(f.read(), b"old-agent")
        self.assertFalse(os.path.exists(new_file))
        with open(config_file, "rb") as f:
            self.assertEqual(f.read(), b'{"uuid":"existing-uuid","device_token":"existing-token"}')
        for directory, expected in (("logs", b"old-log"), ("extension", b"extension")):
            with open(os.path.join(self.app_dir, directory, "keep.txt"), "rb") as f:
                self.assertEqual(f.read(), expected)

    def test_updater_rollback_records_failed_version(self):
        target = os.path.join(self.app_dir, "GivovaMonitorAgent.exe")
        previous = os.path.join(self.app_dir, "GivovaMonitorAgent.previous.exe")
        with open(target, "wb") as f:
            f.write(b"bad-agent")
        with open(previous, "wb") as f:
            f.write(b"known-good-agent")
        logger = MagicMock()

        with patch.object(updater, "start_agent", return_value=True) as start_agent, \
             patch.object(updater.time, "sleep", return_value=None):
            self.assertTrue(updater.execute_rollback(
                self.app_dir, target, previous, "", "2.0.0", "test failure", logger
            ))

        with open(target, "rb") as f:
            self.assertEqual(f.read(), b"known-good-agent")
        with open(os.path.join(self.app_dir, "failed_updates.json"), encoding="utf-8") as f:
            failures = json.load(f)
        self.assertEqual(failures[0]["version"], "2.0.0")
        start_agent.assert_called_once()


if __name__ == "__main__":
    unittest.main()
