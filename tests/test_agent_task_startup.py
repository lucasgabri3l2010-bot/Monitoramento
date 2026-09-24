"""Focused checks for the Windows Agent task registration paths."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TestAgentTaskStartup(unittest.TestCase):
    def test_install_and_recovery_keep_delayed_restarting_single_instance_task(self):
        for script in ("Install-GivovaMonitor.ps1", "Recover-Givova.ps1"):
            with self.subTest(script=script):
                source = (ROOT / "scripts" / script).read_text(encoding="utf-8-sig")
                self.assertIn("New-ScheduledTaskTrigger -AtLogOn", source)
                self.assertIn("['Delay'].Value = 'PT45S'", source)
                self.assertIn("-RestartCount 3", source)
                self.assertIn("-RestartInterval (New-TimeSpan -Minutes 1)", source)
                self.assertIn("-MultipleInstances IgnoreNew", source)
                self.assertIn("-StartWhenAvailable", source)

    def test_upgrade_preserves_existing_install_and_identity(self):
        installer = (ROOT / "scripts" / "Install-GivovaMonitor.ps1").read_text(encoding="utf-8-sig")
        recovery = (ROOT / "scripts" / "Recover-Givova.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("Set-ScheduledTask -TaskName $taskName -Trigger $trigger -Settings $settings", recovery)
        self.assertIn("Assert-AgentConfigState $configFile $configSnapshot", recovery)
        self.assertIn("$after.PreservedState -cne $BeforeSnapshot.PreservedState", recovery)
        self.assertNotIn("/sc onlogon /rl limited /f", installer)
        self.assertNotIn("Start-Process -FilePath $destExe", installer)
        packaged = (ROOT / "dist" / "GivovaRecovery-1.5.1" / "Recover-Givova.ps1")
        if packaged.exists():
            packaged_source = packaged.read_text(encoding="utf-8-sig")
            self.assertIn("Set-ScheduledTask -TaskName $taskName -Trigger $trigger -Settings $settings", packaged_source)
            self.assertEqual(packaged_source.count("        Set-GivovaTaskReliability"), 1)
            self.assertEqual(packaged_source.count("    Set-GivovaTaskReliability"), 2)

    def test_repeated_unexpected_agent_failures_exit_nonzero(self):
        source = (ROOT / "agente.py").read_text(encoding="utf-8")
        self.assertIn("consecutive_cycle_errors += 1", source)
        self.assertIn("if consecutive_cycle_errors >= 3:", source)
        self.assertIn("# Non-zero exit lets Task Scheduler apply its restart policy.\n                raise", source)


if __name__ == "__main__":
    unittest.main()
