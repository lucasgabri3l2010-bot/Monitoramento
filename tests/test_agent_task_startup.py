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
            self.assertGreaterEqual(packaged_source.count("Set-GivovaTaskReliability"), 3)

    def test_repeated_unexpected_agent_failures_exit_nonzero(self):
        source = (ROOT / "agente.py").read_text(encoding="utf-8")
        self.assertIn("consecutive_cycle_errors += 1", source)
        self.assertIn("if consecutive_cycle_errors >= 3:", source)
        self.assertIn("# Non-zero exit lets Task Scheduler apply its restart policy.\n                raise", source)

    def test_existing_pc_startup_repair_does_not_replace_agent_or_config(self):
        recovery = (ROOT / "scripts" / "Recover-Givova.ps1").read_text(encoding="utf-8-sig")
        launcher = (ROOT / "scripts" / "ATUALIZAR_GIVOVA.cmd").read_text(encoding="utf-8-sig")
        packaged_recovery = (ROOT / "dist" / "GivovaRecovery-1.5.1" / "Recover-Givova.ps1").read_text(encoding="utf-8-sig")
        packaged_launcher = (ROOT / "dist" / "GivovaRecovery-1.5.1" / "ATUALIZAR_GIVOVA.cmd").read_text(encoding="utf-8-sig")
        for script in (recovery, packaged_recovery):
            with self.subTest(script=script[:24]):
                repair = script[script.index("if ($StartupOnly) {"):script.index("$taskExists = $false")]
                self.assertLess(script.index("if ($StartupOnly) {"), script.index("Test-ExpectedHash $SourceAgentExe"))
                self.assertIn("Set-GivovaTaskReliability", repair)
                self.assertIn("Enable-ScheduledTask -TaskName $taskName", repair)
                self.assertIn("Assert-GivovaTaskReliability", repair)
                self.assertIn("$configHashBefore = Get-OptionalSha256 $configFile", repair)
                self.assertIn("Acao ou principal da tarefa foi alterado", repair)
                for field in ("LogonTrigger/t:Delay", "RestartOnFailure/t:Interval", "RestartOnFailure/t:Count", "MultipleInstancesPolicy"):
                    self.assertIn(field, script)
                for forbidden in ("Copy-Item", "Stop-GivovaProcesses", "Set-RailwayEndpoint", "Register-ScheduledTask"):
                    self.assertNotIn(forbidden, repair)
        for cmd in (launcher, packaged_launcher):
            self.assertIn('if /I "%~1"=="startup" set "RECOVERY_ARGS= -StartupOnly"', cmd)
            self.assertIn("+ $env:RECOVERY_ARGS", cmd)


if __name__ == "__main__":
    unittest.main()
