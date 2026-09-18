import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class RecoveryPackageTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recovery = (ROOT / "scripts" / "Recover-Givova.ps1").read_text(encoding="utf-8")
        cls.build = (ROOT / "scripts" / "Build-GivovaMonitor.ps1").read_text(encoding="utf-8")
        cls.launcher = (ROOT / "scripts" / "ATUALIZAR_GIVOVA.cmd").read_text(encoding="utf-8")

    def test_recovery_stages_and_validates_both_binaries_before_stopping_agent(self):
        self.assertIn('"__AGENT_SHA256__"', self.recovery)
        self.assertIn('"__UPDATER_SHA256__"', self.recovery)
        self.assertIn('Copy-Item -LiteralPath $SourceAgentExe -Destination $stagedAgent -Force', self.recovery)
        self.assertIn('Copy-Item -LiteralPath $SourceUpdaterExe -Destination $stagedUpdater -Force', self.recovery)
        self.assertLess(
            self.recovery.index('Test-ExpectedHash $stagedUpdater'),
            self.recovery.index('Disable-ScheduledTask'),
        )

    def test_rollback_restores_agent_and_updater_and_finally_reenables_task(self):
        rollback_start = self.recovery.index('function Restore-Backups')
        rollback_end = self.recovery.index('if (-not (Test-Administrator))')
        rollback = self.recovery[rollback_start:rollback_end]
        self.assertIn('Copy-Item -LiteralPath $previousAgent -Destination $targetAgent -Force', rollback)
        self.assertIn('Copy-Item -LiteralPath $previousUpdater -Destination $targetUpdater -Force', rollback)
        self.assertIn('Restore-Backups $taskExists', self.recovery)
        finally_block = self.recovery[self.recovery.index('finally {'):]
        self.assertIn('Enable-ScheduledTask -TaskName $taskName', finally_block)

    def test_build_renders_and_validates_four_file_usb_package(self):
        self.assertIn('dist\\GivovaRecovery-1.5.1', self.build)
        self.assertIn('Replace("__AGENT_SHA256__", $shaRecoveryAgent)', self.build)
        self.assertIn('Replace("__UPDATER_SHA256__", $shaUpdater)', self.build)
        self.assertIn('"ATUALIZAR_GIVOVA.cmd"', self.build)
        self.assertIn('"GivovaMonitorUpdater.exe"', self.build)

    def test_launcher_requests_uac_for_script_next_to_itself(self):
        self.assertIn('%~dp0Recover-Givova.ps1', self.launcher)
        self.assertIn('-Verb RunAs', self.launcher)

    def test_launcher_quotes_script_path_for_folders_with_spaces(self):
        self.assertIn("'-NoProfile -ExecutionPolicy Bypass -File \\\"' + $env:RECOVERY_PS1 + '\\\"'", self.launcher)
        raw = (ROOT / "scripts" / "ATUALIZAR_GIVOVA.cmd").read_bytes()
        self.assertEqual(raw.count(b"\n"), raw.count(b"\r\n"), "cmd launcher must use CRLF line endings")

    def test_build_packages_published_agent_and_freshly_built_updater(self):
        self.assertIn('Join-Path $repoRoot "releases\\manifest.json"', self.build)
        self.assertIn('"dist\\releases\\$recoveryVersion\\GivovaMonitorAgent.exe"', self.build)
        self.assertIn('$shaRecoveryAgent -ne $releaseManifest.sha256.ToLower()', self.build)
        self.assertIn('Replace("__AGENT_SHA256__", $shaRecoveryAgent)', self.build)
        self.assertIn('Copy-Item -LiteralPath $recoveryAgentSource', self.build)
        self.assertIn('Copy-Item -Path $distUpdaterExe -Destination (Join-Path $distRecoveryDir', self.build)

    def test_recovery_stages_in_local_temp_and_preserves_config(self):
        self.assertIn('[IO.Path]::GetTempPath()', self.recovery)
        self.assertIn('$configHashBefore = Get-OptionalSha256 $configFile', self.recovery)
        self.assertIn('(Get-OptionalSha256 $configFile) -ne $configHashBefore', self.recovery)
        for protected in ('Remove-Item -LiteralPath $configFile', 'Remove-Item -LiteralPath $logDir', 'extension'):
            self.assertNotIn(protected, self.recovery.split('#>', 1)[1])

    def test_recovery_confirms_report_of_running_version(self):
        self.assertIn('target_version = $targetVersion', self.recovery)
        self.assertIn('$data.update_id -eq $UpdateId', self.recovery)
        self.assertIn('$data.version -ne $targetVersion', self.recovery)
        self.assertLess(
            self.recovery.index('$updateId = Request-ReportConfirmation'),
            self.recovery.index('Start-GivovaAgent $taskExists\n    if (-not (Wait-AgentRunning 30))'),
        )

    def test_idempotent_path_keeps_agent_running_without_replacing(self):
        start = self.recovery.index('# Idempotent path')
        end = self.recovery.index('exit 0', start)
        block = self.recovery[start:end]
        self.assertIn('Start-GivovaAgent $taskExists', block)
        self.assertNotIn('Copy-Item', block)
        self.assertNotIn('Disable-ScheduledTask', block)

    def test_failure_before_backup_restarts_original_agent(self):
        catch_block = self.recovery[self.recovery.index('catch {\n    $failure'):self.recovery.index('finally {')]
        self.assertIn('$processesStopped -and -not (Test-AgentRunning)', catch_block)
        self.assertLess(self.recovery.index('$processesStopped = $true'), self.recovery.index('Stop-GivovaProcesses\n    Copy-Item'))

    def test_recovery_has_no_secrets_and_does_not_touch_defender(self):
        for text in (self.recovery, self.launcher):
            lowered = text.lower()
            for forbidden in ('agent_token', 'password', 'senha', 'set-mppreference', 'add-mppreference'):
                self.assertNotIn(forbidden, lowered)
        self.assertIn('Join-Path $packageDir "GivovaMonitorAgent.exe"', self.recovery)
        self.assertIn('Join-Path $packageDir "GivovaMonitorUpdater.exe"', self.recovery)

    def test_package_dir_is_not_resolved_inside_param_defaults(self):
        # Windows PowerShell 5.1 leaves $PSScriptRoot empty in param() defaults under -File.
        wrapper = (ROOT / "scripts" / "Recover-Agent-To-1.5.1.ps1").read_text(encoding="utf-8")
        for script in (self.recovery, wrapper):
            param_block = script[script.index('param('):script.index('$ErrorActionPreference')]
            self.assertNotIn('$PSScriptRoot', param_block)
            self.assertIn('Split-Path -Parent $MyInvocation.MyCommand.Path', script)


if __name__ == "__main__":
    unittest.main()
