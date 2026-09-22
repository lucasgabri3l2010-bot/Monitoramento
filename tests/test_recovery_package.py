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
        replacement_path = self.recovery[self.recovery.index('# Stage from removable media'):]
        self.assertLess(
            replacement_path.index('Test-ExpectedHash $stagedUpdater'),
            replacement_path.index('Disable-ScheduledTask'),
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

    def test_railway_to_railway_is_idempotent_without_replacing_binaries(self):
        start = self.recovery.index('# Idempotent path')
        end = self.recovery.index('exit 0', start)
        block = self.recovery[start:end]
        self.assertIn('Start-GivovaAgent $taskExists', block)
        self.assertIn('$configSnapshot.EndpointState -eq "Render"', block)
        self.assertNotIn('Copy-Item -LiteralPath $stagedAgent', block)
        self.assertNotIn('Copy-Item -LiteralPath $stagedUpdater', block)

    def test_render_endpoint_is_replaced_with_railway_only(self):
        self.assertIn('$oldBackend = "https://monitoramento-gb9g.onrender.com"', self.recovery)
        self.assertIn('$newBackend = "https://monitoramento-production.up.railway.app"', self.recovery)
        self.assertIn('if ($Snapshot.EndpointState -ne "Render")', self.recovery)
        self.assertIn('$newBackend + $Snapshot.NormalizedServerUrl.Substring($oldBackend.Length)', self.recovery)
        self.assertIn('$Snapshot.Config.PSObject.Properties["server_url"].Value = $migratedUrl', self.recovery)

    def test_custom_endpoint_is_preserved_and_logged_as_skipped(self):
        self.assertIn('$state = "Custom"', self.recovery)
        self.assertIn('Endpoint customizado detectado; migracao de URL ignorada.', self.recovery)
        self.assertIn('$BeforeSnapshot.EndpointState -eq "Custom"', self.recovery)
        self.assertIn('agent_config.json foi alterado sem necessidade.', self.recovery)

    def test_config_path_priority_is_override_then_programdata_then_app_directory(self):
        resolver = self.recovery[
            self.recovery.index('function Resolve-AgentConfigPath'):
            self.recovery.index('function Read-AgentConfig')
        ]
        override = resolver.index('$env:GIVOVA_CONFIG_PATH')
        programdata = resolver.index('Test-Path -LiteralPath $ProgramDataConfig')
        app_directory = resolver.index('Join-Path $ApplicationDirectory "agent_config.json"')
        self.assertLess(override, programdata)
        self.assertLess(programdata, app_directory)
        self.assertIn('C:\\ProgramData\\GivovaMonitor\\agent_config.json', resolver)

    def test_uuid_token_and_all_non_endpoint_config_are_preserved(self):
        preserve = self.recovery[
            self.recovery.index('function Get-PreservedConfigState'):
            self.recovery.index('function Get-AgentConfigSnapshot')
        ]
        self.assertEqual(preserve.count('Properties.Remove("server_url")'), 1)
        self.assertIn('$after.PreservedState -cne $BeforeSnapshot.PreservedState', self.recovery)
        self.assertNotIn('[guid]::NewGuid()', preserve)

    def test_config_and_binaries_are_rolled_back_on_failure(self):
        catch_start = self.recovery.rindex('catch {\n    $failure')
        catch_block = self.recovery[catch_start:self.recovery.index('finally {', catch_start)]
        self.assertIn('Restore-ConfigBackup $configBackup', catch_block)
        self.assertIn('Restore-Backups $taskExists', catch_block)
        self.assertLess(
            catch_block.index('Restore-ConfigBackup $configBackup'),
            catch_block.index('Restore-Backups $taskExists'),
        )

    def test_failure_before_backup_restarts_original_agent(self):
        catch_start = self.recovery.rindex('catch {\n    $failure')
        catch_block = self.recovery[catch_start:self.recovery.index('finally {', catch_start)]
        self.assertIn('elseif ($processesStopped)', catch_block)
        self.assertIn('Start-GivovaAgent $taskExists', catch_block)
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
