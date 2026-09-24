"""One-time Windows task repair for the 1.5.1 -> 1.5.2 auto-update."""

import base64
import json
import os
import re
import subprocess
import sys


TASK_NAME = "Givova Monitor Agent"
REPAIR_TIMEOUT_SECONDS = 20  # The installed 1.5.1 updater waits only 45 seconds.

_CHECK_TASK = r"""
function Test-GivovaTask {
    $task = Get-ScheduledTask -TaskName 'Givova Monitor Agent' -ErrorAction Stop
    if ([string]$task.State -eq 'Disabled') { return $false }
    [xml]$definition = Export-ScheduledTask -TaskName 'Givova Monitor Agent' -ErrorAction Stop
    $ns = [System.Xml.XmlNamespaceManager]::new($definition.NameTable)
    $ns.AddNamespace('t', $definition.DocumentElement.NamespaceURI)
    $delay = $definition.SelectSingleNode('//t:LogonTrigger/t:Delay', $ns)
    $interval = $definition.SelectSingleNode('//t:Settings/t:RestartOnFailure/t:Interval', $ns)
    $count = $definition.SelectSingleNode('//t:Settings/t:RestartOnFailure/t:Count', $ns)
    $instances = $definition.SelectSingleNode('//t:Settings/t:MultipleInstancesPolicy', $ns)
    return ($null -ne $delay -and [Xml.XmlConvert]::ToTimeSpan($delay.InnerText) -eq [TimeSpan]::FromSeconds(45) -and
        $null -ne $interval -and [Xml.XmlConvert]::ToTimeSpan($interval.InnerText) -eq [TimeSpan]::FromMinutes(1) -and
        $null -ne $count -and [int]$count.InnerText -eq 3 -and
        $null -ne $instances -and $instances.InnerText -eq 'IgnoreNew')
}
"""

_READ_TASK = _CHECK_TASK + r"""
try { if (Test-GivovaTask) { exit 0 } else { exit 1 } } catch { exit 2 }
"""

_REPAIR_TASK = _CHECK_TASK + r"""
$ErrorActionPreference = 'Stop'
try {
    if (Test-GivovaTask) { exit 0 }
    $before = Get-ScheduledTask -TaskName 'Givova Monitor Agent' -ErrorAction Stop
    $beforeAction = @($before.Actions | ForEach-Object { "$($_.Execute)|$($_.Arguments)|$($_.WorkingDirectory)" }) -join ';'
    $beforePrincipal = "$($before.Principal.UserId)|$($before.Principal.GroupId)|$($before.Principal.LogonType)|$($before.Principal.RunLevel)"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $trigger.CimInstanceProperties['Delay'].Value = 'PT45S'
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable
    Set-ScheduledTask -TaskName 'Givova Monitor Agent' -Trigger $trigger -Settings $settings -ErrorAction Stop | Out-Null
    Enable-ScheduledTask -TaskName 'Givova Monitor Agent' -ErrorAction Stop | Out-Null
    $after = Get-ScheduledTask -TaskName 'Givova Monitor Agent' -ErrorAction Stop
    $afterAction = @($after.Actions | ForEach-Object { "$($_.Execute)|$($_.Arguments)|$($_.WorkingDirectory)" }) -join ';'
    $afterPrincipal = "$($after.Principal.UserId)|$($after.Principal.GroupId)|$($after.Principal.LogonType)|$($after.Principal.RunLevel)"
    if ($beforeAction -cne $afterAction -or $beforePrincipal -cne $afterPrincipal) { exit 3 }
    if (-not (Test-GivovaTask)) { exit 4 }
    exit 0
} catch { exit 5 }
"""

_RETRY_AFTER_ROLLBACK = r"""
$target = $env:GIVOVA_REPAIR_TARGET
$updateId = $env:GIVOVA_REPAIR_UPDATE_ID
$version = '1.5.2'
$failed = Join-Path $target 'failed_updates.json'
$pending = Join-Path $target 'pending_update.json'
$current = Join-Path $target 'GivovaMonitorAgent.exe'
$previous = Join-Path $target 'GivovaMonitorAgent.previous.exe'
$deadline = (Get-Date).AddMinutes(3)
while ((Get-Date) -lt $deadline) {
    try {
        if ((Test-Path -LiteralPath $failed) -and
            (Test-Path -LiteralPath $pending) -and
            (Test-Path -LiteralPath $current) -and
            (Test-Path -LiteralPath $previous)) {
            $pendingData = Get-Content -LiteralPath $pending -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($pendingData.update_id -ne $updateId) { exit 1 }
            $parsed = Get-Content -LiteralPath $failed -Raw -Encoding UTF8 | ConvertFrom-Json
            $items = @($parsed | ForEach-Object { $_ })
            if (@($items | Where-Object { $_.version -eq $version }).Count -gt 0 -and
                (Get-FileHash -LiteralPath $current -Algorithm SHA256).Hash -eq
                (Get-FileHash -LiteralPath $previous -Algorithm SHA256).Hash) {
                $remaining = @($items | Where-Object { $_.version -ne $version })
                $json = ConvertTo-Json -InputObject $remaining -Depth 10
                [System.IO.File]::WriteAllText($failed, $json, [System.Text.UTF8Encoding]::new($false))
                exit 0
            }
        }
    } catch {}
    Start-Sleep -Seconds 2
}
exit 1
"""


def _powershell_path():
    return os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
    )


def _encoded(script):
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def _command(script):
    return [_powershell_path(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", _encoded(script)]


def pending_update_id(install_dir, version):
    try:
        with open(os.path.join(install_dir, "pending_update.json"), encoding="utf-8") as handle:
            pending = json.load(handle)
        update_id = str(pending.get("update_id") or "")
        if pending.get("target_version") == version and re.fullmatch(r"upd-[0-9a-f]{12}", update_id):
            return update_id
    except (OSError, ValueError, AttributeError):
        pass
    return ""


def _allow_retry_after_rollback(install_dir, update_id):
    # The deployed 1.5.1 updater blacklists timed-out versions. Only an
    # explicitly failed UAC repair may clear this version, and only after its
    # own rollback restored the previous executable byte-for-byte.
    if not update_id:
        return False
    env = {
        "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
        "GIVOVA_REPAIR_TARGET": install_dir,
        "GIVOVA_REPAIR_UPDATE_ID": update_id,
    }
    flags = 0x00000008 | 0x08000000 if sys.platform == "win32" else 0
    subprocess.Popen(
        _command(_RETRY_AFTER_ROLLBACK), cwd=install_dir, env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=flags, close_fds=True,
    )
    return True


def ensure_startup_task(install_dir, version, logger):
    """Return True only after the existing task is verified or repaired."""
    if sys.platform != "win32":
        return True

    flags = 0x08000000  # No console; the UAC consent dialog remains visible.
    try:
        check = subprocess.run(_command(_READ_TASK), timeout=5, creationflags=flags,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check.returncode == 0:
            return True

        elevated = _encoded(_REPAIR_TASK)
        launch = (
            "$ErrorActionPreference='Stop'; "
            "$p=Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru "
            f"-ArgumentList '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {elevated}'; "
            "exit $p.ExitCode"
        )
        result = subprocess.run(_command(launch), timeout=REPAIR_TIMEOUT_SECONDS,
                                creationflags=flags, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return True
        logger.warning("Startup task repair was not approved or did not validate; update will roll back.")
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("Startup task repair could not complete within the update window: %s", type(exc).__name__)

    update_id = pending_update_id(install_dir, version)
    try:
        if not _allow_retry_after_rollback(install_dir, update_id):
            logger.error("No matching pending update; cannot schedule retry cleanup.")
    except OSError as exc:
        logger.error("Could not schedule retry cleanup after repair failure: %s", type(exc).__name__)
    return False
