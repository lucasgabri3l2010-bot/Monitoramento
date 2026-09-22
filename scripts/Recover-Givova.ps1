<#
.SYNOPSIS
    Installs the verified Givova Monitor 1.5.1 Agent and Updater from local media.

.DESCRIPTION
    This script is rendered into the USB recovery package by Build-GivovaMonitor.ps1.
    Its SHA-256 placeholders are replaced at build time. It changes only server_url
    when it still targets the legacy Render backend, preserves every other config
    field, and never touches existing logs or the browser extension.

    Exit codes:
      0 = 1.5.1 installed (or already installed) and first report confirmed
      1 = recovery failed; previous Agent and Updater were restored
      2 = 1.5.1 installed and running, but the first report was not confirmed in time
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$SourceAgentExe = "",
    [string]$SourceUpdaterExe = "",
    [string]$ExpectedAgentSha256 = "__AGENT_SHA256__",
    [string]$ExpectedUpdaterSha256 = "__UPDATER_SHA256__",
    [string]$InstallDir = "C:\ProgramData\GivovaMonitor",
    [int]$ReportTimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"
# Windows PowerShell 5.1 leaves $PSScriptRoot empty inside param() defaults under -File,
# so the package folder (any USB drive letter) is resolved here instead.
$packageDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $SourceAgentExe) { $SourceAgentExe = Join-Path $packageDir "GivovaMonitorAgent.exe" }
if (-not $SourceUpdaterExe) { $SourceUpdaterExe = Join-Path $packageDir "GivovaMonitorUpdater.exe" }
$targetVersion = "1.5.1"
$taskName = "Givova Monitor Agent"
$oldBackend = "https://monitoramento-gb9g.onrender.com"
$newBackend = "https://monitoramento-production.up.railway.app"
$requiredInstallDir = "C:\ProgramData\GivovaMonitor"
$targetAgent = Join-Path $InstallDir "GivovaMonitorAgent.exe"
$targetUpdater = Join-Path $InstallDir "GivovaMonitorUpdater.exe"
$previousAgent = Join-Path $InstallDir "GivovaMonitorAgent.previous.exe"
$previousUpdater = Join-Path $InstallDir "GivovaMonitorUpdater.previous.exe"
$configFile = $null
$pendingFile = Join-Path $InstallDir "pending_update.json"
$confirmedFile = Join-Path $InstallDir "update_confirmed.json"
$logDir = Join-Path $InstallDir "logs"
$logFile = Join-Path $logDir "recovery-1.5.1.log"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-RecoveryMessage([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $line -ForegroundColor $Color
    try { Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 } catch {}
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-OptionalSha256([string]$Path) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return Get-Sha256 $Path
    }
    return $null
}

function Resolve-AgentConfigPath(
    [string]$ApplicationDirectory,
    [string]$ProgramDataConfig = "C:\ProgramData\GivovaMonitor\agent_config.json"
) {
    if (-not [string]::IsNullOrWhiteSpace($env:GIVOVA_CONFIG_PATH)) {
        return [Environment]::ExpandEnvironmentVariables($env:GIVOVA_CONFIG_PATH.Trim())
    }
    if (Test-Path -LiteralPath $ProgramDataConfig -PathType Leaf) {
        return $ProgramDataConfig
    }
    $applicationConfig = Join-Path $ApplicationDirectory "agent_config.json"
    if (Test-Path -LiteralPath $applicationConfig -PathType Leaf) {
        return $applicationConfig
    }
    return $ProgramDataConfig
}

function Read-AgentConfig([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "agent_config.json nao encontrado no caminho efetivo."
    }
    try {
        $config = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "agent_config.json efetivo nao contem JSON valido."
    }
    if ($null -eq $config -or $config -is [System.Array]) {
        throw "agent_config.json efetivo deve conter um objeto JSON."
    }
    return $config
}

function Get-PreservedConfigState($Config) {
    $copy = $Config | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $copy.PSObject.Properties.Remove("server_url")
    return ($copy | ConvertTo-Json -Depth 100 -Compress)
}

function Get-AgentConfigSnapshot([string]$Path) {
    $config = Read-AgentConfig $Path
    $serverProperty = $config.PSObject.Properties["server_url"]
    $serverUrl = if ($null -ne $serverProperty) { [string]$serverProperty.Value } else { "" }
    $normalizedUrl = $serverUrl.Trim().TrimEnd("/")
    $state = "Custom"
    if ($normalizedUrl -ieq $oldBackend -or
        $normalizedUrl.StartsWith($oldBackend + "/", [StringComparison]::OrdinalIgnoreCase)) {
        $state = "Render"
    } elseif ($normalizedUrl -ieq $newBackend -or
              $normalizedUrl.StartsWith($newBackend + "/", [StringComparison]::OrdinalIgnoreCase)) {
        $state = "Railway"
    }
    return [pscustomobject]@{
        Config = $config
        EndpointState = $state
        NormalizedServerUrl = $normalizedUrl
        PreservedState = Get-PreservedConfigState $config
    }
}

function Set-RailwayEndpoint([string]$Path, $Snapshot) {
    if ($Snapshot.EndpointState -ne "Render") {
        return
    }
    $migratedUrl = $newBackend + $Snapshot.NormalizedServerUrl.Substring($oldBackend.Length)
    $Snapshot.Config.PSObject.Properties["server_url"].Value = $migratedUrl
    $temporaryConfig = "$Path.recovery-$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $Snapshot.Config | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $temporaryConfig -Encoding UTF8
        Move-Item -LiteralPath $temporaryConfig -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporaryConfig -Force -ErrorAction SilentlyContinue
    }
}

function Assert-AgentConfigState([string]$Path, $BeforeSnapshot) {
    $after = Get-AgentConfigSnapshot $Path
    if ($after.PreservedState -cne $BeforeSnapshot.PreservedState) {
        throw "Campos de identidade/configuracao foram alterados durante a recuperacao."
    }
    if ($BeforeSnapshot.EndpointState -eq "Render" -and $after.EndpointState -ne "Railway") {
        throw "O endpoint efetivo nao foi migrado para Railway."
    }
    if ($BeforeSnapshot.EndpointState -eq "Railway" -and $after.EndpointState -ne "Railway") {
        throw "O endpoint Railway existente foi alterado."
    }
    if ($BeforeSnapshot.EndpointState -eq "Custom" -and $after.EndpointState -ne "Custom") {
        throw "O endpoint customizado foi alterado."
    }
}

function Assert-ScheduledTaskEnabled {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -eq $task -or [string]$task.State -eq "Disabled") {
        throw "A tarefa agendada '$taskName' nao esta habilitada."
    }
}

function Test-ExpectedHash([string]$Path, [string]$ExpectedHash, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label nao encontrado: $Path"
    }
    if ($ExpectedHash -notmatch '^[a-fA-F0-9]{64}$') {
        throw "SHA-256 oficial de $Label nao foi configurado no pacote."
    }
    if ((Get-Sha256 $Path) -ne $ExpectedHash.ToLowerInvariant()) {
        throw "SHA-256 invalido para $Label. Instalacao abortada."
    }
}

function Test-AgentRunning {
    return $null -ne (Get-Process -Name "GivovaMonitorAgent" -ErrorAction SilentlyContinue)
}

function Stop-GivovaProcesses {
    foreach ($name in @("GivovaMonitorAgent", "GivovaMonitorUpdater")) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Stop
    }
    for ($attempt = 0; $attempt -lt 15; $attempt++) {
        if (-not (Get-Process -Name "GivovaMonitorAgent", "GivovaMonitorUpdater" -ErrorAction SilentlyContinue)) {
            return
        }
        Start-Sleep -Seconds 1
    }
    throw "Os processos do Givova Monitor nao encerraram no prazo esperado."
}

function Start-GivovaAgent([bool]$TaskExists) {
    if ($TaskExists) {
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    } else {
        Start-Process -FilePath $targetAgent -WorkingDirectory $InstallDir -ErrorAction Stop | Out-Null
    }
}

function Wait-AgentRunning([int]$Seconds) {
    for ($attempt = 0; $attempt -lt $Seconds; $attempt++) {
        if (Test-AgentRunning) {
            return $true
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Request-ReportConfirmation {
    # Agent 1.5.1 writes update_confirmed.json after its first successful report when
    # pending_update.json targets its own version (same handshake used by the updater).
    $updateId = "usb-recovery-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
    Remove-Item -LiteralPath $confirmedFile -Force -ErrorAction SilentlyContinue
    [ordered]@{
        update_id = $updateId
        target_version = $targetVersion
        created_at = (Get-Date).ToUniversalTime().ToString("o")
        source = "usb-recovery"
    } | ConvertTo-Json | Set-Content -LiteralPath $pendingFile -Encoding ASCII
    return $updateId
}

function Wait-ReportConfirmation([string]$UpdateId, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-AgentRunning)) {
            throw "O Agent $targetVersion encerrou antes de confirmar o primeiro report."
        }
        $data = $null
        if (Test-Path -LiteralPath $confirmedFile -PathType Leaf) {
            # The Agent may still be writing the file; a failed read is retried on the next pass.
            try { $data = Get-Content -LiteralPath $confirmedFile -Raw | ConvertFrom-Json } catch {}
        }
        if ($data -and $data.status -eq "confirmed" -and $data.update_id -eq $UpdateId) {
            if ($data.version -ne $targetVersion) {
                throw "Agent em execucao reportou a versao '$($data.version)', esperada $targetVersion."
            }
            return $true
        }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Restore-ConfigBackup([string]$BackupPath) {
    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
        throw "Rollback da configuracao impossivel: backup ausente."
    }
    Copy-Item -LiteralPath $BackupPath -Destination $configFile -Force
    Write-RecoveryMessage "Configuracao anterior restaurada." Yellow
}

function Restore-Backups([bool]$TaskExists) {
    Write-RecoveryMessage "Falha detectada. Restaurando Agent e Updater anteriores..." Yellow
    Stop-GivovaProcesses
    if ((Test-Path -LiteralPath $previousAgent) -and (Test-Path -LiteralPath $previousUpdater)) {
        Copy-Item -LiteralPath $previousAgent -Destination $targetAgent -Force
        Copy-Item -LiteralPath $previousUpdater -Destination $targetUpdater -Force
        Remove-Item -LiteralPath $pendingFile -Force -ErrorAction SilentlyContinue
        if ($TaskExists) {
            Enable-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null
        }
        Start-GivovaAgent $TaskExists
        Write-RecoveryMessage "Rollback dos dois executaveis concluido." Yellow
    } else {
        throw "Rollback impossivel: um ou ambos os backups nao existem."
    }
}

if (-not (Test-Administrator)) {
    throw "Esta recuperacao exige permissao de Administrador."
}

$normalizedInstallDir = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
$normalizedRequiredDir = [IO.Path]::GetFullPath($requiredInstallDir).TrimEnd('\')
if ($normalizedInstallDir -ine $normalizedRequiredDir) {
    throw "A recuperacao deve permanecer instalada em $requiredInstallDir."
}
$configFile = Resolve-AgentConfigPath $InstallDir

New-Item -ItemType Directory -Path $logDir -Force | Out-Null
Write-RecoveryMessage "Inicio da recuperacao local $targetVersion (origem: $packageDir)." Cyan

$taskExists = $false
$processesStopped = $false
$backupsCreated = $false
$configChanged = $false
$configBackup = $null
$stagingDir = $null
$exitCode = 0

try {
    Test-ExpectedHash $SourceAgentExe $ExpectedAgentSha256 "GivovaMonitorAgent.exe de origem"
    Test-ExpectedHash $SourceUpdaterExe $ExpectedUpdaterSha256 "GivovaMonitorUpdater.exe de origem"
    if (-not (Test-Path -LiteralPath $targetAgent -PathType Leaf) -or -not (Test-Path -LiteralPath $targetUpdater -PathType Leaf)) {
        throw "Instalacao existente incompleta em $InstallDir."
    }
    $taskExists = $null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
    if (-not $taskExists) {
        throw "A tarefa agendada '$taskName' nao foi encontrada."
    }
    $configSnapshot = Get-AgentConfigSnapshot $configFile
    $configHashBefore = Get-OptionalSha256 $configFile
    if ($configSnapshot.EndpointState -eq "Custom") {
        Write-RecoveryMessage "Endpoint customizado detectado; migracao de URL ignorada."
    } elseif ($configSnapshot.EndpointState -eq "Railway") {
        Write-RecoveryMessage "Endpoint Railway ja configurado; nenhuma alteracao necessaria."
    }

    if ((Get-Sha256 $targetAgent) -eq $ExpectedAgentSha256.ToLowerInvariant() -and
        (Get-Sha256 $targetUpdater) -eq $ExpectedUpdaterSha256.ToLowerInvariant()) {
        # Idempotent path: binaries are not replaced. A legacy Render endpoint is
        # still migrated and requires one controlled Agent restart.
        if ($configSnapshot.EndpointState -eq "Render") {
            $configBackup = Join-Path ([IO.Path]::GetTempPath()) ("GivovaConfigBackup-" + [guid]::NewGuid().ToString("N") + ".json")
            Copy-Item -LiteralPath $configFile -Destination $configBackup -Force
            Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
            Write-RecoveryMessage "Tarefa temporariamente desabilitada."
            $processesStopped = $true
            Stop-GivovaProcesses
            Set-RailwayEndpoint $configFile $configSnapshot
            $configChanged = $true
            Write-RecoveryMessage "Endpoint migrado de Render para Railway; identidade e token preservados."
        }

        Enable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
        if (-not (Test-AgentRunning)) {
            Start-GivovaAgent $taskExists
            if (-not (Wait-AgentRunning 30)) {
                throw "Agent $targetVersion ja instalado, mas nao iniciou."
            }
        }
        Assert-ScheduledTaskEnabled
        Assert-AgentConfigState $configFile $configSnapshot
        if ($configSnapshot.EndpointState -ne "Render" -and (Get-OptionalSha256 $configFile) -ne $configHashBefore) {
            throw "agent_config.json foi alterado sem necessidade."
        }
        Write-RecoveryMessage "Computador ja atualizado para $targetVersion. Nenhuma substituicao necessaria." Green
        exit 0
    }

    # Stage from removable media into local TEMP before any task/process is touched,
    # so removing the USB drive mid-run cannot leave a half-copied binary.
    $stagingDir = Join-Path ([IO.Path]::GetTempPath()) ("GivovaRecovery-$targetVersion-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
    $stagedAgent = Join-Path $stagingDir "GivovaMonitorAgent.exe"
    $stagedUpdater = Join-Path $stagingDir "GivovaMonitorUpdater.exe"
    Copy-Item -LiteralPath $SourceAgentExe -Destination $stagedAgent -Force
    Copy-Item -LiteralPath $SourceUpdaterExe -Destination $stagedUpdater -Force
    Test-ExpectedHash $stagedAgent $ExpectedAgentSha256 "GivovaMonitorAgent.exe copiado localmente"
    Test-ExpectedHash $stagedUpdater $ExpectedUpdaterSha256 "GivovaMonitorUpdater.exe copiado localmente"
    Write-RecoveryMessage "Binarios verificados e copiados para staging local."

    Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
    Write-RecoveryMessage "Tarefa temporariamente desabilitada."

    $processesStopped = $true
    Stop-GivovaProcesses
    Copy-Item -LiteralPath $targetAgent -Destination $previousAgent -Force
    Copy-Item -LiteralPath $targetUpdater -Destination $previousUpdater -Force
    $backupsCreated = $true
    Write-RecoveryMessage "Backups dos dois executaveis criados."

    if ($configSnapshot.EndpointState -eq "Render") {
        $configBackup = Join-Path $stagingDir "agent_config.previous.json"
        Copy-Item -LiteralPath $configFile -Destination $configBackup -Force
        Set-RailwayEndpoint $configFile $configSnapshot
        $configChanged = $true
        Write-RecoveryMessage "Endpoint migrado de Render para Railway; identidade e token preservados."
    }

    Copy-Item -LiteralPath $stagedAgent -Destination $targetAgent -Force
    Copy-Item -LiteralPath $stagedUpdater -Destination $targetUpdater -Force
    Test-ExpectedHash $targetAgent $ExpectedAgentSha256 "GivovaMonitorAgent.exe instalado"
    Test-ExpectedHash $targetUpdater $ExpectedUpdaterSha256 "GivovaMonitorUpdater.exe instalado"
    Assert-AgentConfigState $configFile $configSnapshot
    if ($configSnapshot.EndpointState -ne "Render" -and (Get-OptionalSha256 $configFile) -ne $configHashBefore) {
        throw "agent_config.json foi alterado sem necessidade."
    }
    Write-RecoveryMessage "Agent e Updater substituidos; configuracao local preservada."

    $updateId = Request-ReportConfirmation
    Enable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
    Assert-ScheduledTaskEnabled
    Start-GivovaAgent $taskExists
    if (-not (Wait-AgentRunning 30)) {
        throw "O Agent $targetVersion nao iniciou apos a substituicao."
    }
    Write-RecoveryMessage "Agent $targetVersion iniciado. Aguardando o primeiro report (ate ${ReportTimeoutSeconds}s)..."

    if (Wait-ReportConfirmation $updateId $ReportTimeoutSeconds) {
        Write-RecoveryMessage "Recuperacao concluida: Agent $targetVersion ativo e report confirmado pelo servidor." Green
    } else {
        # Binaries are verified and the Agent is alive; rolling back would only restore
        # the defective auto-update. Report the missing confirmation for follow-up instead.
        $exitCode = 2
        Write-RecoveryMessage "Agent $targetVersion instalado e em execucao, mas o report nao foi confirmado em ${ReportTimeoutSeconds}s. Verifique a rede/servidor." Yellow
    }
}
catch {
    $failure = $_
    Write-RecoveryMessage ("ERRO: " + $failure.Exception.Message) Red
    if ($configChanged) {
        try { Restore-ConfigBackup $configBackup } catch { Write-RecoveryMessage ("ERRO NO ROLLBACK DA CONFIGURACAO: " + $_.Exception.Message) Red }
    }
    if ($backupsCreated) {
        try { Restore-Backups $taskExists } catch { Write-RecoveryMessage ("ERRO NO ROLLBACK: " + $_.Exception.Message) Red }
    } elseif ($processesStopped) {
        # Nothing was replaced yet; restart the original Agent with the restored config.
        try { Stop-GivovaProcesses } catch {}
        Enable-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null
        try { Start-GivovaAgent $taskExists } catch { Write-RecoveryMessage ("ERRO AO REINICIAR AGENT: " + $_.Exception.Message) Red }
    }
    throw $failure
}
finally {
    if ($taskExists) {
        Enable-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null
    }
    if ($stagingDir -and (Test-Path -LiteralPath $stagingDir)) {
        Remove-Item -LiteralPath $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($configBackup -and (Test-Path -LiteralPath $configBackup -PathType Leaf)) {
        Remove-Item -LiteralPath $configBackup -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode
