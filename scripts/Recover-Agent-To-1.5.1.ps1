<#
.SYNOPSIS
    Recupera uma instalação legada do Givova Monitor para o Agent 1.5.1.
.DESCRIPTION
    Executa uma única substituição local controlada para máquinas 1.4.1 ou 1.5.0
    afetadas pelo encerramento incompleto do auto-update. Não usa nem registra tokens.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$SourceExe = (Join-Path $PSScriptRoot "GivovaMonitorAgent.exe"),
    [string]$ExpectedSha256 = "e16bfc32798e4e395e28b0035bd27b2c9c3eedbdba8229776b914fbfc34a8288"
)

$ErrorActionPreference = "Stop"
$appName = "Givova Monitor Agent"
$installDir = "C:\ProgramData\GivovaMonitor"
$targetExe = Join-Path $installDir "GivovaMonitorAgent.exe"
$previousExe = Join-Path $installDir "GivovaMonitorAgent.previous.exe"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Wait-AgentStopped {
    for ($attempt = 0; $attempt -lt 15; $attempt++) {
        if (-not (Get-Process -Name "GivovaMonitorAgent" -ErrorAction SilentlyContinue)) {
            return $true
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

if (-not (Test-Administrator)) {
    throw "Execute este script em uma janela PowerShell elevada (Administrador)."
}

if ($ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw "O SHA-256 oficial da versão 1.5.1 não foi configurado no script."
}

if (-not (Test-Path -LiteralPath $SourceExe -PathType Leaf)) {
    throw "Binário 1.5.1 não encontrado: $SourceExe"
}
if (-not (Test-Path -LiteralPath $targetExe -PathType Leaf)) {
    throw "Agent instalado não encontrado: $targetExe"
}

$expectedHash = $ExpectedSha256.ToLowerInvariant()
$sourceHash = Get-Sha256 $SourceExe
if ($sourceHash -ne $expectedHash) {
    throw "O SHA-256 do binário de origem não corresponde à release oficial 1.5.1."
}

if ((Get-Sha256 $targetExe) -eq $expectedHash) {
    Write-Host "O Agent 1.5.1 oficial já está instalado. Nenhuma ação necessária." -ForegroundColor Green
    exit 0
}

$taskExists = $null -ne (Get-ScheduledTask -TaskName $appName -ErrorAction SilentlyContinue)
$backupCreated = $false
$replacementStarted = $false

try {
    if ($taskExists) {
        Disable-ScheduledTask -TaskName $appName -ErrorAction Stop | Out-Null
    }

    Get-Process -Name "GivovaMonitorAgent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Stop
    if (-not (Wait-AgentStopped)) {
        throw "O processo GivovaMonitorAgent não encerrou no prazo esperado."
    }

    Copy-Item -LiteralPath $targetExe -Destination $previousExe -Force
    $backupCreated = $true
    Copy-Item -LiteralPath $SourceExe -Destination $targetExe -Force

    if ($taskExists) {
        Enable-ScheduledTask -TaskName $appName -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $appName -ErrorAction Stop
    } else {
        Start-Process -FilePath $targetExe -WorkingDirectory $installDir -ErrorAction Stop
    }

    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        Start-Sleep -Seconds 1
        if (Get-Process -Name "GivovaMonitorAgent" -ErrorAction SilentlyContinue) {
            $replacementStarted = $true
            break
        }
    }
    if (-not $replacementStarted) {
        throw "O Agent 1.5.1 não iniciou após a substituição."
    }

    Write-Host "Recuperação concluída: Agent 1.5.1 iniciado com sucesso." -ForegroundColor Green
}
catch {
    $failure = $_
    if ($backupCreated -and (Test-Path -LiteralPath $previousExe)) {
        Get-Process -Name "GivovaMonitorAgent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath $previousExe -Destination $targetExe -Force -ErrorAction SilentlyContinue
        if (-not $taskExists) {
            Start-Process -FilePath $targetExe -WorkingDirectory $installDir -ErrorAction SilentlyContinue
        }
    }
    throw $failure
}
finally {
    if ($taskExists) {
        Enable-ScheduledTask -TaskName $appName -ErrorAction SilentlyContinue | Out-Null
        if (-not $replacementStarted -and $backupCreated) {
            Start-ScheduledTask -TaskName $appName -ErrorAction SilentlyContinue
        }
    }
}
