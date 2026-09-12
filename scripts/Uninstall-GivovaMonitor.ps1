<#
.SYNOPSIS
    Desinstalador do Givova Monitor Agent.
.DESCRIPTION
    Interrompe a execução do agente, remove a tarefa agendada do Task Scheduler
    e remove os binários instalados em C:\ProgramData\GivovaMonitor.
.PARAMETER PurgeData
    Se especificado, remove também todos os logs e arquivos de configuração locais.
.PARAMETER Force
    Executa a remoção sem solicitar confirmação interativa.
#>

[CmdletBinding()]
param (
    [switch]$PurgeData,
    [switch]$Force,
    [switch]$NoElevate
)

# -------------------------------------------------------------------------
# 1. AUTOELEVAÇÃO ADMINISTRATIVA (UAC)
# -------------------------------------------------------------------------
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $NoElevate) {
    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host '  Givova Monitor — Solicitando Permissão de Administrador [UAC]' -ForegroundColor Cyan
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host 'A desinstalação necessita de privilégios de Administrador.'
    Write-Host 'Clique em Sim na janela do Windows...' -ForegroundColor Yellow

    $scriptPath = $MyInvocation.MyCommand.Definition
    if (-not $scriptPath) {
        $scriptPath = $PSCommandPath
    }

    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath)
    if ($PurgeData) { $argList += '-PurgeData' }
    if ($Force) { $argList += '-Force' }

    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs
        exit
    } catch {
        Write-Error 'A elevação administrativa foi recusada.'
        exit 1
    }
}

$appName = 'Givova Monitor Agent'
$installDir = 'C:\ProgramData\GivovaMonitor'
$destExe = Join-Path $installDir 'GivovaMonitorAgent.exe'
$destUpdater = Join-Path $installDir 'GivovaMonitorUpdater.exe'
$destExtension = Join-Path $installDir 'extension'
$destConfig = Join-Path $installDir 'agent_config.json'
$logDir = Join-Path $installDir 'logs'

Write-Host ''
Write-Host '================================================================' -ForegroundColor DarkYellow
Write-Host '    GIVOVA TRANSPORTES — DESINSTALAÇÃO DO GIVOVA MONITOR       ' -ForegroundColor Yellow
Write-Host '================================================================' -ForegroundColor DarkYellow
Write-Host ''

if (-not $Force) {
    $confirm = Read-Host 'Tem certeza que deseja remover o Givova Monitor deste computador? [S/N]'
    if ($confirm -notmatch '^[sSyY]') {
        Write-Host 'Operação cancelada pelo usuário.' -ForegroundColor Gray
        exit 0
    }
}

# -------------------------------------------------------------------------
# 2. PARADA DO PROCESSO E TAREFA
# -------------------------------------------------------------------------
Write-Host '[1/4] Interrompendo tarefa agendada e processos...' -ForegroundColor Gray

try {
    Stop-ScheduledTask -TaskName $appName -ErrorAction SilentlyContinue
} catch {}

$runningProcs = Get-Process -Name 'GivovaMonitorAgent' -ErrorAction SilentlyContinue
if ($runningProcs) {
    $runningProcs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

# -------------------------------------------------------------------------
# 3. REMOÇÃO DO TASK SCHEDULER
# -------------------------------------------------------------------------
Write-Host '[2/4] Removendo registro do Windows Task Scheduler...' -ForegroundColor Gray
try {
    Unregister-ScheduledTask -TaskName $appName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Write-Host "      Tarefa agendada '$appName' removida com sucesso." -ForegroundColor Green
} catch {
    Write-Host '      Aviso: Tarefa agendada não encontrada ou já removida.' -ForegroundColor Gray
}

# -------------------------------------------------------------------------
# 4. REMOÇÃO DE BINÁRIOS E COMPONENTES
# -------------------------------------------------------------------------
Write-Host '[3/4] Removendo executáveis e componentes...' -ForegroundColor Gray
if (Test-Path -Path $destExe) {
    Remove-Item -Path $destExe -Force -ErrorAction SilentlyContinue
    Write-Host '      Executável GivovaMonitorAgent.exe removido.' -ForegroundColor Green
}
if (Test-Path -Path $destUpdater) {
    Remove-Item -Path $destUpdater -Force -ErrorAction SilentlyContinue
    Write-Host '      Supervisor GivovaMonitorUpdater.exe removido.' -ForegroundColor Green
}
if (Test-Path -Path $destExtension) {
    Remove-Item -Path $destExtension -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "      Extensão corporativa removida de $destExtension." -ForegroundColor Green
}

# -------------------------------------------------------------------------
# 5. TRATAMENTO DE CONFIGURAÇÕES E LOGS
# -------------------------------------------------------------------------
Write-Host '[4/4] Limpeza de dados locais...' -ForegroundColor Gray
if ($PurgeData) {
    if (Test-Path -Path $installDir) {
        Remove-Item -Path $installDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "      Diretório de dados $installDir removido completamente." -ForegroundColor Green
    }
} else {
    Write-Host "      Configurações e logs preservados em $installDir." -ForegroundColor Gray
    Write-Host '      [Execute com -PurgeData caso deseje excluir logs e configurações].' -ForegroundColor Gray
}

Write-Host ''
Write-Host '================================================================' -ForegroundColor Green
Write-Host '  Givova Monitor desinstalado com sucesso deste computador.     ' -ForegroundColor Green
Write-Host '================================================================' -ForegroundColor Green
Write-Host ''

if (-not $Force) {
    Read-Host 'Pressione ENTER para finalizar...'
}
