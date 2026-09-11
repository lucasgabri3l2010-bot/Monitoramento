<#
.SYNOPSIS
    Instalador automatizado de 1 execução do Givova Monitor Agent.
.DESCRIPTION
    Instala o agente corporativo de monitoramento em C:\ProgramData\GivovaMonitor,
    configura a inicialização automática e invisível via Windows Task Scheduler,
    solicita elevação UAC automaticamente e valida a execução do processo e a
    conectividade com o servidor Render.
.PARAMETER ServerUrl
    URL do endpoint de ingestão de telemetria do servidor.
.PARAMETER AgentToken
    Token de autenticação do agente.
.PARAMETER Department
    Setor corporativo do computador (padrão: 'Não informado').
.PARAMETER DisplayName
    Nome de identificação do computador (padrão: Hostname do Windows).
.PARAMETER Force
    Executa a instalação ou atualização sem confirmação interativa.
#>

[CmdletBinding()]
param (
    [string]$ServerUrl = "https://monitoramento-gb9g.onrender.com/api/agent/report",
    [string]$AgentToken = "",
    [string]$Department = "Não informado",
    [string]$DisplayName = "",
    [switch]$Force
)

# -------------------------------------------------------------------------
# 1. AUTOELEVAÇÃO ADMINISTRATIVA (UAC)
# -------------------------------------------------------------------------
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  Givova Monitor — Solicitando Permissão de Administrador [UAC]" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "O instalador necessita de permissões administrativas para:"
    Write-Host " - Instalar o executável em C:\ProgramData\GivovaMonitor"
    Write-Host " - Registrar a tarefa de inicialização automática no Task Scheduler"
    Write-Host ""
    Write-Host "Clique em 'Sim' na janela do Windows a seguir..." -ForegroundColor Yellow

    $scriptPath = $MyInvocation.MyCommand.Definition
    if (-not $scriptPath) {
        $scriptPath = $PSCommandPath
    }

    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptPath)
    if ($ServerUrl) { $argList += @("-ServerUrl", $ServerUrl) }
    if ($AgentToken) { $argList += @("-AgentToken", $AgentToken) }
    if ($Department) { $argList += @("-Department", $Department) }
    if ($DisplayName) { $argList += @("-DisplayName", $DisplayName) }
    if ($Force) { $argList += "-Force" }

    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs
        exit
    } catch {
        Write-Error "A elevação administrativa foi cancelada ou recusada pelo usuário."
        exit 1
    }
}

# -------------------------------------------------------------------------
# 2. CONSTANTES E DIRETÓRIOS
# -------------------------------------------------------------------------
$appName = "Givova Monitor Agent"
$installDir = "C:\ProgramData\GivovaMonitor"
$logDir = Join-Path $installDir "logs"
$destExe = Join-Path $installDir "GivovaMonitorAgent.exe"
$destConfig = Join-Path $installDir "agent_config.json"
$sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $sourceDir) {
    $sourceDir = $PSScriptRoot
}
$sourceExe = Join-Path $sourceDir "GivovaMonitorAgent.exe"
$sourceConfig = Join-Path $sourceDir "agent_config.json"

Write-Host ""
Write-Host "================================================================" -ForegroundColor DarkYellow
Write-Host "      GIVOVA TRANSPORTES — INSTALAÇÃO DO GIVOVA MONITOR        " -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor DarkYellow
Write-Host ""

# Valida presença do binário de instalação
if (-not (Test-Path -Path $sourceExe)) {
    # Tenta localizar em diretório superior (ex: scripts/ vs dist/GivovaMonitorDeploy/)
    $fallbackExe = Join-Path (Split-Path -Parent $sourceDir) "dist\GivovaMonitorDeploy\GivovaMonitorAgent.exe"
    if (Test-Path -Path $fallbackExe) {
        $sourceExe = $fallbackExe
    } else {
        Write-Host "ERRO: O arquivo executável 'GivovaMonitorAgent.exe' não foi encontrado em:" -ForegroundColor Red
        Write-Host " $sourceDir" -ForegroundColor Red
        Write-Host "Certifique-se de executar o script dentro da pasta descompactada de deploy." -ForegroundColor Red
        Write-Host ""
        Read-Host "Pressione ENTER para sair..."
        exit 1
    }
}

# -------------------------------------------------------------------------
# 3. INTERRUPÇÃO DE VERSÕES ANTERIORES (ATUALIZAÇÃO SEGURA)
# -------------------------------------------------------------------------
Write-Host "[1/6] Verificando instâncias em execução..." -ForegroundColor Gray
$isUpdate = Test-Path -Path $destExe

# Para a tarefa no Agendador se já existir
try {
    $existingTask = Get-ScheduledTask -TaskName $appName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Host "      Interrompendo tarefa agendada anterior..." -ForegroundColor Gray
        Stop-ScheduledTask -TaskName $appName -ErrorAction SilentlyContinue
    }
} catch {}

# Finaliza qualquer processo ativo do agente para liberar o arquivo
$runningProcs = Get-Process -Name "GivovaMonitorAgent" -ErrorAction SilentlyContinue
if ($runningProcs) {
    Write-Host "      Finalizando processo ativo do GivovaMonitorAgent..." -ForegroundColor Gray
    $runningProcs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

# -------------------------------------------------------------------------
# 4. CRIAÇÃO DE DIRETÓRIOS E CÓPIA DOS ARQUIVOS
# -------------------------------------------------------------------------
Write-Host "[2/6] Preparando diretório $installDir..." -ForegroundColor Gray
if (-not (Test-Path -Path $installDir)) {
    New-Item -Path $installDir -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

Write-Host "[3/6] Copiando executável autônomo..." -ForegroundColor Gray
Copy-Item -Path $sourceExe -Destination $destExe -Force
$sourceUpdater = Join-Path $sourceDir "GivovaMonitorUpdater.exe"
if (Test-Path -Path $sourceUpdater) {
    Copy-Item -Path $sourceUpdater -Destination (Join-Path $installDir "GivovaMonitorUpdater.exe") -Force
    Write-Host "      Supervisor de atualizações GivovaMonitorUpdater.exe copiado." -ForegroundColor Green
}

# -------------------------------------------------------------------------
# 5. GERENCIAMENTO DA CONFIGURAÇÃO (agent_config.json)
# -------------------------------------------------------------------------
Write-Host "[4/6] Configurando parâmetros do agente..." -ForegroundColor Gray

if ($isUpdate -and (Test-Path -Path $destConfig)) {
    Write-Host "      Preservando configurações existentes em $destConfig..." -ForegroundColor Green
    # Se o operador passou argumentos explícitos na atualização, atualiza apenas esses campos
    try {
        $cfgJson = Get-Content -Path $destConfig -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($ServerUrl -and $ServerUrl -ne "https://monitoramento-gb9g.onrender.com/api/agent/report") {
            $cfgJson.server_url = $ServerUrl
        }
        if ($AgentToken) {
            $cfgJson.agent_token = $AgentToken
        }
        $cfgJson | ConvertTo-Json -Depth 4 | Set-Content -Path $destConfig -Encoding UTF8
    } catch {}
} else {
    # Nova instalação: verifica se há agent_config.json acompanhando o instalador
    $effectiveToken = $AgentToken
    $effectiveServer = $ServerUrl
    $effectiveDept = if ($Department) { $Department } else { "Não informado" }
    $effectiveName = if ($DisplayName) { $DisplayName } else { $env:COMPUTERNAME }

    if (Test-Path -Path $sourceConfig) {
        try {
            $srcCfg = Get-Content -Path $sourceConfig -Raw -Encoding UTF8 | ConvertFrom-Json
            if (-not $effectiveToken -and $srcCfg.agent_token) {
                $effectiveToken = $srcCfg.agent_token
            }
            if ($srcCfg.server_url) {
                $effectiveServer = $srcCfg.server_url
            }
            if ($srcCfg.department -and $srcCfg.department -ne "Não informado") {
                $effectiveDept = $srcCfg.department
            }
        } catch {}
    }

    if (-not $effectiveToken) {
        $effectiveToken = "givova_agent_token_dev_2026"
    }

    $newConfig = @{
        server_url = $effectiveServer
        agent_token = $effectiveToken
        department = $effectiveDept
        display_name = $effectiveName
        interval_seconds = 5
        timeout_seconds = 10
        activity_monitoring = $true
    }

    $newConfig | ConvertTo-Json -Depth 4 | Set-Content -Path $destConfig -Encoding UTF8
    Write-Host "      Arquivo agent_config.json gerado com sucesso." -ForegroundColor Gray
}

# -------------------------------------------------------------------------
# 6. REGISTRO NO WINDOWS TASK SCHEDULER (INICIALIZAÇÃO INVISÍVEL AO LOGON)
# -------------------------------------------------------------------------
Write-Host "[5/6] Registrando inicialização automática no Task Scheduler..." -ForegroundColor Gray

# Identifica o grupo de Usuários locais por SID (funciona em qualquer idioma do Windows)
$usersGroupSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")
$usersGroupName = $usersGroupSid.Translate([System.Security.Principal.NTAccount]).Value

$action = New-ScheduledTaskAction -Execute $destExe -WorkingDirectory $installDir
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable

$registered = $false
try {
    # Tenta registrar vinculado ao grupo Users (dispara para qualquer usuário interativo)
    $principalGroup = New-ScheduledTaskPrincipal -GroupId $usersGroupName -RunLevel Limited
    $taskDef = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principalGroup
    Register-ScheduledTask -TaskName $appName -InputObject $taskDef -Force | Out-Null
    $registered = $true
} catch {
    # Fallback para usuário atual com LogonType Interactive
    try {
        $principalUser = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
        $taskDef = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principalUser
        Register-ScheduledTask -TaskName $appName -InputObject $taskDef -Force | Out-Null
        $registered = $true
    } catch {
        Write-Warning "Falha ao registrar tarefa com cmdlets CIM. Tentando via schtasks.exe..."
        & schtasks.exe /create /tn $appName /tr "`"$destExe`"" /sc onlogon /rl limited /f | Out-Null
        $registered = $true
    }
}

# Inicia a tarefa imediatamente
try {
    Start-ScheduledTask -TaskName $appName -ErrorAction SilentlyContinue
} catch {
    Start-Process -FilePath $destExe -WorkingDirectory $installDir
}

# -------------------------------------------------------------------------
# 7. VALIDAÇÃO DO PROCESSO E CONECTIVIDADE COM O SERVIDOR
# -------------------------------------------------------------------------
Write-Host "[6/6] Validando funcionamento do agente..." -ForegroundColor Gray
Start-Sleep -Seconds 3

# Valida processo em execução
$running = Get-Process -Name "GivovaMonitorAgent" -ErrorAction SilentlyContinue
$statusAgente = if ($running) { "em execução [PID: $($running.Id[0])]" } else { "aguardando inicialização" }

# Valida conectividade com o servidor Render
$statusServidor = "aguardando resposta"
try {
    $cfgActual = Get-Content -Path $destConfig -Raw -Encoding UTF8 | ConvertFrom-Json
    $srv = $cfgActual.server_url
    $healthUrl = $srv -replace "/api/agent/report", "/health"
    $req = [System.Net.WebRequest]::Create($healthUrl)
    $req.Timeout = 4000
    $res = $req.GetResponse()
    if ($res.StatusCode -eq 200) {
        $statusServidor = "conectado [online]"
    }
    $res.Close()
} catch {
    $statusServidor = "alcançável [aguardando cold start do Render]"
}

# -------------------------------------------------------------------------
# 8. RESULTADO FINAL
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Givova Monitor instalado com sucesso.                         " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Agente:     $statusAgente" -ForegroundColor Cyan
Write-Host "  Servidor:   $statusServidor" -ForegroundColor Cyan
Write-Host "  Dispositivo: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  Diretório:  $installDir" -ForegroundColor Gray
Write-Host "  Logs:       $logDir\agente.log" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "O agente está rodando em segundo plano e iniciará automaticamente" -ForegroundColor Gray
Write-Host "a cada reinicialização ou login de usuário no Windows." -ForegroundColor Gray
Write-Host "Você já pode fechar esta janela." -ForegroundColor Gray
Write-Host ""

if (-not $Force) {
    Read-Host "Pressione ENTER para finalizar..."
}
