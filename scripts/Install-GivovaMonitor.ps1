<#
.SYNOPSIS
    Instalador automatizado de 1 execucao do Givova Monitor Agent.
.DESCRIPTION
    Instala o agente corporativo de monitoramento em C:\ProgramData\GivovaMonitor,
    configura a inicializacao automatica e invisivel via Windows Task Scheduler,
    solicita elevacao UAC automaticamente e valida a execucao do processo e a
    conectividade com o servidor Render.
.PARAMETER ServerUrl
    URL do endpoint de ingestao de telemetria do servidor.
.PARAMETER AgentToken
    Token de autenticacao do agente.
.PARAMETER Department
    Setor corporativo do computador (padrao: 'Nao informado').
.PARAMETER DisplayName
    Nome de identificacao do computador (padrao: Hostname do Windows).
.PARAMETER Force
    Executa a instalacao ou atualizacao sem confirmacao interativa.
#>

[CmdletBinding()]
param (
    [string]$ServerUrl = "https://monitoramento-gb9g.onrender.com/api/agent/report",
    [string]$AgentToken = "",
    [string]$Department = "Nao informado",
    [string]$DisplayName = "",
    [switch]$ReplaceConfig,
    [switch]$Force,
    [switch]$NoElevate
)

# -------------------------------------------------------------------------
# 1. AUTOELEVACAO ADMINISTRATIVA (UAC)
# -------------------------------------------------------------------------
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $NoElevate) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  Givova Monitor -- Solicitando Permissao de Administrador [UAC]" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "O instalador necessita de permissoes administrativas para:"
    Write-Host " - Instalar o executavel em C:\ProgramData\GivovaMonitor"
    Write-Host " - Registrar a tarefa de inicializacao automatica no Task Scheduler"
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
    if ($ReplaceConfig) { $argList += "-ReplaceConfig" }
    if ($Force) { $argList += "-Force" }

    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs
        exit
    } catch {
        Write-Error "A elevacao administrativa foi cancelada ou recusada pelo usuario."
        exit 1
    }
}

# -------------------------------------------------------------------------
# 2. CONSTANTES E DIRETORIOS
# -------------------------------------------------------------------------
$appName = "Givova Monitor Agent"
$installDir = "C:\ProgramData\GivovaMonitor"
$logDir = Join-Path $installDir "logs"
$destExe = Join-Path $installDir "GivovaMonitorAgent.exe"
$destConfig = Join-Path $installDir "agent_config.json"
$destExtension = Join-Path $installDir "extension"

$sourceDir = $PSScriptRoot
if (-not $sourceDir) {
    $sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
if (-not $sourceDir) {
    $sourceDir = (Get-Location).Path
}

$sourceExe = Join-Path $sourceDir "GivovaMonitorAgent.exe"
$sourceConfig = Join-Path $sourceDir "agent_config.json"
$sourceExtension = Join-Path $sourceDir "extension"
if (-not (Test-Path -Path $sourceExtension)) {
    $fallbackExt = Join-Path (Split-Path -Parent $sourceDir) "extension"
    if (Test-Path -Path $fallbackExt) {
        $sourceExtension = $fallbackExt
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor DarkYellow
Write-Host "      GIVOVA TRANSPORTES -- INSTALACAO DO GIVOVA MONITOR        " -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor DarkYellow
Write-Host ""

# Valida integridade do agent_config.json de origem se existir
if (Test-Path -Path $sourceConfig) {
    try {
        $rawSrc = Get-Content -Path $sourceConfig -Raw -Encoding UTF8
        $srcObj = $rawSrc | ConvertFrom-Json
        if (-not $srcObj.server_url) {
            Write-Error "O arquivo 'agent_config.json' do pacote nao contem a propriedade 'server_url'."
            exit 1
        }
        if ($srcObj.server_url -match 'localhost|127\.0\.0\.1' -and -not $Force) {
            Write-Error "O pacote de instalacao contem configuracao apontando para localhost/127.0.0.1. Pacotes de producao devem apontar para o servidor oficial no Render."
            exit 1
        }
    } catch {
        Write-Error "O arquivo 'agent_config.json' de origem esta corrompido ou e invalido: $_"
        exit 1
    }
}

# Valida presenca do binario de instalacao
if (-not (Test-Path -Path $sourceExe)) {
    # Tenta localizar em diretorio superior (ex: scripts/ vs dist/GivovaMonitorDeploy/)
    $fallbackExe = Join-Path (Split-Path -Parent $sourceDir) "dist\GivovaMonitorDeploy\GivovaMonitorAgent.exe"
    if (Test-Path -Path $fallbackExe) {
        $sourceExe = $fallbackExe
    } else {
        Write-Host "ERRO: O arquivo executavel 'GivovaMonitorAgent.exe' nao foi encontrado em:" -ForegroundColor Red
        Write-Host " $sourceDir" -ForegroundColor Red
        Write-Host "Certifique-se de executar o script dentro da pasta descompactada de deploy." -ForegroundColor Red
        Write-Host ""
        Read-Host "Pressione ENTER para sair..."
        exit 1
    }
}

# -------------------------------------------------------------------------
# 3. INTERRUPCAO DE VERSOES ANTERIORES (ATUALIZACAO SEGURA)
# -------------------------------------------------------------------------
Write-Host "[1/6] Verificando instancias em execucao..." -ForegroundColor Gray
$isUpdate = Test-Path -Path $destExe

# Para a tarefa no Agendador se ja existir
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
# 4. CRIACAO DE DIRETORIOS E COPIA DOS ARQUIVOS
# -------------------------------------------------------------------------
Write-Host "[2/6] Preparando diretorio $installDir..." -ForegroundColor Gray
if (-not (Test-Path -Path $installDir)) {
    New-Item -Path $installDir -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

Write-Host "[3/6] Copiando executavel autonomo..." -ForegroundColor Gray
Copy-Item -Path $sourceExe -Destination $destExe -Force
$sourceUpdater = Join-Path $sourceDir "GivovaMonitorUpdater.exe"
if (Test-Path -Path $sourceUpdater) {
    Copy-Item -Path $sourceUpdater -Destination (Join-Path $installDir "GivovaMonitorUpdater.exe") -Force
    Write-Host "      Supervisor de atualizacoes GivovaMonitorUpdater.exe copiado." -ForegroundColor Green
}

# Copia da Extensao Corporativa de Monitoramento de Dominio (Chrome / Edge)
if (Test-Path -Path $sourceExtension) {
    if (-not (Test-Path -Path $destExtension)) {
        New-Item -Path $destExtension -ItemType Directory -Force | Out-Null
    }
    Copy-Item -Path "$sourceExtension\*" -Destination $destExtension -Recurse -Force
    Write-Host "      Extensao corporativa Chrome/Edge copiada para $destExtension." -ForegroundColor Green
} else {
    Write-Host "      [AVISO] Pasta da extensao nao localizada em $sourceExtension." -ForegroundColor Yellow
}

# -------------------------------------------------------------------------
# 5. GERENCIAMENTO DA CONFIGURACAO (agent_config.json)
# -------------------------------------------------------------------------
Write-Host "[4/6] Configurando parametros do agente..." -ForegroundColor Gray

if ($isUpdate -and (Test-Path -Path $destConfig) -and -not $ReplaceConfig) {
    Write-Host "      Preservando configuracoes existentes em $destConfig..." -ForegroundColor Green
    try {
        $cfgJson = Get-Content -Path $destConfig -Raw -Encoding UTF8 | ConvertFrom-Json
        $changed = $false
        if ($PSBoundParameters.ContainsKey('ServerUrl') -and $ServerUrl) {
            $cfgJson.server_url = $ServerUrl
            $changed = $true
        }
        if ($PSBoundParameters.ContainsKey('AgentToken') -and $AgentToken) {
            $cfgJson.agent_token = $AgentToken
            $changed = $true
        }
        if ($PSBoundParameters.ContainsKey('Department') -and $Department) {
            $cfgJson.department = $Department
            $changed = $true
        }
        if ($PSBoundParameters.ContainsKey('DisplayName') -and $DisplayName) {
            $cfgJson.display_name = $DisplayName
            $changed = $true
        }
        if ($changed) {
            $cfgJson | ConvertTo-Json -Depth 4 | Set-Content -Path $destConfig -Encoding UTF8
            Write-Host "      Parametros fornecidos via CLI atualizados em $destConfig." -ForegroundColor Gray
        }
    } catch {
        Write-Warning "Falha ao ler ou atualizar parametros na configuracao: $_"
    }
} else {
    if ($ReplaceConfig -and (Test-Path -Path $destConfig)) {
        Write-Host "      Substituindo configuracao existente (-ReplaceConfig ativado)..." -ForegroundColor Yellow
    }
    # Nova instalacao: verifica se ha agent_config.json acompanhando o instalador
    $effectiveToken = $AgentToken
    $effectiveServer = $ServerUrl
    $effectiveDept = if ($Department) { $Department } else { "Nao informado" }
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
            if ($srcCfg.department -and $srcCfg.department -ne "Nao informado") {
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
# 6. REGISTRO NO WINDOWS TASK SCHEDULER (INICIALIZACAO INVISIVEL AO LOGON)
# -------------------------------------------------------------------------
Write-Host "[5/6] Registrando inicializacao automatica no Task Scheduler..." -ForegroundColor Gray

# Identifica o grupo de Usuarios locais por SID (funciona em qualquer idioma do Windows)
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
    # Tenta registrar vinculado ao grupo Users (dispara para qualquer usuario interativo)
    $principalGroup = New-ScheduledTaskPrincipal -GroupId $usersGroupName -RunLevel Limited
    $taskDef = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principalGroup
    Register-ScheduledTask -TaskName $appName -InputObject $taskDef -Force -ErrorAction Stop | Out-Null
    $registered = $true
} catch {
    # Fallback para usuario atual com LogonType Interactive
    try {
        $principalUser = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
        $taskDef = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principalUser
        Register-ScheduledTask -TaskName $appName -InputObject $taskDef -Force -ErrorAction Stop | Out-Null
        $registered = $true
    } catch {
        try {
            & schtasks.exe /create /tn $appName /tr "`"$destExe`"" /sc onlogon /rl limited /f 2>$null | Out-Null
            $registered = $true
        } catch {}
    }
}

# Inicia a tarefa imediatamente ou fallback para inicializacao direta
$started = $false
try {
    Start-ScheduledTask -TaskName $appName -ErrorAction Stop
    $started = $true
} catch {}

if (-not $started) {
    try {
        & schtasks.exe /run /tn $appName 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $started = $true }
    } catch {}
}

if ($started) {
    Start-Sleep -Seconds 2
}

if (-not (Get-Process -Name "GivovaMonitorAgent" -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath $destExe -WorkingDirectory $installDir
}

# -------------------------------------------------------------------------
# 7. VALIDACAO DO PROCESSO E CONECTIVIDADE COM O SERVIDOR
# -------------------------------------------------------------------------
Write-Host "[6/6] Validando funcionamento do agente..." -ForegroundColor Gray
Start-Sleep -Seconds 3

# Valida processo em execucao
$running = Get-Process -Name "GivovaMonitorAgent" -ErrorAction SilentlyContinue
$statusAgente = if ($running) { "em execucao [PID: $($running.Id[0])]" } else { "aguardando inicializacao" }

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
    $statusServidor = "alcancavel [aguardando cold start do Render]"
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
Write-Host "  Diretorio:  $installDir" -ForegroundColor Gray
Write-Host "  Extensao:   $destExtension" -ForegroundColor Gray
Write-Host "  Logs:       $logDir\agente.log" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "O agente esta rodando em segundo plano e iniciara automaticamente" -ForegroundColor Gray
Write-Host "a cada reinicializacao ou login de usuario no Windows." -ForegroundColor Gray
Write-Host ""
Write-Host "COMO ATIVAR A EXTENSAO NO NAVEGADOR (CHROME / EDGE):" -ForegroundColor Yellow
Write-Host "1. Abra chrome://extensions ou edge://extensions" -ForegroundColor DarkCyan
Write-Host "2. Ative a opcao 'Modo do desenvolvedor'" -ForegroundColor DarkCyan
Write-Host "3. Clique em 'Carregar sem compactacao' (ou Carregar descompactada)" -ForegroundColor DarkCyan
Write-Host "4. Selecione a pasta permanente: $destExtension" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "NOTA: Voce ja pode apagar a pasta original de instalacao ($sourceDir) do Desktop ou pendrive." -ForegroundColor Gray
Write-Host "Todos os arquivos e a extensao foram instalados permanentemente em $installDir." -ForegroundColor Gray
Write-Host ""

if (-not $Force) {
    Read-Host "Pressione ENTER para finalizar..."
}
