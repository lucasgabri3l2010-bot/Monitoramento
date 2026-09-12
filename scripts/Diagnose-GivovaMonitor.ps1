<#
.SYNOPSIS
    Script de diagnostico de saude e integridade do Givova Monitor Agent e Extensao.
.DESCRIPTION
    Verifica o estado da instalacao do agente, processo em segundo plano,
    tarefa agendada, arquivos da extensao corporativa em C:\ProgramData\GivovaMonitor\extension,
    status do receptor HTTP local na porta 5005 e conectividade com o servidor Render.
#>

[CmdletBinding()]
param (
    [switch]$Detailed
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "    GIVOVA TRANSPORTES -- DIAGNOSTICO DO GIVOVA MONITOR          " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Data/Hora: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Computador: $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host ""

$installDir = "C:\ProgramData\GivovaMonitor"
$agentExe = Join-Path $installDir "GivovaMonitorAgent.exe"
$updaterExe = Join-Path $installDir "GivovaMonitorUpdater.exe"
$configFile = Join-Path $installDir "agent_config.json"
$logDir = Join-Path $installDir "logs"
$logFile = Join-Path $logDir "agente.log"
$extensionDir = Join-Path $installDir "extension"
$manifestFile = Join-Path $extensionDir "manifest.json"

# -------------------------------------------------------------------------
# 1. VERIFICACAO DE INSTALACAO BASE
# -------------------------------------------------------------------------
Write-Host "[1/6] Verificando diretorio e arquivos de instalacao..." -ForegroundColor Gray
if (Test-Path -Path $installDir) {
    Write-Host "  [OK] Diretorio base presente: $installDir" -ForegroundColor Green
} else {
    Write-Host "  [ERRO] Diretorio base nao encontrado: $installDir" -ForegroundColor Red
}

if (Test-Path -Path $agentExe) {
    $exeSizeMb = [math]::Round(((Get-Item $agentExe).Length / 1MB), 2)
    Write-Host "  [OK] GivovaMonitorAgent.exe presente (${exeSizeMb} MB)" -ForegroundColor Green
} else {
    Write-Host "  [ERRO] GivovaMonitorAgent.exe ausente em $installDir" -ForegroundColor Red
}

if (Test-Path -Path $updaterExe) {
    Write-Host "  [OK] GivovaMonitorUpdater.exe presente" -ForegroundColor Green
} else {
    Write-Host "  [INFO] GivovaMonitorUpdater.exe nao instalado (modo agente autonomo)" -ForegroundColor Gray
}

# -------------------------------------------------------------------------
# 2. CONFIGURACAO (agent_config.json)
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "[2/6] Verificando configuracao local..." -ForegroundColor Gray
$serverUrl = "https://monitoramento-gb9g.onrender.com/api/agent/report"
if (Test-Path -Path $configFile) {
    try {
        $cfg = Get-Content -Path $configFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $serverUrl = if ($cfg.server_url) { $cfg.server_url } else { $serverUrl }
        $maskedToken = if ($cfg.agent_token) {
            $t = $cfg.agent_token.ToString()
            if ($t.Length -gt 8) { $t.Substring(0, 4) + "..." + $t.Substring($t.Length - 4) } else { "***" }
        } else { "nao definido" }

        Write-Host "  [OK] agent_config.json valido" -ForegroundColor Green
        Write-Host "       Servidor:   $serverUrl" -ForegroundColor Gray
        Write-Host "       Token:      $maskedToken" -ForegroundColor Gray
        Write-Host "       Setor:      $($cfg.department)" -ForegroundColor Gray
        Write-Host "       Nome exibicao: $($cfg.display_name)" -ForegroundColor Gray
        Write-Host "       Intervalo:  $($cfg.interval_seconds)s" -ForegroundColor Gray
    } catch {
        Write-Host "  [ERRO] Falha ao ler agent_config.json: $_" -ForegroundColor Red
    }
} else {
    Write-Host "  [ERRO] Arquivo de configuracao ausente: $configFile" -ForegroundColor Red
}

# -------------------------------------------------------------------------
# 3. PROCESSO EM EXECUCAO E TAREFA AGENDADA
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "[3/6] Verificando execucao e Task Scheduler..." -ForegroundColor Gray
$procs = Get-Process -Name "GivovaMonitorAgent" -ErrorAction SilentlyContinue
if ($procs) {
    $pids = ($procs | ForEach-Object { $_.Id }) -join ", "
    Write-Host "  [OK] Processo em execucao: GivovaMonitorAgent (PID: $pids)" -ForegroundColor Green
} else {
    Write-Host "  [WARNING] Processo GivovaMonitorAgent NAO esta em execucao no momento." -ForegroundColor Yellow
}

try {
    $task = Get-ScheduledTask -TaskName "Givova Monitor Agent" -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "  [OK] Tarefa agendada 'Givova Monitor Agent' registrada (Estado: $($task.State))" -ForegroundColor Green
    } else {
        Write-Host "  [WARNING] Tarefa agendada 'Givova Monitor Agent' nao encontrada." -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [INFO] Consulta ao Task Scheduler requer permissoes de administrador." -ForegroundColor Gray
}

# -------------------------------------------------------------------------
# 4. DIAGNOSTICO DA EXTENSAO CORPORATIVA (CHROME / EDGE)
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "[4/6] Verificando extensao corporativa de dominio..." -ForegroundColor Gray

$extInstalled = $false
$extVersion = "desconhecida"

if ((Test-Path -Path $extensionDir) -and (Test-Path -Path $manifestFile)) {
    try {
        $manifestJson = Get-Content -Path $manifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $extVersion = if ($manifestJson.version) { $manifestJson.version } else { "1.0.0" }
        $extName = if ($manifestJson.name) { $manifestJson.name } else { "Givova Extension" }
        $extInstalled = $true
        Write-Host "  [OK] Extension files installed (v$extVersion) em $extensionDir" -ForegroundColor Green
        Write-Host "       Nome: $extName" -ForegroundColor Gray
        Write-Host "       Service Worker: $($manifestJson.background.service_worker)" -ForegroundColor Gray
    } catch {
        Write-Host "  [WARNING] Pasta da extensao existe, mas falha ao ler manifest.json: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [WARNING] Extension files missing em $extensionDir" -ForegroundColor Yellow
    Write-Host "            (A pasta da extensao nao foi copiada para C:\ProgramData\GivovaMonitor\extension)" -ForegroundColor Gray
}

Write-Host "  --> NOTA: Arquivos presentes NAO garantem que a extensao esteja habilitada no navegador." -ForegroundColor DarkYellow
Write-Host "      Em navegadores nao gerenciados por GPO corporativa, habilite uma unica vez:" -ForegroundColor DarkYellow
Write-Host "      1. Abra chrome://extensions ou edge://extensions" -ForegroundColor DarkGray
Write-Host "      2. Ative o 'Modo do desenvolvedor'" -ForegroundColor DarkGray
Write-Host "      3. Clique em 'Carregar sem compactacao' e selecione $extensionDir" -ForegroundColor DarkGray

# -------------------------------------------------------------------------
# 5. RECEPTOR LOCAL HTTP NA PORTA 5005
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "[5/6] Verificando receptor local da extensao (127.0.0.1:5005)..." -ForegroundColor Gray

$receiverListening = $false
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $connect = $tcp.BeginConnect("127.0.0.1", 5005, $null, $null)
    $success = $connect.AsyncWaitHandle.WaitOne(1000, $false)
    if ($success -and $tcp.Connected) {
        $receiverListening = $true
        $tcp.EndConnect($connect)
    }
    $tcp.Close()
} catch {}

if ($receiverListening) {
    Write-Host "  [OK] Receptor local ativo e ouvindo em http://127.0.0.1:5005/active-tab" -ForegroundColor Green
} else {
    Write-Host "  [WARNING] Receptor local INATIVO na porta 5005." -ForegroundColor Yellow
    Write-Host "            (O agente precisa estar em execucao para que a extensao comunique o dominio ativo)." -ForegroundColor Gray
}

# Verificacao do ultimo active_domain registrado nos logs
$lastDomain = $null
if (Test-Path -Path $logFile) {
    try {
        $logLines = Get-Content -Path $logFile -Tail 200 -ErrorAction SilentlyContinue
        foreach ($line in ($logLines | Select-Object -Reverse)) {
            if ($line -match 'active_domain["'':\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})') {
                $lastDomain = $matches[1]
                break
            } elseif ($line -match 'domain["'':\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})') {
                $lastDomain = $matches[1]
                break
            }
        }
    } catch {}
}

if ($lastDomain) {
    Write-Host "  [INFO] Ultimo active_domain detectado nos logs: $lastDomain" -ForegroundColor Cyan
} else {
    Write-Host "  [INFO] Nenhum active_domain recente registrado nos logs locais (normal se nenhum browser navegou ainda)." -ForegroundColor Gray
}

# Verificacao do ultimo envio com sucesso registrado nos logs
$lastSuccessReport = $null
if (Test-Path -Path $logFile) {
    try {
        $logLines = Get-Content -Path $logFile -Tail 200 -ErrorAction SilentlyContinue
        foreach ($line in ($logLines | Select-Object -Reverse)) {
            if ($line -match 'Enviado com sucesso \(HTTP 200\)') {
                $lastSuccessReport = $line.Trim()
                break
            }
        }
    } catch {}
}

if ($lastSuccessReport) {
    Write-Host "  [OK] Ultimo report confirmado: $lastSuccessReport" -ForegroundColor Green
} else {
    Write-Host "  [INFO] Nenhum report HTTP 200 recente encontrado nos logs locais." -ForegroundColor Gray
}

# -------------------------------------------------------------------------
# 6. CONECTIVIDADE COM O SERVIDOR RENDER
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "[6/6] Verificando conectividade com o servidor..." -ForegroundColor Gray

$healthUrl = $serverUrl -replace "/api/agent/report", "/health"
try {
    $req = [System.Net.WebRequest]::Create($healthUrl)
    $req.Timeout = 5000
    $res = $req.GetResponse()
    $code = [int]$res.StatusCode
    $res.Close()
    if ($code -eq 200) {
        Write-Host "  [OK] Servidor online e respondendo em $healthUrl (Status 200)" -ForegroundColor Green
    } else {
        Write-Host "  [WARNING] Servidor respondeu com codigo $code em $healthUrl" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [WARNING] Nao foi possivel conectar ao servidor em $healthUrl ($($_.Exception.Message))" -ForegroundColor Yellow
    Write-Host "            (Servidores Render podem demorar ~30-50s para acordar em cold start)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "                 FIM DO DIAGNOSTICO                             " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
