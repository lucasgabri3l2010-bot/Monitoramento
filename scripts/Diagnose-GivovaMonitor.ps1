<#
.SYNOPSIS
    Script de diagnostico de saude e integridade do Givova Monitor Agent e Extensao.
.DESCRIPTION
    Verifica o estado da instalacao do agente, processo em segundo plano,
    tarefa agendada, arquivos da extensao corporativa em C:\ProgramData\GivovaMonitor\extension,
    status do receptor HTTP local na porta 5005 e conectividade com o servidor Render.
#>

[CmdletBinding(PositionalBinding=$false)]
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
Write-Host "[1/7] Verificando diretorio e arquivos de instalacao..." -ForegroundColor Gray
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
Write-Host "[2/7] Verificando configuracao local e variaveis de ambiente..." -ForegroundColor Gray

$overridePath = $env:GIVOVA_CONFIG_PATH
if (-not $overridePath) {
    $overridePath = [System.Environment]::GetEnvironmentVariable('GIVOVA_CONFIG_PATH', 'User')
}
if (-not $overridePath) {
    $overridePath = [System.Environment]::GetEnvironmentVariable('GIVOVA_CONFIG_PATH', 'Machine')
}
$overrideActive = if ($overridePath) { "YES" } else { "NO" }

if ($overrideActive -eq "YES") {
    Write-Host "  [WARNING] GIVOVA_CONFIG_PATH esta sobrescrevendo o caminho padrao: $overridePath" -ForegroundColor Yellow
} else {
    Write-Host "  [OK] GIVOVA_CONFIG_PATH override: NO (utilizando caminho padrao)" -ForegroundColor Green
}

$serverUrl = "https://monitoramento-gb9g.onrender.com/api/agent/report"
$tokenPresent = "NO"
$tokenValidation = "INVALID"
$configPathStatus = "MISSING"

if (Test-Path -Path $configFile) {
    $configPathStatus = "OK"
    try {
        $cfg = Get-Content -Path $configFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $serverUrl = if ($cfg.server_url) { $cfg.server_url } else { $serverUrl }

        if ($cfg.agent_token -and $cfg.agent_token.ToString().Trim().Length -gt 0) {
            $tokenPresent = "YES"
            $t = $cfg.agent_token.ToString().Trim()
            $badWords = @('informado', 'nao informado', 'none', 'token', 'placeholder', 'your_token_here', 'copie_o_agent_secret_token')
            if ($t.Length -ge 16 -and -not ($t -match '\s') -and ($badWords -notcontains $t.ToLower())) {
                $tokenValidation = "VALID"
            } else {
                $tokenValidation = "INVALID"
            }
        }

        Write-Host "  [OK] agent_config.json carregado com sucesso" -ForegroundColor Green
        Write-Host "       Servidor:         $serverUrl" -ForegroundColor Gray
        Write-Host "       Token present:    $tokenPresent" -ForegroundColor Gray
        Write-Host "       Token validation: $tokenValidation" -ForegroundColor $(if ($tokenValidation -eq "VALID") { "Green" } else { "Red" })
        Write-Host "       Setor:            $($cfg.department)" -ForegroundColor Gray
        Write-Host "       Nome exibicao:    $($cfg.display_name)" -ForegroundColor Gray
        Write-Host "       Intervalo:        $($cfg.interval_seconds)s" -ForegroundColor Gray
    } catch {
        Write-Host "  [ERRO] Falha ao ler agent_config.json: $_" -ForegroundColor Red
        $configPathStatus = "CORRUPT"
    }
} else {
    Write-Host "  [ERRO] Arquivo de configuracao ausente: $configFile" -ForegroundColor Red
}

# -------------------------------------------------------------------------
# 3. PROCESSO EM EXECUCAO E TAREFA AGENDADA
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "[3/7] Verificando execucao e Task Scheduler..." -ForegroundColor Gray
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
Write-Host "[4/7] Verificando extensao corporativa de dominio..." -ForegroundColor Gray
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
Write-Host "[5/7] Verificando receptor local da extensao (127.0.0.1:5005)..." -ForegroundColor Gray

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
        $logLines = @(Get-Content -Path $logFile -Tail 200 -ErrorAction SilentlyContinue)
        for ($i = $logLines.Count - 1; $i -ge 0; $i--) {
            $line = $logLines[$i]
            if ($line -match 'Atividade:.*?[\u2014-]\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})') {
                $lastDomain = $matches[1]
                break
            } elseif ($line -match 'active_domain["'':\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})') {
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

# Verificacao do historico recente de logs
$lastAttempt = "Nenhum registro de envio"
$lastHttpStatus = "N/A"
$lastSuccessReport = "Nenhum report com sucesso ainda"
$detectedAgentVersion = "1.4.1"

if (Test-Path -Path $logFile) {
    try {
        $logLines = @(Get-Content -Path $logFile -Tail 200 -ErrorAction SilentlyContinue)
        for ($i = $logLines.Count - 1; $i -ge 0; $i--) {
            $line = $logLines[$i]
            if ($lastHttpStatus -eq "N/A") {
                if ($line -match 'HTTP (\d{3})') {
                    $lastHttpStatus = $matches[1]
                    $lastAttempt = $line.Trim()
                } elseif ($line -match 'timeout|tempo de resposta esgotado|Report failed') {
                    $lastHttpStatus = "TIMEOUT/FAIL"
                    $lastAttempt = $line.Trim()
                }
            }
            if ($lastSuccessReport -eq "Nenhum report com sucesso ainda") {
                if ($line -match 'HTTP 200' -or $line -match 'Enviado com sucesso') {
                    $lastSuccessReport = $line.Trim()
                }
            }
            if ($line -match 'Agent version:\s*([0-9.]+)') {
                $detectedAgentVersion = $matches[1]
            }
        }
    } catch {}
}

Write-Host "  [INFO] Ultima tentativa registrada: $lastAttempt" -ForegroundColor Gray
Write-Host "  [INFO] Ultimo status HTTP:          $lastHttpStatus" -ForegroundColor $(if ($lastHttpStatus -eq "200") { "Green" } else { "Yellow" })
Write-Host "  [INFO] Ultimo report confirmado:    $lastSuccessReport" -ForegroundColor $(if ($lastSuccessReport -ne "Nenhum report com sucesso ainda") { "Green" } else { "Gray" })

# -------------------------------------------------------------------------
# 6. CONECTIVIDADE COM O SERVIDOR RENDER (/health e /health/db)
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "[6/7] Verificando conectividade com o servidor Render..." -ForegroundColor Gray

$renderHealth = "FAIL"
$renderDb = "FAIL"

$baseServerUrl = $serverUrl -replace "/api/agent/report", ""
$baseServerUrl = $baseServerUrl.TrimEnd("/")
$healthUrl = "$baseServerUrl/health"
$healthDbUrl = "$baseServerUrl/health/db"

try {
    $req = [System.Net.WebRequest]::Create($healthUrl)
    $req.Timeout = 5000
    $res = $req.GetResponse()
    $renderHealth = [int]$res.StatusCode
    $res.Close()
    Write-Host "  [OK] Render /health: $renderHealth" -ForegroundColor Green
} catch {
    Write-Host "  [WARNING] Falha ao conectar em $healthUrl ($($_.Exception.Message))" -ForegroundColor Yellow
}

try {
    $reqDb = [System.Net.WebRequest]::Create($healthDbUrl)
    $reqDb.Timeout = 5000
    $resDb = $reqDb.GetResponse()
    $renderDb = [int]$resDb.StatusCode
    $resDb.Close()
    Write-Host "  [OK] Render /health/db: $renderDb" -ForegroundColor Green
} catch {
    Write-Host "  [WARNING] Falha ao conectar em $healthDbUrl ($($_.Exception.Message))" -ForegroundColor Yellow
}

# -------------------------------------------------------------------------
# 7. TELEMETRIA DE ATIVIDADE E ESTADO DA SESSAO (v1.5.0)
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "[7/7] Verificando telemetria de inatividade e sessao Windows (v1.5.0)..." -ForegroundColor Gray

$idleSeconds = -1.0
$sessionState = "desconhecido"
$lockState = "unknown"
$winSessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId

$configuredThreshold = 300
if ($cfg -and $cfg.idle_threshold_seconds) {
    $configuredThreshold = [int]$cfg.idle_threshold_seconds
}

try {
    $csharpCode = @"
using System;
using System.Runtime.InteropServices;

public class GivovaWin32Diag {
    [StructLayout(LayoutKind.Sequential)]
    public struct LASTINPUTINFO {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    [DllImport("kernel32.dll")]
    public static extern uint GetTickCount();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSQuerySessionInformationW(
        IntPtr hServer,
        int sessionId,
        int wtsInfoClass,
        out IntPtr ppBuffer,
        out int pBytesReturned
    );

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr pMemory);

    public static float GetIdleSeconds() {
        LASTINPUTINFO lii = new LASTINPUTINFO();
        lii.cbSize = (uint)Marshal.SizeOf(lii);
        if (GetLastInputInfo(ref lii)) {
            uint currentTick = GetTickCount();
            uint idleTicks = currentTick >= lii.dwTime ? (currentTick - lii.dwTime) : 0;
            return (float)idleTicks / 1000.0f;
        }
        return -1.0f;
    }

    public static string GetSessionLockState(int sessionId) {
        IntPtr pBuffer = IntPtr.Zero;
        int bytesReturned = 0;
        try {
            if (WTSQuerySessionInformationW(IntPtr.Zero, sessionId, 25, out pBuffer, out bytesReturned)) {
                if (bytesReturned >= 32) {
                    int level = Marshal.ReadInt32(pBuffer, 0);
                    if (level == 1) {
                        int sessionFlags = Marshal.ReadInt32(pBuffer, 16);
                        if (sessionFlags == 0) return "locked";
                        if (sessionFlags == 1) return "unlocked";
                    }
                }
            }
        } catch {}
        finally {
            if (pBuffer != IntPtr.Zero) WTSFreeMemory(pBuffer);
        }
        return "unknown";
    }
}
"@
    Add-Type -TypeDefinition $csharpCode -ErrorAction SilentlyContinue

    $idleSeconds = [GivovaWin32Diag]::GetIdleSeconds()
    $lockState = [GivovaWin32Diag]::GetSessionLockState($winSessionId)

    if ($lockState -eq "locked") {
        $sessionState = "bloqueado"
    } elseif ($idleSeconds -ge $configuredThreshold) {
        $sessionState = "ocioso"
    } elseif ($idleSeconds -ge 0) {
        $sessionState = "ativo"
    }

    Write-Host "  [OK] GetLastInputInfo: $($idleSeconds.ToString('F1'))s sem interacao local" -ForegroundColor Green
    Write-Host "  [OK] WTSQuerySessionInformation (Sessao $winSessionId): estado = $lockState" -ForegroundColor Green
    Write-Host "  [OK] Limiar de inatividade configurado: ${configuredThreshold}s ($([math]::Round($configuredThreshold/60, 1)) min)" -ForegroundColor Gray
    Write-Host "  [OK] Estado inferido da sessao: $sessionState" -ForegroundColor $(if ($sessionState -eq "ativo") { "Green" } elseif ($sessionState -eq "ocioso") { "Yellow" } else { "Cyan" })
} catch {
    Write-Host "  [WARNING] Nao foi possivel consultar chamadas Win32 diretamente no PowerShell: $_" -ForegroundColor Yellow
}

# -------------------------------------------------------------------------
# RESUMO ESTRUTURADO DE DIAGNOSTICO (CONFORME ESPECIFICACAO OFICIAL)
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "                PAINEL RESUMO DE DIAGNOSTICO                    " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

$agentRunning = if ((Get-Process -Name "GivovaMonitorAgent" -ErrorAction SilentlyContinue)) { "OK" } else { "NO" }
$taskState = "NOT FOUND"
$taskLastResult = "N/A"
try {
    $task = Get-ScheduledTask -TaskName "Givova Monitor Agent" -ErrorAction SilentlyContinue
    if ($task) {
        $taskState = "OK"
        $info = Get-ScheduledTaskInfo -TaskName "Givova Monitor Agent" -ErrorAction SilentlyContinue
        if ($info) { $taskLastResult = $info.LastTaskResult.ToString() }
    }
} catch {}

Write-Host "Agent installed:                   $configPathStatus"
Write-Host "Agent running:                     $agentRunning"
Write-Host "Agent version:                     $detectedAgentVersion"
Write-Host ""
Write-Host "Config path:                       $configPathStatus"
Write-Host "Server URL:                        $(if ($serverUrl.StartsWith('https://')) { 'OK' } else { 'INSECURE' })"
Write-Host "Token present:                     $tokenPresent"
Write-Host "Token validation:                  $tokenValidation"
Write-Host ""
Write-Host "Render /health:                    $renderHealth"
Write-Host "Render /health/db:                 $renderDb"
Write-Host ""
Write-Host "Last report attempt:               $lastAttempt"
Write-Host "Last report HTTP status:           $lastHttpStatus"
Write-Host "Last successful report:            $lastSuccessReport"
Write-Host ""
Write-Host "Session state (v1.5.0):            $sessionState"
Write-Host "Idle seconds:                      $(if ($idleSeconds -ge 0) { "$($idleSeconds.ToString('F1'))s" } else { 'N/A' })"
Write-Host "Idle threshold:                    ${configuredThreshold}s"
Write-Host "Lock state:                        $lockState"
Write-Host ""
Write-Host "Task Scheduler:                    $taskState"
Write-Host "Task Last Result:                  $taskLastResult"
Write-Host ""
Write-Host "GIVOVA_CONFIG_PATH override:       $overrideActive"
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
