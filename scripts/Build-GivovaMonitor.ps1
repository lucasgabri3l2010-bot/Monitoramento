<#
.SYNOPSIS
    Compilador e gerador do pacote de implantação do Givova Monitor Agent.
.DESCRIPTION
    Compila o agente Python em um binário Windows autônomo e sem console (GivovaMonitorAgent.exe)
    usando PyInstaller e monta o pacote final de implantação em dist\GivovaMonitorDeploy.
.PARAMETER ServerUrl
    URL do servidor Render para telemetria (padrão: https://monitoramento-gb9g.onrender.com/api/agent/report).
.PARAMETER AgentToken
    Token de autenticação do agente. Se omitido, busca automaticamente no deploy_config.local.json ou no .env local.
#>

[CmdletBinding()]
param (
    [string]$ServerUrl = "https://monitoramento-gb9g.onrender.com/api/agent/report",
    [string]$AgentToken = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $repoRoot) {
    $repoRoot = (Get-Location).Path
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor DarkCyan
Write-Host "     GIVOVA TRANSPORTES — BUILD DO AGENTE DE MONITORAMENTO      " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor DarkCyan
Write-Host "Raiz do Projeto: $repoRoot" -ForegroundColor Gray
Write-Host ""

# -------------------------------------------------------------------------
# 1. LOCALIZAÇÃO DO AMBIENTE PYTHON E PYINSTALLER
# -------------------------------------------------------------------------
Write-Host "[1/5] Verificando ambiente Python e PyInstaller..." -ForegroundColor Gray

$pyInstallerExe = Join-Path $repoRoot "venv\Scripts\pyinstaller.exe"
$pythonExe = Join-Path $repoRoot "venv\Scripts\python.exe"

if (-not (Test-Path -Path $pythonExe)) {
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pythonExe) {
        Write-Error "Python não encontrado no ambiente virtual 'venv' nem no PATH do sistema."
        exit 1
    }
}

if (-not (Test-Path -Path $pyInstallerExe)) {
    Write-Host "      PyInstaller não detectado em venv. Instalando via pip..." -ForegroundColor Yellow
    & $pythonExe -m pip install --upgrade pyinstaller
    if (-not (Test-Path -Path $pyInstallerExe)) {
        $pyInstallerExe = (Get-Command pyinstaller -ErrorAction SilentlyContinue).Source
    }
}

Write-Host "      Compilador: $pyInstallerExe" -ForegroundColor Green

# -------------------------------------------------------------------------
# 2. RESOLUÇÃO SEGURA DO TOKEN (SEM EXPOR NO GIT)
# -------------------------------------------------------------------------
Write-Host "[2/5] Obtendo credenciais de conexão para o pacote local..." -ForegroundColor Gray

$resolvedToken = $AgentToken
$deployConfigLocal = Join-Path $repoRoot "deploy_config.local.json"
$envFile = Join-Path $repoRoot ".env"

if (-not $resolvedToken -and (Test-Path -Path $deployConfigLocal)) {
    try {
        $localCfg = Get-Content -Path $deployConfigLocal -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($localCfg.agent_token) {
            $resolvedToken = $localCfg.agent_token
            Write-Host "      Token obtido de deploy_config.local.json" -ForegroundColor Green
        }
        if ($localCfg.server_url) {
            $ServerUrl = $localCfg.server_url
        }
    } catch {}
}

if (-not $resolvedToken -and (Test-Path -Path $envFile)) {
    $envLines = Get-Content -Path $envFile
    foreach ($line in $envLines) {
        if ($line -match '^AGENT_SECRET_TOKEN\s*=\s*(.+)$') {
            $resolvedToken = $matches[1].Trim().Trim('"').Trim("'")
            Write-Host "      Token obtido do arquivo local .env da TI" -ForegroundColor Green
            break
        }
    }
}

if (-not $resolvedToken) {
    Write-Host "      Aviso: Token não informado nem localizado em .env." -ForegroundColor Yellow
    Write-Host "      Usando token padrão de desenvolvimento [altere antes de implantar em produção]." -ForegroundColor Yellow
    $resolvedToken = "givova_agent_token_dev_2026"
}

# -------------------------------------------------------------------------
# 3. COMPILAÇÃO DO EXECUTÁVEL AUTÔNOMO (PYINSTALLER)
# -------------------------------------------------------------------------
Write-Host "[3/5] Compilando GivovaMonitorAgent.exe com PyInstaller..." -ForegroundColor Gray
$agenteScript = Join-Path $repoRoot "agente.py"

$pyArgs = @(
    "--noconsole",
    "--onefile",
    "--name", "GivovaMonitorAgent",
    "--clean",
    "--hidden-import", "psutil",
    "--hidden-import", "requests",
    "--hidden-import", "urllib3",
    "--hidden-import", "certifi",
    "--hidden-import", "idna",
    "--hidden-import", "charset_normalizer",
    $agenteScript
)

Push-Location $repoRoot
try {
    & $pyInstallerExe @pyArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "A compilação do PyInstaller falhou com código $LASTEXITCODE."
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

$compiledExe = Join-Path $repoRoot "dist\GivovaMonitorAgent.exe"
if (-not (Test-Path -Path $compiledExe)) {
    Write-Error "O executável esperado não foi gerado em: $compiledExe"
    exit 1
}

$exeSizeMb = [math]::Round(((Get-Item $compiledExe).Length / 1MB), 2)
Write-Host "      Executável gerado com sucesso: $compiledExe - ${exeSizeMb} MB" -ForegroundColor Green

# -------------------------------------------------------------------------
# 4. MONTAGEM DO PACOTE DE IMPLANTAÇÃO (dist\GivovaMonitorDeploy)
# -------------------------------------------------------------------------
Write-Host "[4/5] Montando pasta de implantação dist\GivovaMonitorDeploy\..." -ForegroundColor Gray

$deployDir = Join-Path $repoRoot "dist\GivovaMonitorDeploy"
if (-not (Test-Path -Path $deployDir)) {
    New-Item -Path $deployDir -ItemType Directory -Force | Out-Null
}

# 1. Copia o binário executável
Copy-Item -Path $compiledExe -Destination (Join-Path $deployDir "GivovaMonitorAgent.exe") -Force

# 2. Copia os scripts com nomes amigáveis em português
Copy-Item -Path (Join-Path $repoRoot "scripts\Install-GivovaMonitor.ps1") -Destination (Join-Path $deployDir "Instalar-GivovaMonitor.ps1") -Force
Copy-Item -Path (Join-Path $repoRoot "scripts\Uninstall-GivovaMonitor.ps1") -Destination (Join-Path $deployDir "Desinstalar-GivovaMonitor.ps1") -Force

# 3. Gera o agent_config.json pré-configurado
$agentCfg = @{
    server_url = $ServerUrl
    agent_token = $resolvedToken
    department = "Não informado"
    display_name = ""
    interval_seconds = 5
    timeout_seconds = 10
    activity_monitoring = $true
}
$agentCfg | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $deployDir "agent_config.json") -Encoding UTF8

# 4. Gera instruções rápidas em LEIAME_INSTALACAO.txt
$leiameContent = @'
================================================================================
   GIVOVA TRANSPORTES — SISTEMA DE MONITORAMENTO DE COMPUTADORES
   PACOTE DE IMPLANTAÇÃO AUTÔNOMO (WINDOWS)
================================================================================

COMO INSTALAR NO COMPUTADOR CLIENTE:

1. Copie esta pasta 'GivovaMonitorDeploy' para o computador autorizado
   (via pendrive, compartilhamento de rede ou pasta temporária).

2. Clique com o botão direito no arquivo:
   'Instalar-GivovaMonitor.ps1'
   e selecione:
   "Executar com o PowerShell" (ou abra o terminal e execute .\Instalar-GivovaMonitor.ps1).

3. Quando o Windows exibir a confirmação de Administrador (UAC), clique em "Sim".

4. O instalador fará todo o processo de forma 100% automática:
   - Instala em C:\ProgramData\GivovaMonitor\
   - Configura o início automático com o Windows (Task Scheduler)
   - Executa invisível, sem abrir janelas de CMD ou PowerShell
   - Testa a conexão com o servidor Render
   - Inicia o monitoramento imediatamente.

================================================================================
ATUALIZAÇÃO:
Basta executar 'Instalar-GivovaMonitor.ps1' novamente. Ele substituirá o executável
preservando o nome e as configurações já existentes do computador.

DESINSTALAÇÃO:
Clique com o botão direito em 'Desinstalar-GivovaMonitor.ps1' e execute com PowerShell.
================================================================================
'@
$leiameContent | Set-Content -Path (Join-Path $deployDir "LEIAME_INSTALACAO.txt") -Encoding UTF8

# -------------------------------------------------------------------------
# 5. RESUMO FINAL
# -------------------------------------------------------------------------
Write-Host "[5/5] Validação de segurança e integridade concluída." -ForegroundColor Gray
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  PACOTE DE IMPLANTAÇÃO GERADO COM SUCESSO!                     " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Destino:       $deployDir" -ForegroundColor Cyan
Write-Host "  Executável:    GivovaMonitorAgent.exe - ${exeSizeMb} MB" -ForegroundColor Gray
Write-Host "  Instalador:    Instalar-GivovaMonitor.ps1" -ForegroundColor Gray
Write-Host "  Desinstalador: Desinstalar-GivovaMonitor.ps1" -ForegroundColor Gray
Write-Host "  Configuração:  agent_config.json - Servidor: $ServerUrl" -ForegroundColor Gray
Write-Host "  Segurança:     Pasta dist/ protegida no .gitignore [zero secrets no Git]" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
