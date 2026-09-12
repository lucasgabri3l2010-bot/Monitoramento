<#
.SYNOPSIS
    Compilador e gerador do pacote oficial de implantacao do Givova Monitor Agent.
.DESCRIPTION
    Compila os executaveis GivovaMonitorAgent.exe e GivovaMonitorUpdater.exe do zero,
    valida rigorosamente a configuracao de producao (rejeita localhost e tokens ausentes),
    monta a pasta oficial dist\GivovaMonitorDeploy e gera o deployment_manifest.json sem secrets.
.PARAMETER ServerUrl
    URL do servidor para telemetria. Se omitida, busca em deploy_config.local.json, GIVOVA_PRODUCTION_SERVER_URL ou agent_config.json.
.PARAMETER AgentToken
    Token de autenticacao do agente. Se omitido, busca em deploy_config.local.json, agent_config.json ou .env local.
.PARAMETER Force
    Executa o build sem prompts interativos.
#>

[CmdletBinding(PositionalBinding=$false)]
param (
    [Parameter(Mandatory=$false)]
    [string]$ServerUrl = "",

    [Parameter(Mandatory=$false)]
    [string]$AgentToken = "",

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $repoRoot) {
    $repoRoot = (Get-Location).Path
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor DarkCyan
Write-Host "     GIVOVA TRANSPORTES -- REBUILD DO PACOTE OFICIAL DE DEPLOY   " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor DarkCyan
Write-Host "Raiz do Projeto: $repoRoot" -ForegroundColor Gray
Write-Host ""

# -------------------------------------------------------------------------
# 1. LIMPEZA TOTAL DE ARTEFATOS ANTERIORES
# -------------------------------------------------------------------------
Write-Host "[1/6] Limpando artefatos e diretorios anteriores..." -ForegroundColor Gray

$buildAgentDir = Join-Path $repoRoot "build\GivovaMonitorAgent"
$buildUpdaterDir = Join-Path $repoRoot "build\GivovaMonitorUpdater"
$distDeployDir = Join-Path $repoRoot "dist\GivovaMonitorDeploy"
$distAgentExe = Join-Path $repoRoot "dist\GivovaMonitorAgent.exe"
$distUpdaterExe = Join-Path $repoRoot "dist\GivovaMonitorUpdater.exe"

foreach ($dir in @($buildAgentDir, $buildUpdaterDir, $distDeployDir)) {
    if (Test-Path -Path $dir) {
        Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

foreach ($f in @($distAgentExe, $distUpdaterExe)) {
    if (Test-Path -Path $f) {
        Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "      Diretorios de build e deploy limpos com sucesso." -ForegroundColor Green

# -------------------------------------------------------------------------
# 2. LOCALIZACAO DO AMBIENTE PYTHON E PYINSTALLER
# -------------------------------------------------------------------------
Write-Host "[2/6] Verificando ambiente Python e PyInstaller..." -ForegroundColor Gray

$pythonExe = Join-Path $repoRoot "venv\Scripts\python.exe"
$pyInstallerExe = Join-Path $repoRoot "venv\Scripts\pyinstaller.exe"

if (-not (Test-Path -Path $pythonExe)) {
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pythonExe) {
        Write-Error "Python nao encontrado no ambiente virtual 'venv' nem no PATH do sistema."
        exit 1
    }
}

if (-not (Test-Path -Path $pyInstallerExe)) {
    Write-Host "      PyInstaller nao detectado em venv. Instalando via pip..." -ForegroundColor Yellow
    & $pythonExe -m pip install --upgrade pyinstaller
    if (-not (Test-Path -Path $pyInstallerExe)) {
        $pyInstallerExe = (Get-Command pyinstaller -ErrorAction SilentlyContinue).Source
    }
}

Write-Host "      Python:      $pythonExe" -ForegroundColor Green
Write-Host "      Compilador:  $pyInstallerExe" -ForegroundColor Green

# -------------------------------------------------------------------------
# 3. RESOLUCAO E VALIDACAO DA CONFIGURACAO DE PRODUCAO
# -------------------------------------------------------------------------
Write-Host "[3/6] Resolvendo e validando parametros de producao..." -ForegroundColor Gray

$resolvedServerUrl = $ServerUrl
$resolvedToken = $AgentToken
$resolvedDept = "TI"
$resolvedDisplayName = "PC Victor - TI"

$deployConfigLocal = Join-Path $repoRoot "deploy_config.local.json"
$rootAgentConfig = Join-Path $repoRoot "agent_config.json"
$envFile = Join-Path $repoRoot ".env"

# 3.1 Resolucao da URL
if (-not $resolvedServerUrl) {
    if ($env:GIVOVA_PRODUCTION_SERVER_URL) {
        $resolvedServerUrl = $env:GIVOVA_PRODUCTION_SERVER_URL
        Write-Host "      ServerUrl obtido de variavel de ambiente GIVOVA_PRODUCTION_SERVER_URL" -ForegroundColor Green
    } elseif (Test-Path -Path $deployConfigLocal) {
        try {
            $lcfg = Get-Content -Path $deployConfigLocal -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($lcfg.server_url) { $resolvedServerUrl = $lcfg.server_url }
        } catch {}
    }
}

if (-not $resolvedServerUrl) {
    $resolvedServerUrl = "https://monitoramento-gb9g.onrender.com/api/agent/report"
}

# 3.2 Resolucao do Token (Fontes locais nao versionadas estritamente)
# 1. Parametro explicito -AgentToken
if (-not $resolvedToken -and ($PSBoundParameters.ContainsKey('AgentToken')) -and $AgentToken) {
    $resolvedToken = $AgentToken
    Write-Host "      Token obtido via parametro de linha de comando (-AgentToken)" -ForegroundColor Green
}

# 2. Variavel de ambiente local
if (-not $resolvedToken) {
    if ($env:AGENT_TOKEN) {
        $resolvedToken = $env:AGENT_TOKEN
        Write-Host "      Token obtido de variavel de ambiente AGENT_TOKEN" -ForegroundColor Green
    } elseif ($env:AGENT_SECRET_TOKEN) {
        $resolvedToken = $env:AGENT_SECRET_TOKEN
        Write-Host "      Token obtido de variavel de ambiente AGENT_SECRET_TOKEN" -ForegroundColor Green
    }
}

# 3. deploy_config.local.json (arquivo local nao versionado listado no .gitignore)
if (-not $resolvedToken -and (Test-Path -Path $deployConfigLocal)) {
    try {
        $lcfg = Get-Content -Path $deployConfigLocal -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($lcfg.agent_token) {
            $resolvedToken = $lcfg.agent_token
            Write-Host "      Token obtido de deploy_config.local.json" -ForegroundColor Green
        }
    } catch {}
}

# 3.3 VALIDACAO RIGIDA DE SEGURANCA E PRODUCAO
$validationErrors = @()

if (-not $resolvedServerUrl.StartsWith("https://", [System.StringComparison]::OrdinalIgnoreCase)) {
    $validationErrors += "Server URL deve utilizar HTTPS obrigatorio: $resolvedServerUrl"
}

if (-not ($resolvedServerUrl.EndsWith("/api/agent/report") -or $resolvedServerUrl.EndsWith("/monitoramento"))) {
    $validationErrors += "Server URL deve terminar em /api/agent/report: $resolvedServerUrl"
}

if ($resolvedServerUrl -match 'localhost|127\.0\.0\.1') {
    $validationErrors += "Server URL de producao nao pode apontar para localhost ou 127.0.0.1: $resolvedServerUrl"
}

if (-not $resolvedToken -or $resolvedToken.Trim() -eq "") {
    $validationErrors += "BUILD ABORTED: production Agent token is missing."
} elseif ($resolvedToken -match 'COPIE_O_AGENT_SECRET_TOKEN|YOUR_TOKEN_HERE|<TOKEN>|informado|placeholder') {
    $validationErrors += "Token detectado e um placeholder generico nao preenchido."
} elseif ($resolvedToken.Length -lt 16) {
    $validationErrors += "Token informado tem comprimento insuficiente (menos de 16 caracteres)."
} elseif ($resolvedToken -match '\s') {
    $validationErrors += "Token informado contem espacos invalidos."
}

if ($validationErrors.Count -gt 0) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "  ERRO CRITICO NA VALIDACAO DA CONFIGURACAO DE PRODUCAO         " -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    foreach ($err in $validationErrors) {
        Write-Host " - $err" -ForegroundColor Red
    }
    Write-Host ""
    Write-Error "BUILD ABORTED: production Agent token is missing."
    exit 1
}

Write-Host "      Server URL:  $resolvedServerUrl" -ForegroundColor Green
Write-Host "      Token:       Presente e validado [credencial segura de producao]" -ForegroundColor Green
Write-Host "      Setor:       $resolvedDept" -ForegroundColor Gray
Write-Host "      Dispositivo: $resolvedDisplayName" -ForegroundColor Gray

# -------------------------------------------------------------------------
# 4. RECOMPILACAO LIMPA COM PYINSTALLER
# -------------------------------------------------------------------------
Write-Host "[4/6] Recompilando binarios com PyInstaller (codigo mais recente)..." -ForegroundColor Gray

# 4.1 Compilacao do GivovaMonitorAgent.exe
$agenteScript = Join-Path $repoRoot "agente.py"
Write-Host "      Compilando GivovaMonitorAgent.exe..." -ForegroundColor Gray

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
        Write-Error "A compilacao do GivovaMonitorAgent.exe falhou com codigo $LASTEXITCODE."
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

if (-not (Test-Path -Path $distAgentExe)) {
    Write-Error "O executavel esperado nao foi gerado em: $distAgentExe"
    exit 1
}

$agentSizeMb = [math]::Round(((Get-Item $distAgentExe).Length / 1MB), 2)
Write-Host "      [OK] GivovaMonitorAgent.exe gerado: ${agentSizeMb} MB" -ForegroundColor Green

# 4.2 Compilacao do GivovaMonitorUpdater.exe
$updaterScript = Join-Path $repoRoot "updater.py"
Write-Host "      Compilando GivovaMonitorUpdater.exe..." -ForegroundColor Gray

$updaterArgs = @(
    "--noconsole",
    "--onefile",
    "--name", "GivovaMonitorUpdater",
    "--clean",
    $updaterScript
)

Push-Location $repoRoot
try {
    & $pyInstallerExe @updaterArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "A compilacao do GivovaMonitorUpdater.exe falhou com codigo $LASTEXITCODE."
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

if (-not (Test-Path -Path $distUpdaterExe)) {
    Write-Error "O executavel esperado nao foi gerado em: $distUpdaterExe"
    exit 1
}

$updaterSizeMb = [math]::Round(((Get-Item $distUpdaterExe).Length / 1MB), 2)
Write-Host "      [OK] GivovaMonitorUpdater.exe gerado: ${updaterSizeMb} MB" -ForegroundColor Green

# -------------------------------------------------------------------------
# 5. MONTAGEM LIMPA DO PACOTE OFICIAL (dist\GivovaMonitorDeploy)
# -------------------------------------------------------------------------
Write-Host "[5/6] Montando pasta oficial dist\GivovaMonitorDeploy\..." -ForegroundColor Gray

New-Item -Path $distDeployDir -ItemType Directory -Force | Out-Null

# 5.1 Binarios
Copy-Item -Path $distAgentExe -Destination (Join-Path $distDeployDir "GivovaMonitorAgent.exe") -Force
Copy-Item -Path $distUpdaterExe -Destination (Join-Path $distDeployDir "GivovaMonitorUpdater.exe") -Force

# 5.2 Scripts operacionais
Copy-Item -Path (Join-Path $repoRoot "scripts\Install-GivovaMonitor.ps1") -Destination (Join-Path $distDeployDir "Instalar-GivovaMonitor.ps1") -Force
Copy-Item -Path (Join-Path $repoRoot "scripts\Uninstall-GivovaMonitor.ps1") -Destination (Join-Path $distDeployDir "Desinstalar-GivovaMonitor.ps1") -Force
Copy-Item -Path (Join-Path $repoRoot "scripts\Diagnose-GivovaMonitor.ps1") -Destination (Join-Path $distDeployDir "Diagnose-GivovaMonitor.ps1") -Force

# 5.3 Extensao corporativa Chrome / Edge
$srcExtension = Join-Path $repoRoot "extension"
$destExtension = Join-Path $distDeployDir "extension"
New-Item -Path $destExtension -ItemType Directory -Force | Out-Null

Get-ChildItem -Path $srcExtension -File | Where-Object {
    $_.Name -notin @(".git", ".gitignore") -and
    $_.Extension -notin @(".tmp", ".bak", ".pyc")
} | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $destExtension -Force
}

# 5.4 agent_config.json de producao validado
$agentCfg = [ordered]@{
    server_url = $resolvedServerUrl
    agent_token = $resolvedToken
    department = $resolvedDept
    display_name = $resolvedDisplayName
    interval_seconds = 5
    timeout_seconds = 10
    activity_monitoring = $true
}
$agentCfg | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $distDeployDir "agent_config.json") -Encoding UTF8

# 5.5 Extracao de versoes para manifesto e documentacao
$agentVersion = "1.4.0"
foreach ($line in (Get-Content -Path $agenteScript -ErrorAction SilentlyContinue)) {
    if ($line.Trim().StartsWith("VERSION =")) {
        $parts = $line.Split('"')
        if ($parts.Length -ge 2) {
            $agentVersion = $parts[1]
            break
        }
    }
}

$updaterVersion = "1.1.0"
foreach ($line in (Get-Content -Path $updaterScript -ErrorAction SilentlyContinue)) {
    if ($line.Trim().StartsWith("UPDATER_VERSION =")) {
        $parts = $line.Split('"')
        if ($parts.Length -ge 2) {
            $updaterVersion = $parts[1]
            break
        }
    }
}

$manifestJsonPath = Join-Path $srcExtension "manifest.json"
$extensionVersion = "1.0.0"
if (Test-Path -Path $manifestJsonPath) {
    try {
        $mObj = Get-Content -Path $manifestJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($mObj.version) { $extensionVersion = $mObj.version }
    } catch {}
}

# 5.6 Calculo de Hashes SHA-256 dos executaveis e arquivos da extensao
$shaAgent = (Get-FileHash -Path (Join-Path $distDeployDir "GivovaMonitorAgent.exe") -Algorithm SHA256).Hash.ToLower()
$shaUpdater = (Get-FileHash -Path (Join-Path $distDeployDir "GivovaMonitorUpdater.exe") -Algorithm SHA256).Hash.ToLower()
$buildDateIso = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")

# 5.7 Geracao do deployment_manifest.json (SEM SECRETS)
$manifestObj = [ordered]@{
    package_name = "GivovaMonitorDeploy"
    build_date = $buildDateIso
    agent_version = $agentVersion
    updater_version = $updaterVersion
    extension_version = $extensionVersion
    server_url = $resolvedServerUrl
    binaries = [ordered]@{
        "GivovaMonitorAgent.exe" = [ordered]@{
            sha256 = $shaAgent
            size_bytes = (Get-Item (Join-Path $distDeployDir "GivovaMonitorAgent.exe")).Length
        }
        "GivovaMonitorUpdater.exe" = [ordered]@{
            sha256 = $shaUpdater
            size_bytes = (Get-Item (Join-Path $distDeployDir "GivovaMonitorUpdater.exe")).Length
        }
    }
    extension_files = @(Get-ChildItem -Path $destExtension -File | ForEach-Object { $_.Name })
}
$manifestObj | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $distDeployDir "deployment_manifest.json") -Encoding UTF8

# 5.8 Geracao do LEIAME_INSTALACAO.txt
$leiameLines = @(
    "================================================================================",
    "   GIVOVA TRANSPORTES -- SISTEMA DE MONITORAMENTO DE COMPUTADORES",
    "   PACOTE OFICIAL DE IMPLANTACAO AUTONOMO (WINDOWS)",
    "================================================================================",
    "Versao do Agente:    v$agentVersion",
    "Versao do Updater:   v$updaterVersion",
    "Versao da Extensao:  v$extensionVersion",
    "Data de Geracao:     $buildDateIso",
    "Servidor Render:     $resolvedServerUrl",
    "",
    "ESTRUTURA DO PACOTE:",
    "- GivovaMonitorAgent.exe       : Executavel principal do agente (invisivel em 2o plano)",
    "- GivovaMonitorUpdater.exe     : Supervisor autonomo de auto-update",
    "- Instalar-GivovaMonitor.ps1   : Instalador automatico de 1 execucao (suporta -ReplaceConfig e -Force)",
    "- Desinstalar-GivovaMonitor.ps1: Desinstalador limpo (suporta -PurgeData e -Force)",
    "- Diagnose-GivovaMonitor.ps1   : Diagnostico de saude, extensao e conectividade",
    "- agent_config.json            : Parametros pre-configurados e validados de producao",
    "- extension\                   : Arquivos da extensao corporativa (Chrome e Edge Manifest V3)",
    "- deployment_manifest.json     : Manifesto de integridade com hashes SHA-256 (sem secrets)",
    "",
    "================================================================================",
    "COMO INSTALAR NO COMPUTADOR CLIENTE:",
    "================================================================================",
    "",
    "1. Copie esta pasta 'GivovaMonitorDeploy' para o computador autorizado",
    "   (via pendrive, compartilhamento de rede ou pasta temporaria).",
    "",
    "2. Clique com o botao direito no arquivo:",
    "   'Instalar-GivovaMonitor.ps1'",
    "   e selecione:",
    "   'Executar com o PowerShell' (ou execute em um terminal PowerShell elevado).",
    "",
    "3. Quando o Windows exibir a confirmacao de Administrador (UAC), clique em 'Sim'.",
    "",
    "4. O instalador fara todo o processo de forma 100% automatica:",
    "   - Instala os binarios em C:\ProgramData\GivovaMonitor\",
    "   - Copia a extensao para C:\ProgramData\GivovaMonitor\extension\",
    "   - Configura o inicio automatico com o Windows (Task Scheduler)",
    "   - Executa invisivel, sem abrir janelas de CMD ou PowerShell",
    "   - Valida a conectividade com o servidor Render",
    "   - Inicia o monitoramento imediatamente.",
    "",
    "5. INDEPENDENCIA TOTAL DA PASTA DE DEPLOY:",
    "   Apos a conclusao da instalacao, voce pode APAGAR COMPLETAMENTE a pasta",
    "   'GivovaMonitorDeploy' do Desktop ou pendrive.",
    "   Todos os arquivos necessarios e a extensao agora residem permanentemente em:",
    "   C:\ProgramData\GivovaMonitor\",
    "",
    "================================================================================",
    "COMO ATIVAR A EXTENSAO NO NAVEGADOR (CHROME / EDGE):",
    "================================================================================",
    "",
    "Em computadores sem gerenciamento centralizado por GPO, a extensao deve ser",
    "ativada uma unica vez:",
    "",
    "No Google Chrome:",
    "1. Abra o Chrome e acesse: chrome://extensions",
    "2. Ative a chave 'Modo do desenvolvedor' (no canto superior direito).",
    "3. Clique em 'Carregar sem compactacao' (Load unpacked).",
    "4. Selecione a pasta permanente:",
    "   C:\ProgramData\GivovaMonitor\extension",
    "5. Pronto!",
    "",
    "No Microsoft Edge:",
    "1. Abra o Edge e acesse: edge://extensions",
    "2. Ative a chave 'Modo do desenvolvedor' (na barra lateral esquerda).",
    "3. Clique em 'Carregar descompactada' (Load unpacked).",
    "4. Selecione a pasta permanente:",
    "   C:\ProgramData\GivovaMonitor\extension",
    "5. Pronto!",
    "",
    "================================================================================",
    "DIAGNOSTICO E SUPORTE:",
    "================================================================================",
    "Para testar a saude da instalacao, da extensao e da conexao com o servidor, execute:",
    ".\Diagnose-GivovaMonitor.ps1",
    "",
    "================================================================================",
    "ATUALIZACAO OU SUBSTITUICAO DE CONFIGURACAO:",
    "================================================================================",
    "- Atualizacao normal:",
    "  Execute 'Instalar-GivovaMonitor.ps1'. Ele atualiza os binarios preservando a",
    "  configuracao existente do computador.",
    "",
    "- Substituicao total da configuracao:",
    "  Execute 'Instalar-GivovaMonitor.ps1 -ReplaceConfig'. Ele sobrescreve a",
    "  configuracao instalada pela configuracao deste pacote.",
    "",
    "================================================================================",
    "DESINSTALACAO:",
    "================================================================================",
    "Execute:",
    ".\Desinstalar-GivovaMonitor.ps1",
    "Para remover tambem configuracoes e logs, execute:",
    ".\Desinstalar-GivovaMonitor.ps1 -PurgeData",
    "================================================================================"
)
$leiameLines -join [Environment]::NewLine | Set-Content -Path (Join-Path $distDeployDir "LEIAME_INSTALACAO.txt") -Encoding UTF8

# 5.9 Limpeza final de seguranca (remover qualquer pasta de log residual)
$residualLogs = Join-Path $distDeployDir "logs"
if (Test-Path -Path $residualLogs) {
    Remove-Item -Path $residualLogs -Recurse -Force -ErrorAction SilentlyContinue
}

# -------------------------------------------------------------------------
# 6. RELATORIO DO BUILD E INTEGRIDADE
# -------------------------------------------------------------------------
Write-Host "[6/6] Verificando integridade dos arquivos do pacote..." -ForegroundColor Gray

$expectedFiles = @(
    "GivovaMonitorAgent.exe",
    "GivovaMonitorUpdater.exe",
    "Instalar-GivovaMonitor.ps1",
    "Desinstalar-GivovaMonitor.ps1",
    "Diagnose-GivovaMonitor.ps1",
    "agent_config.json",
    "deployment_manifest.json",
    "LEIAME_INSTALACAO.txt"
)

foreach ($f in $expectedFiles) {
    $fp = Join-Path $distDeployDir $f
    if (-not (Test-Path -Path $fp)) {
        Write-Error "Arquivo obrigatorio ausente no pacote final: $f"
        exit 1
    }
}

if (-not (Test-Path -Path (Join-Path $distDeployDir "extension\manifest.json"))) {
    Write-Error "Extensao obrigatoria ausente em: $distDeployDir\extension"
    exit 1
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  PACOTE OFICIAL DE IMPLANTACAO GERADO COM SUCESSO!             " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Destino:         $distDeployDir" -ForegroundColor Cyan
Write-Host "  Versao Agente:   v$agentVersion" -ForegroundColor Gray
Write-Host "  Versao Updater:  v$updaterVersion" -ForegroundColor Gray
Write-Host "  Versao Extensao: v$extensionVersion" -ForegroundColor Gray
Write-Host "  Servidor:        $resolvedServerUrl" -ForegroundColor Gray
Write-Host "  Hash Agent:      $shaAgent" -ForegroundColor Gray
Write-Host "  Hash Updater:    $shaUpdater" -ForegroundColor Gray
Write-Host "  Zero Secrets:    Token validado e omitido do Git/Manifesto" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
