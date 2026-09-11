# ==============================================================================
# GIVOVA TRANSPORTES — PUBLICADOR E GERADOR DE RELEASES DO AGENTE
# ==============================================================================
# Prepara uma nova versão do agente para distribuição e auto-update:
# 1. Valida a versão semântica (ex: 1.4.0)
# 2. Localiza ou compila o binário Windows (GivovaMonitorAgent.exe)
# 3. Calcula o hash SHA-256 de integridade
# 4. Gera o manifest.json compatível com a API /api/agent/update
# 5. Estrutura a release em dist\releases\versao\
# 6. Opcionalmente publica no servidor via /api/admin/releases/publish
# 7. Fornece instruções para publicação via GitHub Releases.
# ==============================================================================

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [string]$ServerUrl = "https://monitoramento-gb9g.onrender.com",
    [string]$DownloadUrl = "",
    [string]$MinSupportedVersion = "1.0.0",
    [string]$Changelog = "Atualização corporativa de monitoramento e conformidade de políticas.",
    [switch]$Mandatory,
    [switch]$PublishToServer,
    [string]$AdminUser = "",
    [string]$AdminPassword = "",
    [string]$ExistingExePath = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $repoRoot) {
    $repoRoot = (Get-Location).Path
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor DarkCyan
Write-Host "    GIVOVA TRANSPORTES — PUBLICAÇÃO DE RELEASE DO AGENTE        " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor DarkCyan
Write-Host "Versão Alvo:       $Version" -ForegroundColor Yellow
Write-Host "Servidor Alvo:     $ServerUrl" -ForegroundColor Gray
Write-Host "Raiz do Projeto:   $repoRoot" -ForegroundColor Gray
Write-Host ""

# -------------------------------------------------------------------------
# 1. LOCALIZAÇÃO OU COMPILAÇÃO DO EXECUTÁVEL
# -------------------------------------------------------------------------
$exeToPublish = $null

if ($ExistingExePath -and (Test-Path -Path $ExistingExePath)) {
    $exeToPublish = (Resolve-Path $ExistingExePath).Path
    Write-Host "[1/4] Usando executável informado: $exeToPublish" -ForegroundColor Green
} else {
    $candidateExe = Join-Path $repoRoot "dist\GivovaMonitorAgent.exe"
    $deployCandidate = Join-Path $repoRoot "dist\GivovaMonitorDeploy\GivovaMonitorAgent.exe"

    if (Test-Path -Path $candidateExe) {
        $exeToPublish = $candidateExe
        Write-Host "[1/4] Usando executável existente em: $exeToPublish" -ForegroundColor Green
    } elseif (Test-Path -Path $deployCandidate) {
        $exeToPublish = $deployCandidate
        Write-Host "[1/4] Usando executável existente em: $exeToPublish" -ForegroundColor Green
    } else {
        Write-Host "[1/4] Binário não encontrado. Iniciando compilação via PyInstaller..." -ForegroundColor Yellow
        $buildScript = Join-Path $repoRoot "scripts\Build-GivovaMonitor.ps1"
        if (Test-Path -Path $buildScript) {
            & powershell -ExecutionPolicy Bypass -File $buildScript
            if (Test-Path -Path $candidateExe) {
                $exeToPublish = $candidateExe
            } else {
                Write-Error "Falha ao compilar GivovaMonitorAgent.exe. Abortando publicação."
                exit 1
            }
        } else {
            Write-Error "Script Build-GivovaMonitor.ps1 não encontrado em $buildScript."
            exit 1
        }
    }
}

$exeSizeMb = [math]::Round(((Get-Item $exeToPublish).Length / 1MB), 2)
Write-Host "      Tamanho do binário: ${exeSizeMb} MB" -ForegroundColor Gray

# -------------------------------------------------------------------------
# 2. CÁLCULO DO HASH SHA-256 (INTEGRIDADE CRIPTOGRÁFICA)
# -------------------------------------------------------------------------
Write-Host "[2/4] Calculando hash criptográfico SHA-256..." -ForegroundColor Gray
$fileHash = (Get-FileHash -Path $exeToPublish -Algorithm SHA256).Hash.ToLower()
Write-Host "      SHA-256: $fileHash" -ForegroundColor Green

# -------------------------------------------------------------------------
# 3. MONTAGEM DA RELEASE LOCAL E MANIFESTO
# -------------------------------------------------------------------------
Write-Host "[3/4] Gerando pacote de release e manifest.json..." -ForegroundColor Gray

# Diretório de releases na máquina local da TI (protegido pelo .gitignore)
$releaseFolder = Join-Path $repoRoot "dist\releases\$Version"
if (-not (Test-Path -Path $releaseFolder)) {
    New-Item -Path $releaseFolder -ItemType Directory -Force | Out-Null
}

$releaseExeDest = Join-Path $releaseFolder "GivovaMonitorAgent.exe"
Copy-Item -Path $exeToPublish -Destination $releaseExeDest -Force

$effectiveDownloadUrl = $DownloadUrl
if (-not $effectiveDownloadUrl) {
    $cleanServer = $ServerUrl.TrimEnd('/')
    $effectiveDownloadUrl = "$cleanServer/api/agent/download/$Version"
}

$todayIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$manifest = @{
    version = $Version
    min_supported_version = $MinSupportedVersion
    release_date = $todayIso
    download_url = $effectiveDownloadUrl
    sha256 = $fileHash
    changelog = $Changelog
    mandatory = [bool]$Mandatory
}

$manifestJson = $manifest | ConvertTo-Json -Depth 4
$manifestPath = Join-Path $releaseFolder "manifest.json"
$manifestJson | Set-Content -Path $manifestPath -Encoding UTF8

# Copia manifesto para dist\releases\manifest.json (ponteiro para a última versão)
$rootManifestPath = Join-Path $repoRoot "dist\releases\manifest.json"
$manifestJson | Set-Content -Path $rootManifestPath -Encoding UTF8

Write-Host "      Release gerada em: $releaseFolder" -ForegroundColor Green
Write-Host "      Manifesto gerado:  $manifestPath" -ForegroundColor Green

# -------------------------------------------------------------------------
# 4. PUBLICAÇÃO AUTOMÁTICA VIA API DO SERVIDOR (OPCIONAL)
# -------------------------------------------------------------------------
if ($PublishToServer) {
    Write-Host "[4/4] Publicando release no servidor Render..." -ForegroundColor Cyan

    $cleanServer = $ServerUrl.TrimEnd('/')
    $publishEndpoint = "$cleanServer/api/admin/releases/publish"
    $loginEndpoint = "$cleanServer/login"

    if (-not $AdminUser -or -not $AdminPassword) {
        Write-Host "      Credenciais de admin não fornecidas. Solicitando..." -ForegroundColor Yellow
        $cred = Get-Credential -UserName "admin" -Message "Informe o usuário e senha do Dashboard da Givova Transportes:"
        $AdminUser = $cred.UserName
        $AdminPassword = $cred.GetNetworkCredential().Password
    }

    try {
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

        # 1. Login no Dashboard
        Write-Host "      Autenticando como '$AdminUser'..." -ForegroundColor Gray
        $loginBody = @{
            username = $AdminUser
            password = $AdminPassword
        }
        $loginResp = Invoke-WebRequest -Uri $loginEndpoint -Method POST -Body $loginBody -WebSession $session -MaximumRedirection 0 -ErrorAction SilentlyContinue

        # 2. Upload do binário e manifesto
        Write-Host "      Enviando executável e manifesto para $publishEndpoint..." -ForegroundColor Gray

        # Cria corpo multipart manual para compatibilidade
        $boundary = [System.Guid]::NewGuid().ToString()
        $CRLF = "`r`n"
        $fileBytes = [System.IO.File]::ReadAllBytes($releaseExeDest)
        $fileHeader = "--$boundary" + $CRLF +
                      'Content-Disposition: form-data; name="file"; filename="GivovaMonitorAgent.exe"' + $CRLF +
                      'Content-Type: application/octet-stream' + $CRLF + $CRLF
        $manifestPart = $CRLF + "--$boundary" + $CRLF +
                        'Content-Disposition: form-data; name="manifest"' + $CRLF + $CRLF +
                        $manifestJson + $CRLF + "--$boundary--" + $CRLF

        $headerBytes = [System.Text.Encoding]::UTF8.GetBytes($fileHeader)
        $trailerBytes = [System.Text.Encoding]::UTF8.GetBytes($manifestPart)

        $totalBody = New-Object byte[] ($headerBytes.Length + $fileBytes.Length + $trailerBytes.Length)
        [System.Buffer]::BlockCopy($headerBytes, 0, $totalBody, 0, $headerBytes.Length)
        [System.Buffer]::BlockCopy($fileBytes, 0, $totalBody, $headerBytes.Length, $fileBytes.Length)
        [System.Buffer]::BlockCopy($trailerBytes, 0, $totalBody, $headerBytes.Length + $fileBytes.Length, $trailerBytes.Length)

        $headers = @{
            "Content-Type" = "multipart/form-data; boundary=$boundary"
        }

        $publishResp = Invoke-RestMethod -Uri $publishEndpoint -Method POST -Body $totalBody -Headers $headers -WebSession $session
        Write-Host "      Sucesso na publicação no servidor: $($publishResp.message)" -ForegroundColor Green
    } catch {
        Write-Warning "Não foi possível publicar diretamente no servidor via API: $_"
        Write-Warning "Você pode hospedar o binário no GitHub Releases ou configurar STORAGE_BACKEND."
    }
} else {
    Write-Host "[4/4] Publicação remota ignorada (use -PublishToServer para upload automático)." -ForegroundColor Gray
}

# -------------------------------------------------------------------------
# RESUMO FINAL E ORIENTAÇÃO PARA GITHUB RELEASES
# -------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "       RELEASE $Version DO AGENTE GERADA COM SUCESSO!           " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Versão:          $Version" -ForegroundColor Yellow
Write-Host "  SHA-256:         $fileHash" -ForegroundColor Cyan
Write-Host "  Pasta Local:     $releaseFolder" -ForegroundColor Gray
Write-Host "  URL de Download: $effectiveDownloadUrl" -ForegroundColor Gray
Write-Host ""
Write-Host "DISTRIBUIÇÃO EM PRODUÇÃO (RENDER / GITHUB RELEASES):" -ForegroundColor White
Write-Host " 1. Como o filesystem do Render é efêmero e binários .exe não são" -ForegroundColor Gray
Write-Host "    commitados no Git, crie uma Release no GitHub:" -ForegroundColor Gray
Write-Host "    - Tag: v$Version" -ForegroundColor Gray
Write-Host "    - Anexe: dist\releases\$Version\GivovaMonitorAgent.exe" -ForegroundColor Gray
Write-Host "    - URL do Asset: https://github.com/<org>/Monitoramento/releases/download/v$Version/GivovaMonitorAgent.exe" -ForegroundColor Gray
Write-Host " 2. Defina no Render a variável de ambiente:" -ForegroundColor Gray
Write-Host "    LATEST_AGENT_VERSION=$Version" -ForegroundColor Yellow
Write-Host " 3. Os agentes autorizados nos terminais Windows consultarão o servidor" -ForegroundColor Gray
Write-Host "    e realizarão a atualização automática e segura com rollback." -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
