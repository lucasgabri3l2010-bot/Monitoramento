<# Build the one-time, signed 1.5.3 migration media. No release is uploaded. #>
[CmdletBinding()]
param(
    [string]$CertificateThumbprint = $env:GIVOVA_CODESIGN_THUMBPRINT,
    [string]$TimestampUrl = $env:GIVOVA_TIMESTAMP_URL,
    [string]$PythonExe = ''
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $PythonExe) { $PythonExe = Join-Path $repo 'venv\Scripts\python.exe' }
$agent = Join-Path $repo 'releases\1.5.3\GivovaMonitorAgent.exe'
$package = Join-Path $repo 'dist\GivovaTrustedMigration-1.5.3'
$expectedAgentHash = '281e48b47dd3a6303010fd4056eba7cbbe44a98840578470f14a83613d2f7e1e'

if ($CertificateThumbprint -notmatch '^[0-9a-fA-F]{40}$' -or -not $TimestampUrl -or
    -not $TimestampUrl.StartsWith('https://')) {
    throw 'Certificado real (GIVOVA_CODESIGN_THUMBPRINT) e timestamp HTTPS sao obrigatorios.'
}
$certificate = @(Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
    Where-Object { $_.Thumbprint -eq $CertificateThumbprint -and $_.HasPrivateKey -and
                   $_.NotAfter -gt (Get-Date) -and $_.EnhancedKeyUsageList.FriendlyName -contains 'Code Signing' } |
    Select-Object -First 1)[0]
if (-not $certificate) { throw 'Certificado de assinatura de codigo valido nao encontrado no Windows.' }
if (-not (Test-Path -LiteralPath $agent -PathType Leaf) -or
    (Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedAgentHash) {
    throw 'Agent 1.5.3 precompilado nao corresponde ao artefato aprovado.'
}
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) { throw 'Python de build nao encontrado.' }
if (Test-Path -LiteralPath $package) { throw 'Pacote de migracao ja existe; remova-o manualmente antes de recriar.' }
$signtool = (Get-Command signtool.exe -ErrorAction Stop).Source
$stage = Join-Path ([IO.Path]::GetTempPath()) ('GivovaTrustedMigration-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
try {
    $build = Join-Path $stage 'build'
    $spec = Join-Path $stage 'spec'
    $binary = Join-Path $stage 'bin'
    & $PythonExe -m PyInstaller --noconsole --onefile --name GivovaMonitorUpdater `
        --distpath $binary --workpath $build --specpath $spec (Join-Path $repo 'updater.py')
    if ($LASTEXITCODE -ne 0) { throw 'Build do Updater 1.2.0 falhou.' }
    $updater = Join-Path $binary 'GivovaMonitorUpdater.exe'
    if ((& $updater --updater-version) -notmatch 'v1\.2\.0') { throw 'Versao incorreta do Updater.' }

    $signedAgent = Join-Path $stage 'GivovaMonitorAgent.exe'
    Copy-Item -LiteralPath $agent -Destination $signedAgent
    foreach ($item in @($signedAgent, $updater)) {
        & $signtool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $item
        if ($LASTEXITCODE -ne 0) { throw 'Assinatura Authenticode falhou.' }
        $signature = Get-AuthenticodeSignature -LiteralPath $item
        if ($signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
            throw 'Assinatura Authenticode nao validada pelo Windows.'
        }
    }

    $template = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Recover-Givova.ps1') -Raw -Encoding UTF8
    $recovery = $template.Replace('$targetVersion = "1.5.1"', '$targetVersion = "1.5.3"').Replace(
        'recovery-1.5.1.log', 'recovery-1.5.3.log').Replace(
        '__AGENT_SHA256__', (Get-FileHash $signedAgent -Algorithm SHA256).Hash.ToLowerInvariant()).Replace(
        '__UPDATER_SHA256__', (Get-FileHash $updater -Algorithm SHA256).Hash.ToLowerInvariant())
    $signatureGuard = @'
    $agentSignature = Get-AuthenticodeSignature -LiteralPath $SourceAgentExe
    $updaterSignature = Get-AuthenticodeSignature -LiteralPath $SourceUpdaterExe
    if ($agentSignature.Status -ne 'Valid' -or $updaterSignature.Status -ne 'Valid' -or
        -not $agentSignature.SignerCertificate -or -not $updaterSignature.SignerCertificate -or
        $agentSignature.SignerCertificate.Thumbprint -cne $updaterSignature.SignerCertificate.Thumbprint) {
        throw "Assinaturas Authenticode invalidas ou publicadores divergentes."
    }
    $trustedTaskScript = Join-Path $packageDir 'Install-TrustedUpdaterTask.ps1'
    if (-not (Test-Path -LiteralPath $trustedTaskScript -PathType Leaf) -or
        (Get-AuthenticodeSignature -LiteralPath $trustedTaskScript).Status -ne 'Valid' -or
        (Get-AuthenticodeSignature -LiteralPath $trustedTaskScript).SignerCertificate.Thumbprint -cne
        $updaterSignature.SignerCertificate.Thumbprint) {
        throw "Instalador confiavel da tarefa de update ausente ou sem assinatura valida."
    }
'@
    $needle = '    Test-ExpectedHash $SourceUpdaterExe $ExpectedUpdaterSha256 "GivovaMonitorUpdater.exe de origem"'
    if (-not $recovery.Contains($needle)) { throw 'Template de recuperacao inesperado.' }
    $recovery = $recovery.Replace($needle, $needle + "`r`n" + $signatureGuard)
    $recovery = $recovery.Replace('$exitCode = 0',
        '$exitCode = 0' + "`r`n" + '$trustedTaskPreviouslyPresent = $null -ne (Get-ScheduledTask -TaskName "Givova Monitor Updater" -ErrorAction SilentlyContinue)')
    $recovery = $recovery.Replace('        Set-GivovaTaskReliability',
        '        & (Join-Path $packageDir "Install-TrustedUpdaterTask.ps1")' + "`r`n" + '        Set-GivovaTaskReliability')
    $recovery = $recovery.Replace('    $updateId = Request-ReportConfirmation',
        '    & (Join-Path $packageDir "Install-TrustedUpdaterTask.ps1")' + "`r`n" +
        '    $updateId = Request-ReportConfirmation')
    $recovery = $recovery.Replace('    if ($configChanged) {',
        '    if (-not $trustedTaskPreviouslyPresent) { Unregister-ScheduledTask -TaskName "Givova Monitor Updater" -Confirm:$false -ErrorAction SilentlyContinue }' + "`r`n" +
        '    if ($configChanged) {')
    $recovery = $recovery.Replace(
        '$exitCode = 2',
        'throw "Primeiro report nao confirmado; rollback da migracao necessario."')

    # Publish locally only after both binaries and the rendered recovery are signed.
    $rendered = Join-Path $stage 'Recover-Givova.ps1'
    Set-Content -LiteralPath $rendered -Value $recovery -Encoding UTF8
    $scriptSignature = Set-AuthenticodeSignature -LiteralPath $rendered -Certificate $certificate -TimestampServer $TimestampUrl -HashAlgorithm SHA256
    if ($scriptSignature.Status -ne 'Valid') { throw 'Assinatura do script de recuperacao falhou.' }
    $taskScript = Join-Path $stage 'Install-TrustedUpdaterTask.ps1'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-TrustedUpdaterTask.ps1') -Destination $taskScript
    $taskSignature = Set-AuthenticodeSignature -LiteralPath $taskScript -Certificate $certificate -TimestampServer $TimestampUrl -HashAlgorithm SHA256
    if ($taskSignature.Status -ne 'Valid') { throw 'Assinatura do instalador da tarefa falhou.' }
    $ready = Join-Path $stage 'ready'
    New-Item -ItemType Directory -Path $ready | Out-Null
    Copy-Item -LiteralPath $signedAgent -Destination (Join-Path $ready 'GivovaMonitorAgent.exe')
    Copy-Item -LiteralPath $updater -Destination (Join-Path $ready 'GivovaMonitorUpdater.exe')
    Copy-Item -LiteralPath $rendered -Destination (Join-Path $ready 'Recover-Givova.ps1')
    Copy-Item -LiteralPath $taskScript -Destination (Join-Path $ready 'Install-TrustedUpdaterTask.ps1')
    $updaterHash = (Get-FileHash -LiteralPath $updater -Algorithm SHA256).Hash.ToLowerInvariant()
    $metadata = [ordered]@{
        version = '1.2.0'
        sha256 = $updaterHash
        file_size = (Get-Item -LiteralPath $updater).Length
        object_key = 'updaters/1.2.0/GivovaMonitorUpdater.exe'
        status = 'draft'
    }
    $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ready 'updater.release.draft.json') -Encoding UTF8
    Move-Item -LiteralPath $ready -Destination $package
    Write-Host "Pacote assinado preparado: $package"
} finally {
    $resolvedStage = [IO.Path]::GetFullPath($stage)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if ($resolvedStage.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedStage)) {
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}
