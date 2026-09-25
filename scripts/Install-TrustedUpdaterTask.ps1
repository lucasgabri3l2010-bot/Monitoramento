<# One-time elevated installation of a fixed, narrowly scoped updater task. #>
$ErrorActionPreference = 'Stop'
$name = 'Givova Monitor Updater'
$installDir = 'C:\ProgramData\GivovaMonitor'
$updater = Join-Path $installDir 'GivovaMonitorUpdater.exe'
$trustedDir = 'C:\Program Files\GivovaMonitorUpdate'
$trustedUpdater = Join-Path $trustedDir 'GivovaMonitorUpdater.exe'
function Set-TrustedAcl([string]$Path, [bool]$Directory) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    $inheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($entry in @(
        @('S-1-5-18', 'FullControl'),
        @('S-1-5-32-544', 'FullControl'),
        @('S-1-5-32-545', 'ReadAndExecute')
    )) {
        $sid = [Security.Principal.SecurityIdentifier]::new($entry[0])
        $rights = [Security.AccessControl.FileSystemRights]$entry[1]
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, $rights, $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator approval is required for the one-time Updater task installation.'
}
if (-not (Test-Path -LiteralPath $updater -PathType Leaf) -or
    (Get-AuthenticodeSignature -LiteralPath $updater).Status -ne 'Valid') {
    throw 'Signed Updater is required before registering the privileged task.'
}
if (-not (Test-Path -LiteralPath $trustedDir -PathType Container)) {
    New-Item -ItemType Directory -Path $trustedDir | Out-Null
}
# Program Files is admin-owned; never grant ordinary users write access here.
Set-TrustedAcl $trustedDir $true
if (-not (Test-Path -LiteralPath $trustedUpdater -PathType Leaf) -or
    (Get-FileHash -LiteralPath $trustedUpdater -Algorithm SHA256).Hash -ne
    (Get-FileHash -LiteralPath $updater -Algorithm SHA256).Hash) {
    Copy-Item -LiteralPath $updater -Destination $trustedUpdater -Force
}
Set-TrustedAcl $trustedUpdater $false
if ((Get-AuthenticodeSignature -LiteralPath $trustedUpdater).Status -ne 'Valid') {
    throw 'Protected Updater copy did not retain a valid signature.'
}
$existing = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if ($existing) {
    $action = @($existing.Actions)[0]
    if (@($existing.Actions).Count -ne 1 -or
        $action.Execute -ine $trustedUpdater -or $action.Arguments -cne '--apply-approved-request' -or
        $existing.Principal.UserId -notin @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18')) {
        throw 'Existing Updater task differs from the fixed trusted action; refusing replacement.'
    }
    Enable-ScheduledTask -TaskName $name -ErrorAction Stop | Out-Null
    return
}
$action = New-ScheduledTaskAction -Execute $trustedUpdater -Argument '--apply-approved-request' -WorkingDirectory $trustedDir
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
$system = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger `
    -Settings $settings -Principal $system -ErrorAction Stop | Out-Null
