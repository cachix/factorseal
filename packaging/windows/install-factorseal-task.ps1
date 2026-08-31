[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallDirectory = $PSScriptRoot,
    [string]$TaskName = 'Factorseal',
    [string]$Root,
    [switch]$Replace,
    [switch]$AllowUnsignedDevelopmentArtifact
)

$ErrorActionPreference = 'Stop'

if ($TaskName -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$') {
    throw 'TaskName must contain only letters, numbers, spaces, periods, underscores, or hyphens'
}
if (-not (Test-Path -LiteralPath $InstallDirectory -PathType Container)) {
    throw "Factorseal install directory is missing: $InstallDirectory"
}
$InstallDirectory = (Resolve-Path -LiteralPath $InstallDirectory).Path.TrimEnd('\')

$factorseal = Join-Path $InstallDirectory 'factorseal.exe'
$askpassWrapper = Join-Path $InstallDirectory 'factorseal-askpass.cmd'
$askpassScript = Join-Path $InstallDirectory 'factorseal-askpass.ps1'
$templatePath = Join-Path $InstallDirectory 'factorseal-task.xml.in'
foreach ($path in @($factorseal, $askpassWrapper, $askpassScript, $templatePath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required Factorseal package file is missing: $path"
    }
}

$signature = Get-AuthenticodeSignature -LiteralPath $factorseal
$signatureIsValid = $signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid
if (-not $signatureIsValid -and -not $AllowUnsignedDevelopmentArtifact.IsPresent) {
    throw "factorseal.exe must have a valid Authenticode signature before login-task installation (status: $($signature.Status))"
}
if (-not $signatureIsValid) {
    Write-Warning 'Installing an unsigned development artifact. This cannot pass release acceptance.'
}

$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$escapedDirectory = [System.Security.SecurityElement]::Escape($InstallDirectory)
$escapedSid = [System.Security.SecurityElement]::Escape($sid)
$rootArguments = ''
if (-not [string]::IsNullOrWhiteSpace($Root)) {
    if (-not [System.IO.Path]::IsPathRooted($Root)) { throw 'Root must be absolute' }
    $Root = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $escapedRoot = [System.Security.SecurityElement]::Escape($Root)
    $rootArguments = "--root &quot;$escapedRoot&quot; "
}
$taskXml = Get-Content -LiteralPath $templatePath -Raw
$taskXml = $taskXml.Replace('@INSTALL_DIR@', $escapedDirectory)
$taskXml = $taskXml.Replace('@USER_SID@', $escapedSid)
$taskXml = $taskXml.Replace('@ROOT_ARGUMENTS@', $rootArguments)
if ($taskXml.Contains('@INSTALL_DIR@') -or $taskXml.Contains('@USER_SID@') -or $taskXml.Contains('@ROOT_ARGUMENTS@')) {
    throw 'Scheduled Task template still contains unresolved placeholders'
}
[void]([xml]$taskXml)

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $existing -and -not $Replace.IsPresent) {
    throw "Scheduled Task '$TaskName' already exists; use -Replace to update it"
}

if ($PSCmdlet.ShouldProcess($TaskName, 'Register Factorseal per-user logon task')) {
    $parameters = @{
        TaskName = $TaskName
        Xml = $taskXml
    }
    if ($Replace.IsPresent) { $parameters.Force = $true }
    Register-ScheduledTask @parameters | Out-Null
    Write-Host "Installed Scheduled Task '$TaskName' for SID $sid"
    Write-Host "Start it now with: Start-ScheduledTask -TaskName '$TaskName'"
}
