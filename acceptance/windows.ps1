[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Factorseal,
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$PasswordFile,
    [switch]$DestroyAfter
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Factorseal -PathType Leaf)) { throw "factorseal.exe is missing: $Factorseal" }
if (-not [System.IO.Path]::IsPathRooted($Root)) { throw 'Root must be absolute' }
if (Test-Path -LiteralPath $Root) { throw "Acceptance root already exists: $Root" }
if (-not (Test-Path -LiteralPath $PasswordFile -PathType Leaf)) { throw "Password file is missing: $PasswordFile" }

$service = $null

function Get-Status {
    $status = & $Factorseal --root $Root status
    if ($LASTEXITCODE -ne 0) { throw 'factorseal status failed' }
    $status | ConvertFrom-Json
}

function Wait-ForState([string]$Expected) {
    for ($attempt = 0; $attempt -lt 180; $attempt++) {
        try {
            if ((Get-Status).state -eq $Expected) { return }
        } catch { }
        Start-Sleep -Seconds 1
    }
    throw "Vault did not become $Expected within three minutes"
}

try {
& $Factorseal --root $Root --password-file $PasswordFile init --unlock password,biometric
if ($LASTEXITCODE -ne 0) { throw 'factorseal init failed' }
$metadata = Get-Status
if ($metadata.hardware_backend -ne 'windows-tpm') {
    throw "Expected Windows TPM backend, got $($metadata.hardware_backend)"
}

$service = Start-Process -FilePath $Factorseal -ArgumentList @(
    '--root', $Root, '--password-file', $PasswordFile,
    'agent', '--idle-seconds', '3600', '--maximum-seconds', '3600'
) -PassThru -RedirectStandardOutput (Join-Path $Root 'acceptance-unseal.log') -RedirectStandardError (Join-Path $Root 'acceptance-unseal-error.log')
Wait-ForState 'unsealed'
'hardware-lifecycle-acceptance' | & $Factorseal --root $Root set acceptance --field value
if ($LASTEXITCODE -ne 0) { throw 'factorseal set failed' }
$value = & $Factorseal --root $Root get acceptance --field value
if ($LASTEXITCODE -ne 0 -or $value -ne 'hardware-lifecycle-acceptance') {
    throw 'Keyring round trip failed'
}

Write-Host 'Lock this exact Windows session now (Win+L is suitable).'
Write-Host 'The runner will fail if the real session lifecycle notification does not seal the vault.'
[void](Read-Host 'Press Enter after initiating the lock event')
$service.WaitForExit(180000)
if (-not $service.HasExited) { throw 'Vault did not exit after the lifecycle event' }
Wait-ForState 'sealed'
$sealedValue = & $Factorseal --root $Root get acceptance --field value 2>$null
if ($LASTEXITCODE -eq 0 -or $sealedValue) {
    throw 'Sealed vault returned a secret'
}

$service = Start-Process -FilePath $Factorseal -ArgumentList @(
    '--root', $Root, '--password-file', $PasswordFile,
    'agent', '--idle-seconds', '3600', '--maximum-seconds', '3600'
) -PassThru -RedirectStandardOutput (Join-Path $Root 'acceptance-reunseal.log') -RedirectStandardError (Join-Path $Root 'acceptance-reunseal-error.log')
Wait-ForState 'unsealed'
$value = & $Factorseal --root $Root get acceptance --field value
if ($LASTEXITCODE -ne 0 -or $value -ne 'hardware-lifecycle-acceptance') {
    throw 'Hardware re-unseal did not recover the stored value'
}
& $Factorseal --root $Root delete acceptance --field value
if ($LASTEXITCODE -ne 0) { throw 'factorseal delete failed' }
Stop-Process -Id $service.Id
$service.WaitForExit(30000)
Wait-ForState 'sealed'

if ($DestroyAfter) {
    & $Factorseal --root $Root --password-file $PasswordFile destroy --yes-really-destroy
    if ($LASTEXITCODE -ne 0) { throw 'factorseal destroy failed' }
}
Write-Host 'Windows native hardware/lifecycle acceptance passed.'
} finally {
    if ($null -ne $service -and -not $service.HasExited) {
        Stop-Process -Id $service.Id -ErrorAction SilentlyContinue
        $service.WaitForExit(30000)
    }
}
