[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Factorseal,
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$PasswordFile,
    [string]$Evidence,
    [switch]$DestroyAfter
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Factorseal -PathType Leaf)) { throw "factorseal.exe is missing: $Factorseal" }
if (-not [System.IO.Path]::IsPathRooted($Root)) { throw 'Root must be absolute' }
if (Test-Path -LiteralPath $Root) { throw "Acceptance root already exists: $Root" }
if (-not (Test-Path -LiteralPath $PasswordFile -PathType Leaf)) { throw "Password file is missing: $PasswordFile" }

$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$hardwareSummary = "$($computer.Manufacturer); $($computer.Model)"
if ($hardwareSummary -match '(?i)virtual|vmware|virtualbox|qemu|kvm|xen|parallels') {
    throw "Physical acceptance refuses virtualized hardware: $hardwareSummary"
}
$tpm = Get-Tpm
if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {
    throw 'A present and ready physical TPM is required'
}

if ([string]::IsNullOrWhiteSpace($Evidence)) { $Evidence = "$Root.acceptance-record" }
if (-not [System.IO.Path]::IsPathRooted($Evidence)) { throw 'Evidence path must be absolute' }
$evidencePartial = "$Evidence.partial"
if ((Test-Path -LiteralPath $Evidence) -or (Test-Path -LiteralPath $evidencePartial)) {
    throw "Evidence path already exists: $Evidence (or its .partial file)"
}
$evidenceParent = Split-Path -Parent $Evidence
if (-not (Test-Path -LiteralPath $evidenceParent -PathType Container)) {
    throw "Evidence parent directory does not exist: $evidenceParent"
}

function Add-Evidence([string]$Key, [object]$Value) {
    $safeValue = ([string]$Value) -replace '[\r\n\t=]', ' '
    Add-Content -LiteralPath $evidencePartial -Encoding UTF8 -Value "$Key=$safeValue"
}

$version = & $Factorseal --version
if ($LASTEXITCODE -ne 0) { throw 'factorseal --version failed' }
$factorsealHash = (Get-FileHash -LiteralPath $Factorseal -Algorithm SHA256).Hash.ToLowerInvariant()
Add-Evidence 'schema' 'factorseal-physical-acceptance-v1'
Add-Evidence 'platform' 'windows'
Add-Evidence 'started_at_utc' ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
Add-Evidence 'factorseal_filename' (Split-Path -Leaf $Factorseal)
Add-Evidence 'factorseal_sha256' $factorsealHash
Add-Evidence 'factorseal_version' $version
Add-Evidence 'os_summary' ([System.Environment]::OSVersion.VersionString)
Add-Evidence 'expected_backend' 'windows-tpm'
Add-Evidence 'physical_host_check' 'pass'
Add-Evidence 'hardware_summary' "$hardwareSummary; TPM present and ready"
Add-Evidence 'lifecycle_event' 'windows-session-lock'

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
Add-Evidence 'observed_backend' $metadata.hardware_backend
$promptObserved = Read-Host 'Did you observe the native Windows Hello user-verification prompt? [y/N]'
if ($promptObserved -notmatch '^(?i:y|yes)$') { throw 'Native user verification was not observed' }
Add-Evidence 'native_prompt_create_observed' 'pass'
Add-Evidence 'test.create' 'pass'

$service = Start-Process -FilePath $Factorseal -ArgumentList @(
    '--root', $Root, '--password-file', $PasswordFile,
    'agent', '--idle-seconds', '3600', '--maximum-seconds', '3600'
) -PassThru -RedirectStandardOutput (Join-Path $Root 'acceptance-unseal.log') -RedirectStandardError (Join-Path $Root 'acceptance-unseal-error.log')
Wait-ForState 'unsealed'
$unsealPromptObserved = Read-Host 'Did the initial unseal show a native Windows Hello user-verification prompt? [y/N]'
if ($unsealPromptObserved -notmatch '^(?i:y|yes)$') { throw 'Native user verification was not observed during unseal' }
Add-Evidence 'native_prompt_unseal_observed' 'pass'
Add-Evidence 'native_prompt_observed' 'pass'
Add-Evidence 'test.initial_unseal' 'pass'
'hardware-lifecycle-acceptance' | & $Factorseal --root $Root set acceptance --field value
if ($LASTEXITCODE -ne 0) { throw 'factorseal set failed' }
$value = & $Factorseal --root $Root get acceptance --field value
if ($LASTEXITCODE -ne 0 -or $value -ne 'hardware-lifecycle-acceptance') {
    throw 'Keyring round trip failed'
}
Add-Evidence 'test.ipc_round_trip' 'pass'

Write-Host 'Lock this exact Windows session now (Win+L is suitable).'
Write-Host 'The runner will fail if the real session lifecycle notification does not seal the vault.'
[void](Read-Host 'Press Enter after initiating the lock event')
$service.WaitForExit(180000)
if (-not $service.HasExited) { throw 'Vault did not exit after the lifecycle event' }
Wait-ForState 'sealed'
Add-Evidence 'test.lifecycle_seal' 'pass'
$sealedValue = & $Factorseal --root $Root get acceptance --field value 2>$null
if ($LASTEXITCODE -eq 0 -or $sealedValue) {
    throw 'Sealed vault returned a secret'
}
Add-Evidence 'test.sealed_read_denied' 'pass'

$service = Start-Process -FilePath $Factorseal -ArgumentList @(
    '--root', $Root, '--password-file', $PasswordFile,
    'agent', '--idle-seconds', '3600', '--maximum-seconds', '3600'
) -PassThru -RedirectStandardOutput (Join-Path $Root 'acceptance-reunseal.log') -RedirectStandardError (Join-Path $Root 'acceptance-reunseal-error.log')
Wait-ForState 'unsealed'
$value = & $Factorseal --root $Root get acceptance --field value
if ($LASTEXITCODE -ne 0 -or $value -ne 'hardware-lifecycle-acceptance') {
    throw 'Hardware re-unseal did not recover the stored value'
}
Add-Evidence 'test.reunseal_recovery' 'pass'
& $Factorseal --root $Root delete acceptance --field value
if ($LASTEXITCODE -ne 0) { throw 'factorseal delete failed' }
Add-Evidence 'test.delete' 'pass'
Stop-Process -Id $service.Id
$service.WaitForExit(30000)
Wait-ForState 'sealed'

if ($DestroyAfter) {
    & $Factorseal --root $Root --password-file $PasswordFile destroy --yes-really-destroy
    if ($LASTEXITCODE -ne 0) { throw 'factorseal destroy failed' }
    Add-Evidence 'test.destroy' 'pass'
} else {
    Add-Evidence 'test.destroy' 'not-run'
}
Add-Evidence 'completed_at_utc' ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
Move-Item -LiteralPath $evidencePartial -Destination $Evidence
Write-Host "Windows native hardware/lifecycle acceptance passed. Evidence: $Evidence"
} finally {
    if ($null -ne $service -and -not $service.HasExited) {
        Stop-Process -Id $service.Id -ErrorAction SilentlyContinue
        $service.WaitForExit(30000)
    }
}
