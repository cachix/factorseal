[CmdletBinding()]
param(
    [string]$Factorseal,
    [string]$Root,
    [string]$PasswordFile,
    [string]$Evidence,
    [string]$StorePackageName,
    [switch]$DestroyAfter,
    [switch]$AllowUnsignedDevelopmentArtifact
)

$ErrorActionPreference = 'Stop'

$runId = "$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))-$PID"
$storePackage = $null
if (-not [string]::IsNullOrWhiteSpace($StorePackageName)) {
    if ($AllowUnsignedDevelopmentArtifact.IsPresent) {
        throw 'StorePackageName cannot be combined with AllowUnsignedDevelopmentArtifact'
    }
    $storePackages = @(Get-AppxPackage -Name $StorePackageName)
    if ($storePackages.Count -ne 1) {
        throw "Expected one installed Store package named '$StorePackageName', found $($storePackages.Count)"
    }
    $storePackage = $storePackages[0]
    if ([string]$storePackage.Status -ne 'Ok') {
        throw "Installed Store package status is not Ok: $($storePackage.Status)"
    }
    if ([string]$storePackage.SignatureKind -ne 'Store') {
        throw "Installed package must have a Microsoft Store signature (kind: $($storePackage.SignatureKind))"
    }
    $storeFactorseal = Join-Path $storePackage.InstallLocation 'factorseal.exe'
    if (-not [string]::IsNullOrWhiteSpace($Factorseal)) {
        $requestedFactorseal = (Resolve-Path -LiteralPath $Factorseal).Path
        if ($requestedFactorseal -ne $storeFactorseal) {
            throw 'Factorseal must identify the executable inside StorePackageName when both are supplied'
        }
    }
    $Factorseal = $storeFactorseal
}
if ([string]::IsNullOrWhiteSpace($Factorseal)) {
    $besideRunner = Join-Path $PSScriptRoot 'factorseal.exe'
    $installed = Join-Path $env:ProgramFiles 'Factorseal\factorseal.exe'
    if (Test-Path -LiteralPath $besideRunner -PathType Leaf) {
        $Factorseal = $besideRunner
    } elseif (Test-Path -LiteralPath $installed -PathType Leaf) {
        $Factorseal = $installed
    } else {
        $onPath = Get-Command factorseal.exe -ErrorAction SilentlyContinue
        if ($null -ne $onPath) { $Factorseal = $onPath.Source }
    }
}
if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = Join-Path $env:LOCALAPPDATA "Factorseal-acceptance-$runId"
}
if ([string]::IsNullOrWhiteSpace($Evidence)) {
    $Evidence = Join-Path (Get-Location).Path "factorseal-windows-$runId.acceptance.txt"
}

if ([string]::IsNullOrWhiteSpace($Factorseal) -or -not (Test-Path -LiteralPath $Factorseal -PathType Leaf)) {
    throw "factorseal.exe is missing: $Factorseal"
}
if (-not [System.IO.Path]::IsPathRooted($Root)) { throw 'Root must be absolute' }
if (Test-Path -LiteralPath $Root) { throw "Acceptance root already exists: $Root" }
if (-not [string]::IsNullOrWhiteSpace($PasswordFile) -and -not (Test-Path -LiteralPath $PasswordFile -PathType Leaf)) {
    throw "Password file is missing: $PasswordFile"
}

$signature = if ($null -eq $storePackage) {
    Get-AuthenticodeSignature -LiteralPath $Factorseal
} else {
    $null
}
$signatureIsValid = if ($null -ne $storePackage) {
    $true
} else {
    $signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid
}
if (-not $signatureIsValid -and -not $AllowUnsignedDevelopmentArtifact.IsPresent) {
    throw "factorseal.exe must have a valid Authenticode signature for release acceptance (status: $($signature.Status))"
}
if (-not $signatureIsValid) {
    Write-Warning 'Unsigned development override enabled. This run cannot count as release acceptance evidence.'
}

$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$hardwareSummary = "$($computer.Manufacturer); $($computer.Model)"
$virtualHardwarePattern = '(?i)virtual|vmware|virtualbox|qemu|kvm|xen|parallels|amazon ec2|google compute engine'
if ($hardwareSummary -match $virtualHardwarePattern) {
    throw "Physical acceptance refuses virtualized hardware: $hardwareSummary"
}
$tpm = Get-Tpm
if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {
    throw 'A present and ready physical TPM is required'
}

if (-not [System.IO.Path]::IsPathRooted($Evidence)) { throw 'Evidence path must be absolute' }
$evidencePartial = if ($Evidence.EndsWith('.txt', [StringComparison]::OrdinalIgnoreCase)) {
    "$($Evidence.Substring(0, $Evidence.Length - 4)).partial.txt"
} else {
    "$Evidence.partial"
}
if ((Test-Path -LiteralPath $Evidence) -or (Test-Path -LiteralPath $evidencePartial)) {
    throw "Evidence path already exists: $Evidence or $evidencePartial"
}
$evidenceParent = Split-Path -Parent $Evidence
if (-not (Test-Path -LiteralPath $evidenceParent -PathType Container)) {
    throw "Evidence parent directory does not exist: $evidenceParent"
}

function Add-Evidence([string]$Key, [object]$Value) {
    $safeValue = ([string]$Value) -replace '[\r\n\t=]', ' '
    Add-Content -LiteralPath $evidencePartial -Encoding UTF8 -Value "$Key=$safeValue"
}

# Start-Process joins an ArgumentList array with spaces and removes the
# PowerShell string quotes. Quote each native argument according to the Windows
# command-line rules so custom roots and password paths containing spaces stay
# one argument under Windows PowerShell 5.1 as well as modern PowerShell.
function ConvertTo-NativeArgument([string]$Value) {
    if ($null -eq $Value -or $Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }

    $quoted = New-Object System.Text.StringBuilder
    [void]$quoted.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$quoted.Append(('\' * (($backslashes * 2) + 1)))
            [void]$quoted.Append('"')
        } else {
            if ($backslashes -gt 0) { [void]$quoted.Append(('\' * $backslashes)) }
            [void]$quoted.Append($character)
        }
        $backslashes = 0
    }
    if ($backslashes -gt 0) { [void]$quoted.Append(('\' * ($backslashes * 2))) }
    [void]$quoted.Append('"')
    $quoted.ToString()
}

function Start-FactorsealAgent([string]$StandardOutput, [string]$StandardError) {
    $arguments = @(
        '--root', $Root, '--password-file', $PasswordFile,
        'agent', '--idle-seconds', '3600', '--maximum-seconds', '3600'
    )
    $quotedArguments = foreach ($argument in $arguments) {
        ConvertTo-NativeArgument ([string]$argument)
    }
    Start-Process -FilePath $Factorseal -ArgumentList ($quotedArguments -join ' ') `
        -PassThru -RedirectStandardOutput $StandardOutput -RedirectStandardError $StandardError
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
Add-Evidence 'artifact_signature' $(if ($null -ne $storePackage) { 'microsoft-store' } elseif ($signatureIsValid) { 'valid' } else { 'unsigned-development-override' })
if ($null -ne $storePackage) {
    Add-Evidence 'store_package_name' $storePackage.Name
    Add-Evidence 'store_package_full_name' $storePackage.PackageFullName
    Add-Evidence 'store_package_signature_kind' $storePackage.SignatureKind
}
Add-Evidence 'os_summary' ([System.Environment]::OSVersion.VersionString)
Add-Evidence 'expected_backend' 'windows-tpm'
Add-Evidence 'physical_host_check' 'pass'
Add-Evidence 'hardware_summary' "$hardwareSummary; TPM present and ready"
Add-Evidence 'lifecycle_event' 'windows-session-lock,windows-suspend'

$generatedPasswordFile = $false
$destroyAfterRun = $DestroyAfter.IsPresent
if ([string]::IsNullOrWhiteSpace($PasswordFile)) {
    $PasswordFile = Join-Path ([System.IO.Path]::GetTempPath()) "factorseal-acceptance-password-$([Guid]::NewGuid().ToString('N'))"
    $randomBytes = New-Object byte[] 32
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($randomBytes) } finally { $random.Dispose() }
    [System.IO.File]::WriteAllText(
        $PasswordFile,
        [Convert]::ToBase64String($randomBytes),
        [System.Text.UTF8Encoding]::new($false)
    )
    [Array]::Clear($randomBytes, 0, $randomBytes.Length)
    $generatedPasswordFile = $true
    $destroyAfterRun = $true
}

Write-Host 'Factorseal physical Windows acceptance'
Write-Host "  Test vault: $Root"
Write-Host "  Evidence:   $Evidence"
Write-Host 'Native Windows Hello prompts will appear during creation, unseal, recovery, and cleanup.'
if ($generatedPasswordFile) {
    Write-Host 'The guided run uses a generated test-only factor and removes the test vault after success.'
} else {
    Write-Host 'The test vault is kept unless -DestroyAfter is supplied.'
}

$service = $null
$acceptancePassed = $false

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
Add-Evidence 'test.create' 'pass'

# Sealing invariants that a create-once flow cannot observe: that re-sealing
# under a label leaves an earlier envelope openable, that another label cannot
# open it, and that delete is label-scoped. Reserved scratch state only. The
# biometric half prompts several times.
Write-Host 'The hardware self-test asks for Windows Hello verification several times.'
& $Factorseal --root $Root hardware-self-test --biometric
if ($LASTEXITCODE -ne 0) { throw 'factorseal hardware-self-test failed' }
Add-Evidence 'test.hardware_self_test' 'pass'

$service = Start-FactorsealAgent `
    (Join-Path $Root 'acceptance-unseal.log') `
    (Join-Path $Root 'acceptance-unseal-error.log')
Wait-ForState 'unsealed'
$promptsObserved = Read-Host 'Did you see native Windows Hello verification for both creation and initial unseal? [y/N]'
if ($promptsObserved -notmatch '^(?i:y|yes)$') { throw 'Both native verification prompts must be observed' }
Add-Evidence 'native_prompt_create_observed' 'pass'
Add-Evidence 'native_prompt_unseal_observed' 'pass'
Add-Evidence 'native_prompt_observed' 'pass'
Add-Evidence 'test.initial_unseal' 'pass'
'hardware-lifecycle-acceptance' | & $Factorseal --root $Root set --project acceptance acceptance --field value
if ($LASTEXITCODE -ne 0) { throw 'factorseal set failed' }
$value = & $Factorseal --root $Root get --project acceptance acceptance --field value
if ($LASTEXITCODE -ne 0 -or $value -ne 'hardware-lifecycle-acceptance') {
    throw 'Keyring round trip failed'
}
Add-Evidence 'test.ipc_round_trip' 'pass'

Write-Host 'Lock this exact Windows session now (Win+L is suitable).'
Write-Host 'After unlocking again, return here and press Enter.'
[void](Read-Host 'Press Enter after the lock/unlock')
$service.WaitForExit(180000)
if (-not $service.HasExited) { throw 'Vault did not exit after the lifecycle event' }
Wait-ForState 'sealed'
Add-Evidence 'test.screen_lock_seal' 'pass'
$sealedValue = & $Factorseal --root $Root get --project acceptance acceptance --field value 2>$null
if ($LASTEXITCODE -eq 0 -or $sealedValue) {
    throw 'Sealed vault returned a secret'
}

$service = Start-FactorsealAgent `
    (Join-Path $Root 'acceptance-after-lock.log') `
    (Join-Path $Root 'acceptance-after-lock-error.log')
Wait-ForState 'unsealed'
$value = & $Factorseal --root $Root get --project acceptance acceptance --field value
if ($LASTEXITCODE -ne 0 -or $value -ne 'hardware-lifecycle-acceptance') {
    throw 'Re-unseal after screen lock did not recover the stored value'
}

Write-Host 'Put this machine to sleep now (Start > Power > Sleep).'
Write-Host 'After it resumes, return here and press Enter.'
[void](Read-Host 'Press Enter after suspend/resume')
$service.WaitForExit(180000)
if (-not $service.HasExited) { throw 'Vault did not exit after suspend/resume' }
Wait-ForState 'sealed'
Add-Evidence 'test.suspend_seal' 'pass'
$sealedValue = & $Factorseal --root $Root get --project acceptance acceptance --field value 2>$null
if ($LASTEXITCODE -eq 0 -or $sealedValue) {
    throw 'Suspended vault returned a secret after resume'
}
Add-Evidence 'test.lifecycle_seal' 'pass'
Add-Evidence 'test.sealed_read_denied' 'pass'

$service = Start-FactorsealAgent `
    (Join-Path $Root 'acceptance-reunseal.log') `
    (Join-Path $Root 'acceptance-reunseal-error.log')
Wait-ForState 'unsealed'
$value = & $Factorseal --root $Root get --project acceptance acceptance --field value
if ($LASTEXITCODE -ne 0 -or $value -ne 'hardware-lifecycle-acceptance') {
    throw 'Hardware re-unseal after suspend did not recover the stored value'
}
Add-Evidence 'test.reunseal_recovery' 'pass'
& $Factorseal --root $Root delete --project acceptance acceptance --field value
if ($LASTEXITCODE -ne 0) { throw 'factorseal delete failed' }
Add-Evidence 'test.delete' 'pass'
Stop-Process -Id $service.Id
$service.WaitForExit(30000)
Wait-ForState 'sealed'

if ($destroyAfterRun) {
    & $Factorseal --root $Root --password-file $PasswordFile destroy --yes-really-destroy
    if ($LASTEXITCODE -ne 0) { throw 'factorseal destroy failed' }
    Add-Evidence 'test.destroy' 'pass'
} else {
    Add-Evidence 'test.destroy' 'not-run'
}
Add-Evidence 'completed_at_utc' ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
Move-Item -LiteralPath $evidencePartial -Destination $Evidence
$acceptancePassed = $true
if ($signatureIsValid) {
    Write-Host "PASS - send this evidence file to the Factorseal maintainers: $Evidence"
    Write-Host 'Upload it to https://github.com/domenkozar/factorseal/issues/2'
} else {
    Write-Host "DEVELOPMENT PASS - unsigned evidence is not release acceptance: $Evidence"
}
} finally {
    if ($null -ne $service -and -not $service.HasExited) {
        Stop-Process -Id $service.Id -ErrorAction SilentlyContinue
        $service.WaitForExit(30000)
    }
    if ($generatedPasswordFile) {
        if ($acceptancePassed -or -not (Test-Path -LiteralPath $Root)) {
            Remove-Item -LiteralPath $PasswordFile -Force -ErrorAction SilentlyContinue
        } else {
            Write-Warning "Test did not finish; the temporary factor was retained for cleanup: $PasswordFile"
        }
    }
}
