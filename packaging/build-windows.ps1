[CmdletBinding()]
param(
    [string]$OutputDirectory = 'dist',
    [string]$SigningCertificateThumbprint,
    [string]$TimestampUrl,
    [string]$SignTool
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($SigningCertificateThumbprint) -and
    (-not [string]::IsNullOrWhiteSpace($TimestampUrl) -or -not [string]::IsNullOrWhiteSpace($SignTool))) {
    throw 'TimestampUrl and SignTool require SigningCertificateThumbprint'
}

$versionLine = Select-String -Path "Cargo.toml" -Pattern '^version = "([^"]+)"' | Select-Object -First 1
$version = $versionLine.Matches[0].Groups[1].Value
$wixArchitecture = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "x64" }
    "ARM64" { "arm64" }
    default { throw "Unsupported Windows architecture: $env:PROCESSOR_ARCHITECTURE" }
}
$archive = "factorseal-$version-windows-$wixArchitecture"
$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
$stage = Join-Path $stageRoot $archive

try {
    cargo build --locked --release --no-default-features --features vault,cli,hardware --bin factorseal
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    $metadataJson = cargo metadata --locked --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $metadata = $metadataJson | ConvertFrom-Json
    $factorseal = Join-Path $metadata.target_directory "release/factorseal.exe"
    if (-not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
        $thumbprint = $SigningCertificateThumbprint.Replace(' ', '')
        if ($thumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
            throw 'SigningCertificateThumbprint must be a 40-character SHA-1 certificate thumbprint'
        }
        if ([string]::IsNullOrWhiteSpace($TimestampUrl)) {
            throw 'TimestampUrl is required when signing a Windows release artifact'
        }
        if ([string]::IsNullOrWhiteSpace($SignTool)) {
            $signToolCommand = Get-Command signtool.exe -ErrorAction SilentlyContinue
            if ($null -eq $signToolCommand) { throw 'signtool.exe was not found on PATH' }
            $SignTool = $signToolCommand.Source
        }
        if (-not (Test-Path -LiteralPath $SignTool -PathType Leaf)) {
            throw "signtool.exe is missing: $SignTool"
        }
        & $SignTool sign /sha1 $thumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $factorseal
        if ($LASTEXITCODE -ne 0) { throw 'signtool.exe failed to sign factorseal.exe' }
        $signature = Get-AuthenticodeSignature -LiteralPath $factorseal
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "factorseal.exe signature verification failed: $($signature.Status)"
        }
    } else {
        Write-Warning 'Building an unsigned development archive; it cannot pass release acceptance.'
    }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Copy-Item $factorseal, "LICENSE", "README.md" -Destination $stage
    Copy-Item "packaging/windows/factorseal-task.xml.in", "packaging/windows/factorseal-askpass.ps1", "packaging/windows/factorseal-askpass.cmd", "packaging/windows/install-factorseal-task.ps1" -Destination $stage
    Copy-Item "acceptance/windows.ps1" -Destination (Join-Path $stage "run-acceptance.ps1")
    $zip = Join-Path $OutputDirectory "$archive.zip"
    Compress-Archive -Path $stage -DestinationPath $zip -Force
    Write-Output $zip
}
finally {
    if (Test-Path $stageRoot) { Remove-Item -Recurse -Force $stageRoot }
}
