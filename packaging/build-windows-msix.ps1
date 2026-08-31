[CmdletBinding()]
param(
    [string]$OutputDirectory = 'dist',
    [string]$IdentityName = 'Factorseal.Development',
    [string]$Publisher = 'CN=Factorseal Development',
    [string]$PublisherDisplayName = 'Factorseal Development',
    [string]$PackageVersion,
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture,
    [string]$MakeAppx,
    [string]$SigningCertificateThumbprint,
    [string]$TimestampUrl,
    [string]$SignTool
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot

function Resolve-WindowsSdkTool([string]$Name, [string]$ExplicitPath) {
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            throw "$Name is missing: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) { return $command.Source }

    $programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
    $sdkBin = Join-Path $programFilesX86 'Windows Kits\10\bin'
    if (Test-Path -LiteralPath $sdkBin -PathType Container) {
        $candidate = Get-ChildItem -LiteralPath $sdkBin -Directory |
            Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName "x64\$Name" } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
        if ($null -ne $candidate) { return $candidate }
    }

    throw "$Name was not found. Install the Windows 10 or 11 SDK, or pass its path explicitly."
}

function ConvertTo-XmlText([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw 'MSIX identity values must not be empty' }
    [System.Security.SecurityElement]::Escape($Value)
}

if ($IdentityName -notmatch '^[A-Za-z0-9.-]{3,50}$') {
    throw 'IdentityName must be 3-50 characters containing only letters, numbers, periods, or hyphens'
}
if (-not [string]::IsNullOrWhiteSpace($TimestampUrl) -and
    [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
    throw 'TimestampUrl requires SigningCertificateThumbprint'
}
if (-not [string]::IsNullOrWhiteSpace($SignTool) -and
    [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
    throw 'SignTool requires SigningCertificateThumbprint'
}

Push-Location $repositoryRoot
try {
    $versionLine = Select-String -Path 'Cargo.toml' -Pattern '^version = "([^"]+)"' |
        Select-Object -First 1
    if ($null -eq $versionLine) { throw 'Could not read the package version from Cargo.toml' }
    $crateVersion = $versionLine.Matches[0].Groups[1].Value

    if ([string]::IsNullOrWhiteSpace($PackageVersion)) {
        if ($crateVersion -notmatch '^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$') {
            throw "Cargo package version cannot be converted to an MSIX version: $crateVersion"
        }
        $PackageVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3]).0"
    }
    if ($PackageVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw 'PackageVersion must contain four numeric components, for example 1.2.3.0'
    }
    $versionParts = @($PackageVersion.Split('.') | ForEach-Object { [uint32]$_ })
    if (($versionParts | Where-Object { $_ -gt 65535 }).Count -gt 0) {
        throw 'Every PackageVersion component must be between 0 and 65535'
    }
    if ($versionParts[3] -ne 0) {
        throw 'The fourth PackageVersion component must be zero for Microsoft Store submission'
    }

    $hostArchitecture = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        ([System.Runtime.InteropServices.Architecture]::X64) { 'x64' }
        ([System.Runtime.InteropServices.Architecture]::Arm64) { 'arm64' }
        default { throw "Unsupported Windows architecture: $_" }
    }
    if ([string]::IsNullOrWhiteSpace($Architecture)) {
        $Architecture = $hostArchitecture
    } elseif ($Architecture -ne $hostArchitecture) {
        throw "Architecture '$Architecture' does not match the native build host '$hostArchitecture'"
    }

    $MakeAppx = Resolve-WindowsSdkTool 'makeappx.exe' $MakeAppx
    $outputRoot = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
        $OutputDirectory
    } else {
        Join-Path $repositoryRoot $OutputDirectory
    }
    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
    $outputRoot = (Resolve-Path -LiteralPath $outputRoot).Path

    cargo build --locked --release --no-default-features --features vault,cli,hardware --bin factorseal
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    $metadataJson = cargo metadata --locked --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $metadata = $metadataJson | ConvertFrom-Json
    $factorseal = Join-Path $metadata.target_directory 'release\factorseal.exe'
    if (-not (Test-Path -LiteralPath $factorseal -PathType Leaf)) {
        throw "Built factorseal.exe is missing: $factorseal"
    }

    $stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
    $stage = Join-Path $stageRoot 'package'
    $verify = Join-Path $stageRoot 'verify'
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Copy-Item -LiteralPath $factorseal, 'LICENSE', 'README.md' -Destination $stage
    Copy-Item -LiteralPath 'packaging\windows\msix\Assets' -Destination $stage -Recurse

    $manifestTemplate = Get-Content -LiteralPath 'packaging\windows\msix\AppxManifest.xml.in' -Raw
    $manifest = $manifestTemplate
    $replacements = [ordered]@{
        '@IDENTITY_NAME@' = ConvertTo-XmlText $IdentityName
        '@PUBLISHER@' = ConvertTo-XmlText $Publisher
        '@PUBLISHER_DISPLAY_NAME@' = ConvertTo-XmlText $PublisherDisplayName
        '@VERSION@' = $PackageVersion
        '@ARCHITECTURE@' = $Architecture
    }
    foreach ($replacement in $replacements.GetEnumerator()) {
        $manifest = $manifest.Replace($replacement.Key, $replacement.Value)
    }
    $manifestPath = Join-Path $stage 'AppxManifest.xml'
    [System.IO.File]::WriteAllText($manifestPath, $manifest, [System.Text.UTF8Encoding]::new($false))

    $msix = Join-Path $outputRoot "factorseal-$crateVersion-windows-store-$Architecture.msix"
    & $MakeAppx pack /d $stage /p $msix /o
    if ($LASTEXITCODE -ne 0) { throw 'makeappx.exe failed to create the MSIX' }

    if (-not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
        $thumbprint = $SigningCertificateThumbprint.Replace(' ', '')
        if ($thumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
            throw 'SigningCertificateThumbprint must be a 40-character SHA-1 certificate thumbprint'
        }
        $certificate = Get-ChildItem "Cert:\CurrentUser\My\$thumbprint" -ErrorAction SilentlyContinue
        if ($null -eq $certificate) {
            $certificate = Get-ChildItem "Cert:\LocalMachine\My\$thumbprint" -ErrorAction SilentlyContinue
        }
        if ($null -eq $certificate) { throw "Signing certificate was not found: $thumbprint" }
        if ($certificate.Subject -ne $Publisher) {
            throw "The signing certificate subject '$($certificate.Subject)' must exactly match Publisher '$Publisher'"
        }
        $SignTool = Resolve-WindowsSdkTool 'signtool.exe' $SignTool
        $signArguments = @('sign', '/sha1', $thumbprint, '/fd', 'SHA256')
        if (-not [string]::IsNullOrWhiteSpace($TimestampUrl)) {
            $signArguments += @('/tr', $TimestampUrl, '/td', 'SHA256')
        }
        $signArguments += $msix
        & $SignTool @signArguments
        if ($LASTEXITCODE -ne 0) { throw 'signtool.exe failed to sign the MSIX' }
        $signature = Get-AuthenticodeSignature -LiteralPath $msix
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "MSIX signature verification failed: $($signature.Status)"
        }
    } else {
        Write-Warning 'The MSIX is unsigned for Microsoft Store ingestion and cannot be installed directly.'
    }

    & $MakeAppx unpack /p $msix /d $verify /o | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'makeappx.exe could not unpack the completed MSIX' }
    [xml]$verifiedManifest = Get-Content -LiteralPath (Join-Path $verify 'AppxManifest.xml') -Raw
    $namespace = [System.Xml.XmlNamespaceManager]::new($verifiedManifest.NameTable)
    $namespace.AddNamespace('f', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    $namespace.AddNamespace('uap5', 'http://schemas.microsoft.com/appx/manifest/uap/windows10/5')
    $alias = $verifiedManifest.SelectSingleNode(
        '/f:Package/f:Applications/f:Application/f:Extensions/uap5:Extension/uap5:AppExecutionAlias/uap5:ExecutionAlias',
        $namespace
    )
    if ($null -eq $alias -or $alias.Alias -ne 'factorseal.exe') {
        throw 'The completed MSIX does not expose the factorseal.exe execution alias'
    }

    Write-Output $msix
}
finally {
    Pop-Location
    if ($null -ne $stageRoot -and (Test-Path -LiteralPath $stageRoot)) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
    }
}
