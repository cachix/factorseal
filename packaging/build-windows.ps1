param([string]$OutputDirectory = "dist")
$ErrorActionPreference = "Stop"

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
    $metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
    $factorseal = Join-Path $metadata.target_directory "release/factorseal.exe"
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Copy-Item $factorseal, "LICENSE", "README.md" -Destination $stage
    Copy-Item "packaging/windows/factorseal-task.xml.in", "packaging/windows/factorseal-askpass.ps1", "packaging/windows/factorseal-askpass.cmd" -Destination $stage
    Copy-Item "acceptance/windows.ps1" -Destination (Join-Path $stage "run-acceptance.ps1")
    $zip = Join-Path $OutputDirectory "$archive.zip"
    Compress-Archive -Path $stage -DestinationPath $zip -Force
    Write-Output $zip
}
finally {
    if (Test-Path $stageRoot) { Remove-Item -Recurse -Force $stageRoot }
}
