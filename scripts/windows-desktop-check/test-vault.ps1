# Creates a throwaway password-only vault for driving Desktop from scripts,
# so no real vault's password is ever typed by automation. Prints key=value
# lines: the vault root and the password file. The password is random and
# kept in a file only the current user can read, as the CLI's
# --password-file requires. Refuses to touch an existing vault.
param(
    [string]$Dir = (Join-Path $env:LOCALAPPDATA 'FactorSeal-check'),
    [Parameter(Mandatory = $true)][string]$Cli
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $Dir 'vault'
$passwordFile = Join-Path $Dir 'password'
if (Test-Path $root) {
    "root=$root"
    "password_file=$passwordFile"
    'created=False'
    exit 0
}
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

# 24 random bytes as base64: printable, so it can be typed as keystrokes.
$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
[System.IO.File]::WriteAllText($passwordFile, [Convert]::ToBase64String($bytes))
# Owner only: drop inherited entries and grant just this user.
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetOwner($me)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')))
Set-Acl -Path $passwordFile -AclObject $acl

$output = & $Cli --root $root --password-file $passwordFile init --unlock password 2>&1
if ($LASTEXITCODE -ne 0) {
    "error=factorseal init failed: $output"
    exit 1
}
"root=$root"
"password_file=$passwordFile"
'created=True'
