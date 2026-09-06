param(
    [ValidateSet('Run', 'Probe')][string]$Mode = 'Run',
    [string]$Fixture
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Mode -eq 'Probe') {
    # A positive control proves this process can read through the shared
    # parent. Failures below must come from product access controls.
    if ([IO.File]::ReadAllText((Join-Path $Fixture 'public-control')) -ne 'public') { exit 2 }
    $paths = @('vault/factorseal.json', 'vault/vault.db', 'vault/vault.db-wal', 'vault/vault.db-shm', 'vault/vault.lock', 'export.factorseal')
    foreach ($relative in $paths) {
        try {
            $file = [IO.File]::OpenRead((Join-Path $Fixture $relative))
            $file.Dispose()
            exit 3
        } catch [UnauthorizedAccessException] { }
    }
    try {
        [IO.File]::WriteAllText((Join-Path $Fixture 'vault/injected'), 'unexpected')
        exit 4
    } catch [UnauthorizedAccessException] { }
    $pipeName = [IO.File]::ReadAllText((Join-Path $Fixture 'pipe-name')).Substring(9)
    $client = [IO.Pipes.NamedPipeClientStream]::new('.', $pipeName, [IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect(5000)
        exit 5
    } catch [UnauthorizedAccessException] {
        # A timeout is not a pass: the owner's positive control connected.
    } finally { $client.Dispose() }
    $env:FACTORSEAL_FOREIGN_FIXTURE = Join-Path $Fixture 'guest'
    & (Join-Path $Fixture 'native-tests.exe') --ignored --exact vault::windows_client::tests::serve_foreign_pipe_fixture *> (Join-Path $env:FACTORSEAL_FOREIGN_FIXTURE 'probe.log')
    exit $LASTEXITCODE
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Two-account acceptance requires an administrator on an isolated Windows test machine.'
}
$Fixture = Join-Path ([IO.Path]::GetTempPath()) ('factorseal-security-' + [Guid]::NewGuid().ToString('N'))
$account = 'fs_test_' + [Guid]::NewGuid().ToString('N').Substring(0, 10)
$server = $null
$probe = $null
$created = $false
$previousFixture = $env:FACTORSEAL_SECURITY_FIXTURE
$previousForeignPipe = $env:FACTORSEAL_FOREIGN_PIPE
try {
    New-Item -ItemType Directory -Path $Fixture | Out-Null
    & icacls $Fixture /grant '*S-1-1-0:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not prepare shared fixture parent.' }
    Copy-Item $PSCommandPath (Join-Path $Fixture 'probe.ps1')
    [IO.File]::WriteAllText((Join-Path $Fixture 'public-control'), 'public')
    $artifacts = & cargo test -p factorseal --lib --all-features --no-run --message-format=json
    if ($LASTEXITCODE -ne 0) { throw 'Could not build native test harness.' }
    $harness = $artifacts | ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object { $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'factorseal' -and $_.profile.test -and $_.executable } |
        Select-Object -Last 1 -ExpandProperty executable
    if (-not $harness) { throw 'Native test harness missing.' }
    Copy-Item $harness (Join-Path $Fixture 'native-tests.exe')
    $env:FACTORSEAL_SECURITY_FIXTURE = $Fixture
    & $harness --ignored --exact security::windows::tests::create_two_account_fixture
    if ($LASTEXITCODE -ne 0) { throw 'Private fixture creation failed.' }
    $server = Start-Process -FilePath $harness -ArgumentList '--ignored --exact vault::windows::tests::serve_two_account_pipe_fixture' -PassThru -NoNewWindow
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path (Join-Path $Fixture 'pipe-name'))) {
        if ($server.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'Pipe fixture did not start.' }
        Start-Sleep -Milliseconds 50
    }
    # Owner controls: the same files and pipe must be usable by this account.
    foreach ($relative in @('vault/factorseal.json', 'vault/vault.db', 'vault/vault.db-wal', 'vault/vault.db-shm', 'vault/vault.lock', 'export.factorseal')) {
        if ([IO.File]::ReadAllText((Join-Path $Fixture $relative)) -ne 'synthetic acceptance marker') { throw 'Owner read failed.' }
    }
    $pipeName = [IO.File]::ReadAllText((Join-Path $Fixture 'pipe-name')).Substring(9)
    $client = [IO.Pipes.NamedPipeClientStream]::new('.', $pipeName, [IO.Pipes.PipeDirection]::InOut)
    try { $client.Connect(5000) } finally { $client.Dispose() }
    $password = ConvertTo-SecureString ('Fs!9-' + [Guid]::NewGuid().ToString('N')) -AsPlainText -Force
    New-LocalUser -Name $account -Password $password -AccountNeverExpires | Out-Null
    $created = $true
    $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $usersGroup -Member $account
    $guestDirectory = Join-Path $Fixture 'guest'
    New-Item -ItemType Directory -Path $guestDirectory | Out-Null
    $guestSid = (Get-LocalUser -Name $account).SID.Value
    & icacls $guestDirectory /grant "*${guestSid}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not prepare guest server fixture.' }
    $credential = [PSCredential]::new("$env:COMPUTERNAME\$account", $password)
    $arguments = '-NoProfile -File "' + (Join-Path $Fixture 'probe.ps1') + '" -Mode Probe -Fixture "' + $Fixture + '"'
    $probe = Start-Process -FilePath (Get-Process -Id $PID).Path -Credential $credential -ArgumentList $arguments -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    while (-not (Test-Path (Join-Path $guestDirectory 'foreign-pipe'))) {
        if ($probe.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'Guest failed before starting its permissive pipe.' }
        Start-Sleep -Milliseconds 50
    }
    $env:FACTORSEAL_FOREIGN_PIPE = [IO.File]::ReadAllText((Join-Path $guestDirectory 'foreign-pipe'))
    & $harness --ignored --exact vault::windows_client::tests::reject_foreign_pipe_fixture
    if ($LASTEXITCODE -ne 0) { throw 'Client did not reject foreign-account pipe.' }
    if (-not $probe.WaitForExit(60000)) { $probe.Kill($true); $probe.WaitForExit(); throw 'Second-account probe timed out.' }
    if ($probe.ExitCode -ne 0) {
        Get-Content (Join-Path $guestDirectory 'probe.log') -ErrorAction SilentlyContinue
        throw "Second-account access controls failed (probe exit $($probe.ExitCode))."
    }
    [IO.File]::WriteAllText((Join-Path $Fixture 'done'), 'done')
    if (-not $server.WaitForExit(10000)) { throw 'Pipe fixture did not exit.' }
    if ($server.ExitCode -ne 0) { throw 'Pipe fixture failed.' }
    Write-Output 'PASS: owner access, second-account file/pipe denial, and zero request bytes released to a foreign-account pipe.'
} finally {
    $env:FACTORSEAL_SECURITY_FIXTURE = $previousFixture
    $env:FACTORSEAL_FOREIGN_PIPE = $previousForeignPipe
    if ($probe -and -not $probe.HasExited) { $probe.Kill($true); $probe.WaitForExit() }
    if ($server -and -not $server.HasExited) { $server.Kill(); $server.WaitForExit() }
    if ($created) { Remove-LocalUser -Name $account }
    if (Test-Path $Fixture) { Remove-Item -LiteralPath $Fixture -Recurse -Force }
}
