# Talks to `factorseal provider` directly, the way SecretSpec does: one
# rpc.initialize, then one provider request, as newline-delimited JSON-RPC
# over the process's standard input and output. Prints both replies and the
# provider's standard error, which SecretSpec never shows. Useful for
# requests the secretspec CLI cannot make, such as a write to a key the
# project does not declare, and for seeing the provider's exact answer.
#
# A `get` reply contains the secret value: use it only with a throwaway vault
# (test-vault.ps1), selected with -Root.
param(
    [Parameter(Mandatory = $true)][string]$Cli,
    [string]$Root,
    [ValidateSet('get', 'set')][string]$Method = 'get',
    [string]$Project = 'secretspec-ui-check',
    [string]$Profile = 'default',
    [string]$Key = 'DEMO_TOKEN',
    [string]$Value = 'provider-probe',
    # The folder SecretSpec would run in; the vault shows and binds it.
    [string]$Directory = (Get-Location).Path,
    [int]$Seconds = 10
)
$ErrorActionPreference = 'Stop'
$start = New-Object System.Diagnostics.ProcessStartInfo
$start.FileName = $Cli
$start.Arguments = 'provider'
$start.UseShellExecute = $false
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.WorkingDirectory = $Directory
if ($Root) { $start.EnvironmentVariables['FACTORSEAL_ROOT'] = $Root }
$provider = [System.Diagnostics.Process]::Start($start)
$stderr = $provider.StandardError.ReadToEndAsync()

function Send([int]$id, [string]$method, [int]$milliseconds, $params) {
    $deadline = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + $milliseconds
    $request = [ordered]@{
        jsonrpc = '2.0'
        id = $id
        method = $method
        _meta = @{ deadline_unix_ms = $deadline }
        params = $params
    }
    $provider.StandardInput.Write(($request | ConvertTo-Json -Depth 8 -Compress) + "`n")
    $provider.StandardInput.Flush()
    $provider.StandardOutput.ReadLine()
}

$initialize = [ordered]@{
    protocol = 'secretspec.provider'
    versions = @(1)
    client = @{ name = 'provider-probe'; version = '1' }
    limits = @{ max_frame_bytes = 32768; max_in_flight = 8 }
    application = [ordered]@{
        scheme = 'factorseal'
        uri = 'factorseal://default'
        context = [ordered]@{
            project = $Project
            profile = $Profile
            base_dir = $null
            reason = 'provider-probe'
            requested_authorization_duration_ms = $null
        }
    }
}
"initialize=$(Send 1 'rpc.initialize' 10000 $initialize)"

$address = [ordered]@{ kind = 'convention'; project = $Project; profile = $Profile; key = $Key }
$params = if ($Method -eq 'set') { [ordered]@{ address = $address; value = $Value } } else { [ordered]@{ address = $address } }
# The provider answers interaction_required shortly before this deadline if
# the request is still waiting for approval.
"$Method=$(Send 2 "provider.$Method" ($Seconds * 1000) $params)"

$provider.StandardInput.Close()
[void]$provider.WaitForExit(5000)
"stderr=$($stderr.Result.Trim())"
