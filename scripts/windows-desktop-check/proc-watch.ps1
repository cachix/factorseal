# Logs FactorSeal processes starting and exiting, and whether Desktop's
# window responds, for diagnosing launch and unlock problems. Only changes
# are written, with a timestamp. Includes crash reporting (WerFault) because
# a helper that crashes is otherwise easy to miss.
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$Seconds = 300
)
$names = 'factorseal', 'factorseal-desktop', 'factorseal-parser', 'factorseal-network', 'factorseal-browser', 'WerFault'
$known = @{}
$responding = @{}
function Log([string]$line) {
    Add-Content -Path $Out -Value "$([DateTime]::Now.ToString('HH:mm:ss.fff')) $line" -Encoding UTF8
}
Log "watching for $Seconds s"
$deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
while ([DateTime]::UtcNow -lt $deadline) {
    $now = @{}
    foreach ($p in Get-CimInstance Win32_Process | Where-Object { $names -contains [IO.Path]::GetFileNameWithoutExtension($_.Name) }) {
        $now[$p.ProcessId] = $p
        if (-not $known.ContainsKey($p.ProcessId)) {
            $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction SilentlyContinue
            Log "start $($p.Name) pid=$($p.ProcessId) parent=$($p.ParentProcessId) ($($parent.Name)) cmd=$($p.CommandLine)"
        }
    }
    foreach ($id in @($known.Keys)) {
        if (-not $now.ContainsKey($id)) { Log "exit  $($known[$id].Name) pid=$id" }
    }
    $known = $now
    foreach ($d in Get-Process factorseal-desktop -ErrorAction SilentlyContinue) {
        if ($d.MainWindowHandle -ne [IntPtr]::Zero) {
            $state = $d.Responding
            if ($responding[$d.Id] -ne $state) {
                Log "desktop pid=$($d.Id) window '$($d.MainWindowTitle)' responding=$state"
                $responding[$d.Id] = $state
            }
        }
    }
    Start-Sleep -Milliseconds 500
}
Log 'done'
