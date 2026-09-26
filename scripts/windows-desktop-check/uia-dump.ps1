# Prints the UI Automation tree of FactorSeal Desktop's windows: control
# type, name, AutomationId, and whether a node exposes a value. Used to check
# what an automation driver (or a screen reader) can find in the approval
# popup. Windows blocks UI Automation from a normal process into an elevated
# one, so run this at the same integrity level as Desktop.
param([string]$Out)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$lines = New-Object System.Collections.Generic.List[string]
$desktop = Get-Process factorseal-desktop -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $desktop) {
    $lines.Add('error=FactorSeal Desktop is not running')
} else {
    $lines.Add("desktop_pid=$($desktop.Id)")
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    $lines.Add("dumper_elevated=$elevated")
    $auto = [System.Windows.Automation.AutomationElement]
    $byPid = New-Object System.Windows.Automation.PropertyCondition($auto::ProcessIdProperty, $desktop.Id)
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    function Walk($element, [int]$depth) {
        $c = $element.Current
        $value = ''
        $pattern = $null
        if ($element.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) {
            # Report only whether a value is exposed and its length, never the value.
            $value = " value_length=$($pattern.Current.Value.Length)"
        }
        $lines.Add(('  ' * $depth) + "$($c.ControlType.ProgrammaticName) name='$($c.Name)' id='$($c.AutomationId)' password=$($c.IsPassword)$value")
        $child = $walker.GetFirstChild($element)
        while ($child) {
            Walk $child ($depth + 1)
            $child = $walker.GetNextSibling($child)
        }
    }
    foreach ($window in $auto::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children, $byPid)) {
        Walk $window 0
    }
}
if ($Out) { $lines | Set-Content -Path $Out -Encoding UTF8 } else { $lines }
