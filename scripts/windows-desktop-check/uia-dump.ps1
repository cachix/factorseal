# Prints the UI Automation tree of FactorSeal Desktop's windows: control
# type, name, AutomationId, whether a node exposes a value, and whether a
# selectable one (a radio button) is selected. Used to check
# what an automation driver (or a screen reader) can find in the approval
# popup. Windows blocks UI Automation from a normal process into an elevated
# one, so run this at the same integrity level as Desktop. -DesktopPid picks
# one Desktop when several run (for example one on a test vault).
param([string]$Out, [int]$DesktopPid)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$lines = New-Object System.Collections.Generic.List[string]
$desktop = if ($DesktopPid) {
    Get-Process -Id $DesktopPid -ErrorAction SilentlyContinue
} else {
    Get-Process factorseal-desktop -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $desktop) {
    $lines.Add('error=FactorSeal Desktop is not running')
} else {
    $lines.Add("desktop_pid=$($desktop.Id)")
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    $lines.Add("dumper_elevated=$elevated")
    $auto = [System.Windows.Automation.AutomationElement]
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    function Walk($element, [int]$depth) {
        $c = $element.Current
        $value = ''
        $pattern = $null
        if ($element.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) {
            # Report only whether a value is exposed and its length, never the value.
            $value = " value_length=$($pattern.Current.Value.Length)"
        }
        $selected = ''
        if ($element.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$pattern)) {
            $selected = " selected=$($pattern.Current.IsSelected)"
        }
        $lines.Add(('  ' * $depth) + "$($c.ControlType.ProgrammaticName) name='$($c.Name)' id='$($c.AutomationId)' password=$($c.IsPassword)$value$selected")
        $child = $walker.GetFirstChild($element)
        while ($child) {
            Walk $child ($depth + 1)
            $child = $walker.GetNextSibling($child)
        }
    }
    # Each top-level window by its handle, not by walking down from the
    # desktop: AccessKit builds a window's tree when that window is asked
    # for it, so a popup owned by the main window shows up empty otherwise.
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class TopLevel {
    public delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc proc, IntPtr lParam);
    [DllImport("user32.dll")] static extern int GetWindowThreadProcessId(IntPtr hwnd, out int pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    public static List<IntPtr> Of(int pid) {
        var found = new List<IntPtr>();
        EnumWindows((hwnd, _) => {
            int owner;
            GetWindowThreadProcessId(hwnd, out owner);
            if (owner == pid && IsWindowVisible(hwnd)) { found.Add(hwnd); }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
"@
    # AccessKit builds a window's tree when that window is asked for it, and
    # walking down from the desktop does not ask a popup the main window
    # owns, which then shows up empty. Ask every window by its handle first,
    # then walk from the desktop. UI Automation lists an owned popup twice,
    # as a desktop child and under its owner, so it prints twice too.
    foreach ($hwnd in [TopLevel]::Of($desktop.Id)) { [void]$auto::FromHandle($hwnd).Current.Name }
    $byPid = New-Object System.Windows.Automation.PropertyCondition($auto::ProcessIdProperty, $desktop.Id)
    foreach ($window in $auto::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children, $byPid)) {
        Walk $window 0
    }
}
if ($Out) { $lines | Set-Content -Path $Out -Encoding UTF8 } else { $lines }
