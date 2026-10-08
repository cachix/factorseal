# Watches FactorSeal Desktop's approval popup from outside the process.
# Runs on Windows (usually launched from WSL through interop) and writes
# key=value lines to observer.txt in OutDir, which check.sh parses. Creates
# OutDir\ready once it is listening, so the caller sends the request only
# after flash notifications are hooked. Files avoid PowerShell's buffering of
# piped output.
param(
    [Parameter(Mandatory = $true)][string]$OutDir,
    [int]$Seconds = 12,
    # Picks one Desktop when several run (for example one on a test vault).
    [int]$DesktopPid,
    # When the popup opens in the foreground, hand the foreground straight
    # back to the window that had it before, as when a person keeps typing
    # elsewhere. The popup must then flash.
    [switch]$Steal
)
$ErrorActionPreference = 'Stop'
$report = Join-Path $OutDir 'observer.txt'
function Emit([string]$line) { Add-Content -Path $report -Value $line -Encoding UTF8 }
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type -ReferencedAssemblies System.Windows.Forms -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

public static class Win {
    public delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc proc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(IntPtr hwnd, out int pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int max);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr value);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr FindWindow(string cls, string title);
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hwnd, int command);
    // An owned popup has no taskbar button; its root owner's button stands for it.
    [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);

    // Windows lets a process take the foreground right after it sent input,
    // so tap Alt first.
    public static bool Activate(IntPtr hwnd) {
        keybd_event(0x12, 0, 0, UIntPtr.Zero);
        keybd_event(0x12, 0, 2, UIntPtr.Zero);
        return SetForegroundWindow(hwnd);
    }
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }

    public static string Title(IntPtr hwnd) {
        var text = new StringBuilder(256);
        GetWindowText(hwnd, text, text.Capacity);
        return text.ToString();
    }

    public static int Pid(IntPtr hwnd) { int pid; GetWindowThreadProcessId(hwnd, out pid); return pid; }

    // The popup is the Desktop process's visible top-level window titled
    // "... Secret access"; the main window is titled "FactorSeal Desktop".
    public static IntPtr FindPopup(int pid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hwnd, _) => {
            if (Pid(hwnd) == pid && IsWindowVisible(hwnd) && Title(hwnd).EndsWith("Secret access")) {
                found = hwnd;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}

// Receives shell notifications; HSHELL_FLASH (HSHELL_REDRAW | HSHELL_HIGHBIT)
// arrives for each window whose taskbar button is flashed.
public class FlashHook : NativeWindow {
    [DllImport("user32.dll")] static extern bool RegisterShellHookWindow(IntPtr hwnd);
    [DllImport("user32.dll")] static extern bool DeregisterShellHookWindow(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern uint RegisterWindowMessage(string name);
    const int HSHELL_FLASH = 0x8006;
    readonly uint shellHook;
    public readonly List<long> Flashed = new List<long>();

    public FlashHook() {
        CreateHandle(new CreateParams());
        shellHook = RegisterWindowMessage("SHELLHOOK");
        if (!RegisterShellHookWindow(Handle)) { throw new InvalidOperationException("RegisterShellHookWindow failed"); }
    }

    protected override void WndProc(ref Message m) {
        if ((uint)m.Msg == shellHook && m.WParam.ToInt64() == HSHELL_FLASH) { Flashed.Add(m.LParam.ToInt64()); }
        base.WndProc(ref m);
    }

    public void Stop() { DeregisterShellHookWindow(Handle); DestroyHandle(); }
}
"@

function Capture($rect, [string]$name) {
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    if ($width -le 0 -or $height -le 0) { return $null }
    $bitmap = New-Object System.Drawing.Bitmap $width, $height
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
    $path = Join-Path $OutDir $name
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose(); $bitmap.Dispose()
    $path
}

# Physical pixels, so window rectangles match the screen capture.
[void][Win]::SetProcessDpiAwarenessContext([IntPtr](-4))

$desktop = if ($DesktopPid) {
    Get-Process -Id $DesktopPid -ErrorAction SilentlyContinue
} else {
    Get-Process factorseal-desktop -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $desktop) { Emit 'error=FactorSeal Desktop is not running'; exit 2 }
Emit "desktop_pid=$($desktop.Id)"

$hook = New-Object FlashHook
$other = $null
if ($Steal) {
    # Stands in for the app the person keeps working in. Desktop's own main
    # window would not do: it owns the popup, which always stays above it.
    $other = New-Object System.Windows.Forms.Form
    $other.Text = 'FactorSeal check: another app'
    $other.StartPosition = 'Manual'
    $other.Location = New-Object System.Drawing.Point(40, 40)
    $other.Size = New-Object System.Drawing.Size(360, 140)
    # Shown without activation, so Desktop's state at the request is unchanged.
    [void][Win]::ShowWindow($other.Handle, 4)
}
New-Item -ItemType File -Path (Join-Path $OutDir 'ready') | Out-Null

$deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
$popup = [IntPtr]::Zero
$foreground = [IntPtr]::Zero
$capturedAt = [DateTime]::MaxValue
$taskbarShot = $null
while ([DateTime]::UtcNow -lt $deadline) {
    [System.Windows.Forms.Application]::DoEvents()
    if ($popup -eq [IntPtr]::Zero) {
        $popup = [Win]::FindPopup($desktop.Id)
        if ($popup -ne [IntPtr]::Zero) {
            Emit "popup_seen_at=$([DateTime]::UtcNow.ToString('HH:mm:ss.fff'))"
            if ($Steal) {
                $took = $false
                for ($i = 0; $i -lt 25 -and -not $took; $i++) {
                    $took = [Win]::GetForegroundWindow() -eq $popup
                    if (-not $took) { Start-Sleep -Milliseconds 20 }
                }
                Emit "popup_took_foreground=$took"
                if ($took) {
                    [void][Win]::Activate($other.Handle)
                    # The switch completes asynchronously.
                    Start-Sleep -Milliseconds 100
                    [System.Windows.Forms.Application]::DoEvents()
                    Emit "stolen=$([Win]::GetForegroundWindow() -eq $other.Handle)"
                }
            }
            # Give activation and the first frame time to settle.
            Start-Sleep -Milliseconds 700
            [System.Windows.Forms.Application]::DoEvents()
            $foreground = [Win]::GetForegroundWindow()
            Emit "popup_title=$([Win]::Title($popup))"
            # An owned popup always stays above its owner, so it shows whenever
            # the owner is in front.
            $owner = [Win]::GetAncestor($popup, 3)
            Emit "popup_foreground=$([bool]($foreground -eq $popup -or ($owner -ne $popup -and $foreground -eq $owner)))"
            Emit "foreground_title=$([Win]::Title($foreground))"
            Emit "foreground_process=$((Get-Process -Id ([Win]::Pid($foreground)) -ErrorAction SilentlyContinue).Name)"
            $rect = New-Object Win+RECT
            [void][Win]::GetWindowRect($popup, [ref]$rect)
            Emit "popup_rect=$($rect.Left),$($rect.Top),$($rect.Right),$($rect.Bottom)"
            # A screen capture shows what is on top at that spot, so a popup
            # kept behind another app shows that app instead.
            $shot = Capture $rect 'popup.png'
            if ($shot) { Emit "popup_screenshot=$shot" }
            $capturedAt = [DateTime]::UtcNow
        }
    } elseif ($foreground -ne $popup -and -not $taskbarShot -and [DateTime]::UtcNow -gt $capturedAt.AddSeconds(5)) {
        # Evidence of the flash: the taskbar once Windows has finished flashing
        # and left the button highlighted.
        $tray = [Win]::FindWindow('Shell_TrayWnd', $null)
        $trayRect = New-Object Win+RECT
        if ($tray -ne [IntPtr]::Zero -and [Win]::GetWindowRect($tray, [ref]$trayRect)) {
            $taskbarShot = Capture $trayRect 'taskbar.png'
            if ($taskbarShot) { Emit "taskbar_screenshot=$taskbarShot" }
        }
    }
    Start-Sleep -Milliseconds 50
}
$hook.Stop()
if ($other) { $other.Close() }

Emit "popup_seen=$([bool]($popup -ne [IntPtr]::Zero))"
$flashed = $false
if ($popup -ne [IntPtr]::Zero) {
    # GA_ROOTOWNER; the popup itself when it has no owner.
    $button = [Win]::GetAncestor($popup, 3)
    if ($button -eq [IntPtr]::Zero) { $button = $popup }
    $flashed = $hook.Flashed -contains $button.ToInt64()
    Emit "popup_owned=$($button -ne $popup)"
}
Emit "popup_flashed=$flashed"
Emit "flash_events=$($hook.Flashed.Count)"
