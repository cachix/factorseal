# Saves a screenshot of FactorSeal Desktop's approval popup as a PNG. The
# popup's text is not exposed to UI Automation, so this is how a check sees
# what the popup says. The popup is raised and kept topmost for the capture,
# since an always-on-top app (such as a pinned terminal) would otherwise
# cover it, then released. Prints saved=PATH or error=REASON.
param(
    [Parameter(Mandatory = $true)][int]$DesktopPid,
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Shot {
    public delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc proc, IntPtr lParam);
    [DllImport("user32.dll")] static extern int GetWindowThreadProcessId(IntPtr hwnd, out int pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int max);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr value);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }

    // Found by title, not through UI Automation, which lists a popup owned
    // by the main window under it rather than at the top level.
    public static IntPtr FindPopup(int pid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hwnd, _) => {
            int owner;
            GetWindowThreadProcessId(hwnd, out owner);
            var title = new StringBuilder(256);
            GetWindowText(hwnd, title, title.Capacity);
            if (owner == pid && IsWindowVisible(hwnd) && title.ToString().EndsWith("Secret access")) {
                found = hwnd;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
"@

# Physical pixels, so the window rectangle matches the screen capture.
[void][Shot]::SetProcessDpiAwarenessContext([IntPtr](-4))
$popup = [Shot]::FindPopup($DesktopPid)
if ($popup -eq [IntPtr]::Zero) { 'error=no approval popup is open'; exit 1 }

# Windows lets a process take the foreground right after it sent input, so
# tap Alt first. SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE = 0x13.
[Shot]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
[Shot]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
[void][Shot]::SetForegroundWindow($popup)
[void][Shot]::SetWindowPos($popup, [IntPtr](-1), 0, 0, 0, 0, 0x13)
try {
    # Let the popup repaint on top before capturing.
    Start-Sleep -Milliseconds 600
    $rect = New-Object Shot+RECT
    [void][Shot]::GetWindowRect($popup, [ref]$rect)
    $bitmap = New-Object System.Drawing.Bitmap ($rect.Right - $rect.Left), ($rect.Bottom - $rect.Top)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
    $bitmap.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose(); $bitmap.Dispose()
} finally {
    [void][Shot]::SetWindowPos($popup, [IntPtr](-2), 0, 0, 0, 0, 0x13)
}
"saved=$Out"
