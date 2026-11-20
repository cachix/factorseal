# Reports which window has the foreground, or brings a process's window there.
# browser-check.mjs uses it: a browser's own idea of whether it has focus
# (chrome.windows) can stay true while another app is in front.
#
#   foreground.ps1 -Action get
#   foreground.ps1 -Action raise -ProcessId P [-TitleLike PATTERN]
# Prints key=value lines: pid, process and title of the foreground window, and
# with -ProcessId, whether it is that process's window titled like -TitleLike
# (matched here: console output can mangle non-ASCII titles).
# -TitleLike picks the process's window by title, such as '*Microsoft*Edge'
# for a browser window rather than one of the browser's own bubbles. raise
# closes the process's other windows first: Edge shows a bubble about
# developer-mode extensions after starting, which takes the foreground.
param(
    [Parameter(Mandatory = $true)][ValidateSet('get', 'raise')][string]$Action,
    [int]$ProcessId,
    [string]$TitleLike = '*'
)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class Front {
    [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Explicit)] struct UNION { [FieldOffset(0)] public KEYBDINPUT ki; [FieldOffset(0)] public long pad0; [FieldOffset(8)] public long pad1; [FieldOffset(16)] public long pad2; [FieldOffset(24)] public long pad3; }
    [StructLayout(LayoutKind.Sequential)] struct INPUT { public uint type; public UNION u; }
    [DllImport("user32.dll")] static extern uint SendInput(uint count, INPUT[] inputs, int size);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(IntPtr hwnd, out int pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr hwnd, System.Text.StringBuilder text, int max);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc proc, IntPtr lParam);

    public static string Title(IntPtr hwnd) {
        var text = new System.Text.StringBuilder(256);
        GetWindowText(hwnd, text, text.Capacity);
        return text.ToString();
    }

    // The visible, titled top-level windows of the process, front first.
    public static System.Collections.Generic.List<IntPtr> Windows(int pid) {
        var found = new System.Collections.Generic.List<IntPtr>();
        EnumWindows((hwnd, _) => {
            int owner;
            GetWindowThreadProcessId(hwnd, out owner);
            if (owner == pid && IsWindowVisible(hwnd) && Title(hwnd).Length > 0) found.Add(hwnd);
            return true;
        }, IntPtr.Zero);
        return found;
    }

    // Windows lets a process take the foreground right after it sent input,
    // so tap Alt first.
    public static void TapAlt() {
        var down = new INPUT { type = 1 };
        down.u.ki.wVk = 0x12;
        var up = down;
        up.u.ki.dwFlags = 2;
        SendInput(2, new[] { down, up }, Marshal.SizeOf(typeof(INPUT)));
    }
}
"@

function Report {
    $hwnd = [Front]::GetForegroundWindow()
    $owner = 0
    [void][Front]::GetWindowThreadProcessId($hwnd, [ref]$owner)
    $name = (Get-Process -Id $owner -ErrorAction SilentlyContinue).Name
    Write-Output "pid=$owner"
    Write-Output "process=$name"
    Write-Output "title=$([Front]::Title($hwnd))"
    if ($ProcessId) { Write-Output "match=$($owner -eq $ProcessId -and [Front]::Title($hwnd) -like $TitleLike)" }
}

if ($Action -eq 'raise') {
    $windows = [Front]::Windows($ProcessId)
    foreach ($other in $windows | Where-Object { [Front]::Title($_) -notlike $TitleLike }) {
        Write-Output "closed=$([Front]::Title($other))"
        [void][Front]::PostMessage($other, 0x10, [IntPtr]::Zero, [IntPtr]::Zero)
    }
    $hwnd = $windows | Where-Object { [Front]::Title($_) -like $TitleLike } | Select-Object -First 1
    if (-not $hwnd) { Write-Output "error=no window of process $ProcessId titled like $TitleLike"; exit 1 }
    if ([Front]::IsIconic($hwnd)) { [void][Front]::ShowWindow($hwnd, 9) }
    [Front]::TapAlt()
    [void][Front]::SetForegroundWindow($hwnd)
    Start-Sleep -Milliseconds 200
}
Report
