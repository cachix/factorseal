# Drives FactorSeal Desktop like a person: unlocks the main window or a popup
# kept open by a seal, grants or denies the approval popup, or presses a named
# button or Escape in it. -Title picks another popup by the end of its title,
# such as 'Browser access' for the browser extension's prompt. UI Automation
# finds the controls; the clicks and keystrokes are real input, since the
# popup accepts approval only after a mouse click inside it and one second
# without changes. Every click first checks that the target window is in the
# foreground and is the window under the pointer, so a click never lands in
# another app.
#
# Use it only with a throwaway vault (test-vault.ps1): the password is typed
# from -PasswordFile. Prints key=value lines; the password is never printed.
param(
    [Parameter(Mandatory = $true)][ValidateSet('find', 'unlock', 'unlock-popup', 'grant', 'deny', 'press', 'escape')][string]$Action,
    [Parameter(Mandatory = $true)][int]$DesktopPid,
    [string]$PasswordFile,
    [string]$Title,
    # press: the button to click. unlock-popup: the button to wait for once unlocked.
    [string]$Name,
    [int]$Seconds = 15
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class Input {
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT { public int dx, dy; public uint mouseData, dwFlags, time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Explicit)] struct UNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)] struct INPUT { public uint type; public UNION u; }
    [DllImport("user32.dll")] static extern uint SendInput(uint count, INPUT[] inputs, int size);
    [DllImport("user32.dll")] static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(POINT point);
    [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    public delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc proc, IntPtr lParam);
    [DllImport("user32.dll")] static extern int GetWindowThreadProcessId(IntPtr hwnd, out int pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr hwnd, System.Text.StringBuilder text, int max);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);

    // A visible top-level window of the process whose title ends as given.
    // UI Automation lists the popup under the main window when Windows makes
    // the main window its owner, so search the window list instead.
    public static IntPtr Find(int pid, string suffix) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hwnd, _) => {
            int owner;
            GetWindowThreadProcessId(hwnd, out owner);
            var title = new System.Text.StringBuilder(256);
            GetWindowText(hwnd, title, title.Capacity);
            if (owner == pid && IsWindowVisible(hwnd) && title.ToString().EndsWith(suffix)) {
                found = hwnd;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr value);
    [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int cx, int cy, uint flags);
    const uint SWP_NOSIZE = 0x1, SWP_NOMOVE = 0x2, SWP_NOACTIVATE = 0x10;

    // An always-on-top window (such as a pinned terminal) covers even the
    // foreground window; a topmost window stays above it until unpinned.
    public static void Pin(IntPtr hwnd, bool pinned) {
        SetWindowPos(hwnd, new IntPtr(pinned ? -1 : -2), 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE);
    }
    const uint INPUT_MOUSE = 0, INPUT_KEYBOARD = 1;
    const uint MOUSEEVENTF_LEFTDOWN = 0x2, MOUSEEVENTF_LEFTUP = 0x4;
    const uint KEYEVENTF_KEYUP = 0x2, KEYEVENTF_UNICODE = 0x4;
    const ushort VK_MENU = 0x12;

    static void Send(INPUT[] inputs) {
        if (SendInput((uint)inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT))) != inputs.Length) {
            throw new InvalidOperationException("SendInput was blocked");
        }
    }

    // The top-level window under a screen point.
    public static IntPtr RootAt(int x, int y) {
        var point = new POINT { X = x, Y = y };
        return GetAncestor(WindowFromPoint(point), 2);
    }

    public static void Click(int x, int y) {
        SetCursorPos(x, y);
        var down = new INPUT { type = INPUT_MOUSE };
        down.u.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
        var up = new INPUT { type = INPUT_MOUSE };
        up.u.mi.dwFlags = MOUSEEVENTF_LEFTUP;
        Send(new[] { down, up });
    }

    // Empty the focused field: End, then Backspace until nothing is left.
    // Ctrl+A would be simpler, but Desktop does not see an injected Ctrl
    // key and inserts an "A" instead.
    public static void Clear(int keys) {
        var end = new INPUT { type = INPUT_KEYBOARD };
        end.u.ki.wVk = 0x23;
        var endUp = end;
        endUp.u.ki.dwFlags = KEYEVENTF_KEYUP;
        Send(new[] { end, endUp });
        for (int i = 0; i < keys; i++) {
            var back = new INPUT { type = INPUT_KEYBOARD };
            back.u.ki.wVk = 0x08;
            var backUp = back;
            backUp.u.ki.dwFlags = KEYEVENTF_KEYUP;
            Send(new[] { back, backUp });
        }
    }

    public static void Key(ushort vk) {
        var down = new INPUT { type = INPUT_KEYBOARD };
        down.u.ki.wVk = vk;
        var up = down;
        up.u.ki.dwFlags = KEYEVENTF_KEYUP;
        Send(new[] { down, up });
    }

    public static void Type(string text) {
        foreach (char c in text) {
            var down = new INPUT { type = INPUT_KEYBOARD };
            down.u.ki.wScan = c;
            down.u.ki.dwFlags = KEYEVENTF_UNICODE;
            var up = down;
            up.u.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
            Send(new[] { down, up });
        }
    }

    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hwnd);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hwnd, int command);

    // Windows lets a process take the foreground right after it sent input,
    // so tap Alt first. Alt alone does nothing in Desktop's windows. A
    // minimized window can still be the foreground one, but its controls are
    // off-screen, so restore it too.
    public static bool Raise(IntPtr hwnd) {
        if (IsIconic(hwnd)) ShowWindow(hwnd, 9);
        var down = new INPUT { type = INPUT_KEYBOARD };
        down.u.ki.wVk = VK_MENU;
        var up = down;
        up.u.ki.dwFlags = KEYEVENTF_KEYUP;
        Send(new[] { down, up });
        return SetForegroundWindow(hwnd);
    }
}
"@

function Emit([string]$line) { Write-Output $line }
function Fail([string]$message) { Emit "error=$message"; exit 1 }

# Physical pixels, so UI Automation rectangles match the pointer's coordinates.
[void][Input]::SetProcessDpiAwarenessContext([IntPtr](-4))

$auto = [System.Windows.Automation.AutomationElement]
$scope = [System.Windows.Automation.TreeScope]
if (-not (Get-Process -Id $DesktopPid -ErrorAction SilentlyContinue)) { Fail "Desktop $DesktopPid is not running" }

# The main window is titled "FactorSeal Desktop"; the popup's title ends in
# "Secret access" (see observe.ps1).
function FindWindow {
    $suffix = if ($Title) { $Title } elseif ($Action -eq 'unlock') { 'FactorSeal Desktop' } else { 'Secret access' }
    $hwnd = [Input]::Find($DesktopPid, $suffix)
    if ($hwnd -eq [IntPtr]::Zero) { return $null }
    $auto::FromHandle($hwnd)
}

# A name with * matches as a wildcard, as the browser prompt's account
# buttons are named "title · username". -Button skips text with the same
# name, such as the browser prompt's title "Save login" above its button.
function Find($window, [string]$name, [switch]$Button) {
    $condition = [System.Windows.Automation.Condition]::TrueCondition
    if ($Button) {
        $condition = New-Object System.Windows.Automation.PropertyCondition($auto::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
    }
    if ($name.Contains('*')) {
        foreach ($element in $window.FindAll($scope::Descendants, $condition)) { if ($element.Current.Name -like $name) { return $element } }
        return $null
    }
    $byName = New-Object System.Windows.Automation.PropertyCondition($auto::NameProperty, $name)
    $window.FindFirst($scope::Descendants, (New-Object System.Windows.Automation.AndCondition($byName, $condition)))
}

# Waits for a named control to be enabled and returns it.
function WaitFor($window, [string]$name, [int]$seconds, [switch]$Button) {
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $element = Find $window $name -Button:$Button
        if ($element -and $element.Current.IsEnabled) { return $element }
        Start-Sleep -Milliseconds 100
    }
    $null
}

function ClickOn($window, $element, [string]$what) {
    $hwnd = [IntPtr]$window.Current.NativeWindowHandle
    $rect = $element.Current.BoundingRectangle
    if ($rect.IsEmpty -or $rect.Width -le 0) { Fail "$what has no screen position" }
    $x = [int]($rect.X + $rect.Width / 2)
    $y = [int]($rect.Y + $rect.Height / 2)
    if ([Input]::GetForegroundWindow() -ne $hwnd) { Fail "the window lost the foreground before clicking $what" }
    if ([Input]::RootAt($x, $y) -ne $hwnd) { Fail "another window covers $what at $x,$y" }
    [Input]::Click($x, $y)
    Emit "clicked=$what"
}

# Reports whether the popup is open, without touching anything.
# Also reports where it is, and whether it lies wholly on one screen.
if ($Action -eq 'find') {
    $window = FindWindow
    Emit "popup_open=$([bool]$window)"
    if ($window) {
        Add-Type -AssemblyName System.Windows.Forms
        $rect = $window.Current.BoundingRectangle
        Emit "bounds=$([int]$rect.X),$([int]$rect.Y),$([int]$rect.Width),$([int]$rect.Height)"
        $inside = [System.Windows.Forms.Screen]::AllScreens | Where-Object {
            $b = $_.Bounds
            $rect.X -ge $b.X -and $rect.Y -ge $b.Y -and $rect.Right -le $b.Right -and $rect.Bottom -le $b.Bottom
        }
        Emit "on_screen=$([bool]$inside)"
        Emit "foreground=$([Input]::GetForegroundWindow() -eq [IntPtr]$window.Current.NativeWindowHandle)"
    }
    exit 0
}

# Keystrokes go to whatever has focus, so check just before typing.
function TypeInto($window, [string]$text) {
    if ([Input]::GetForegroundWindow() -ne [IntPtr]$window.Current.NativeWindowHandle) {
        Fail 'the window lost the foreground before typing'
    }
    # A failed attempt leaves its text in the field; remove it first.
    [Input]::Clear(256)
    [Input]::Type($text)
}

$password = $null
if ($Action -in 'unlock', 'unlock-popup', 'grant') {
    if (-not $PasswordFile) { Fail "-PasswordFile is required to $Action" }
    $password = [System.IO.File]::ReadAllText($PasswordFile).TrimEnd("`r", "`n")
}

$window = $null
$deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
while (-not $window -and [DateTime]::UtcNow -lt $deadline) {
    $window = FindWindow
    if (-not $window) { Start-Sleep -Milliseconds 100 }
}
if (-not $window) { Fail "no $(if ($Action -eq 'unlock') { 'main window' } else { 'approval popup' }) within $Seconds s" }
Emit "window=$($window.Current.Name)"
$hwnd = [IntPtr]$window.Current.NativeWindowHandle
if ([Input]::GetForegroundWindow() -ne $hwnd -or [Input]::IsIconic($hwnd)) {
    [void][Input]::Raise($hwnd)
    Start-Sleep -Milliseconds 300
}
$foreground = [Input]::GetForegroundWindow() -eq $hwnd
Emit "foreground=$foreground"
if (-not $foreground) { Fail 'Windows kept the window out of the foreground' }
[Input]::Pin($hwnd, $true)

try {
switch ($Action) {
    'unlock' {
        $field = WaitFor $window 'FactorSeal password' 5
        if (-not $field) { Fail 'no password field; is the vault already unlocked?' }
        ClickOn $window $field 'password field'
        Start-Sleep -Milliseconds 200
        TypeInto $window $password
        $button = WaitFor $window 'Unlock vault' 2 -Button
        if (-not $button) { Fail 'no enabled Unlock vault button' }
        ClickOn $window $button 'Unlock vault'
        # The password field goes away once the vault is unsealed. It also
        # disappears briefly while an attempt runs, and comes back after a
        # wrong password, so it must stay away.
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        $goneSince = $null
        while ([DateTime]::UtcNow -lt $deadline) {
            if (Find $window 'FactorSeal password') {
                $goneSince = $null
            } elseif (-not $goneSince) {
                $goneSince = [DateTime]::UtcNow
            } elseif (([DateTime]::UtcNow - $goneSince).TotalMilliseconds -ge 1500) {
                break
            }
            Start-Sleep -Milliseconds 200
        }
        $done = $goneSince -and -not (Find $window 'FactorSeal password')
        Emit "unlocked=$done"
    }
    'grant' {
        $field = WaitFor $window 'FactorSeal password' 5
        if (-not $field) { Fail 'the popup shows no password field' }
        # The first click arms the popup's input guard and focuses the field.
        ClickOn $window $field 'password field'
        # The guard also waits one second after the popup's requests change.
        Start-Sleep -Milliseconds 1200
        TypeInto $window $password
        $button = WaitFor $window 'Grant access' 10 -Button
        if (-not $button) { Fail 'no enabled Grant access button' }
        ClickOn $window $button 'Grant access'
    }
    'unlock-popup' {
        # A popup kept open by a seal offers to unlock; it stays open to grant.
        $field = WaitFor $window 'FactorSeal password' 5
        if (-not $field) { Fail 'the popup shows no password field' }
        ClickOn $window $field 'password field'
        Start-Sleep -Milliseconds 1200
        TypeInto $window $password
        $button = WaitFor $window 'Unlock to continue' 5 -Button
        if (-not $button) { Fail 'no enabled Unlock to continue button' }
        ClickOn $window $button 'Unlock to continue'
        Emit "unlocked=$([bool](WaitFor $window $(if ($Name) { $Name } else { 'Grant access' }) 30 -Button))"
    }
    'press' {
        $button = WaitFor $window $Name 10 -Button
        if (-not $button) { Fail "no enabled $Name button" }
        ClickOn $window $button $Name
    }
    'escape' {
        if ([Input]::GetForegroundWindow() -ne $hwnd) { Fail 'the window lost the foreground before Escape' }
        [Input]::Key(0x1B)
        Emit 'pressed=Escape'
    }
    'deny' {
        $button = WaitFor $window 'Deny' 5 -Button
        if (-not $button) { Fail 'no enabled Deny button' }
        ClickOn $window $button 'Deny'
    }
}
} finally {
    # A closed popup has no window left to unpin.
    [Input]::Pin($hwnd, $false)
}
$password = $null

if ($Action -in 'grant', 'deny', 'press', 'escape') {
    # The popup closes once no request is left.
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ((FindWindow) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
    Emit "popup_closed=$(-not (FindWindow))"
}
