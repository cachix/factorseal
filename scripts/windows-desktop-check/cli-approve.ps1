# Approves one pending permission with `factorseal permissions approve`, the
# way a person at a terminal would. The command insists on a terminal for its
# prompts, so it runs in its own console window; this script types -Answer at
# the lifetime prompt (empty accepts the default) and presses Enter, and the
# password comes from -PasswordFile. It types only while that console is the
# foreground window, so keystrokes never land in another app.
#
# Use it only with a throwaway vault (test-vault.ps1). Prints key=value lines:
# exit (the command's exit code) and stdout (what it printed).
param(
    [Parameter(Mandatory = $true)][string]$Cli,
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$PasswordFile,
    [Parameter(Mandatory = $true)][string]$Id,
    [string]$Answer = '',
    [int]$Seconds = 30
)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class ApprovalConsole {
    [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr dwExtraInfo; public uint pad1, pad2; }
    [StructLayout(LayoutKind.Sequential)] struct INPUT { public uint type; public KEYBDINPUT ki; }
    [DllImport("user32.dll")] static extern uint SendInput(uint count, INPUT[] inputs, int size);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    public delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc proc, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr hwnd, System.Text.StringBuilder text, int max);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);

    // A visible top-level window with exactly this title.
    public static IntPtr Find(string wanted) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hwnd, _) => {
            var title = new System.Text.StringBuilder(256);
            GetWindowText(hwnd, title, title.Capacity);
            if (IsWindowVisible(hwnd) && title.ToString() == wanted) {
                found = hwnd;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    static void Key(ushort vk, ushort scan, uint flags) {
        var down = new INPUT { type = 1 };
        down.ki.wVk = vk;
        down.ki.wScan = scan;
        down.ki.dwFlags = flags;
        var up = down;
        up.ki.dwFlags = flags | 2;
        if (SendInput(2, new[] { down, up }, Marshal.SizeOf(typeof(INPUT))) != 2) {
            throw new InvalidOperationException("SendInput was blocked");
        }
    }

    // Windows lets a process take the foreground right after it sent input,
    // so tap Alt first.
    public static bool Raise(IntPtr hwnd) {
        Key(0x12, 0, 0);
        return SetForegroundWindow(hwnd);
    }

    public static void Type(string text) {
        foreach (char c in text) { Key(0, c, 4); }
        Key(0x0D, 0, 0);
    }
}
"@

$title = "factorseal-cli-approve-$Id"
$out = Join-Path $env:TEMP "$title.txt"
$batch = Join-Path $env:TEMP "$title.cmd"
Remove-Item $out, "$out.exit" -ErrorAction SilentlyContinue
# Only standard output is redirected: the prompts need the console.
Set-Content -Encoding ASCII -Path $batch -Value @"
@echo off
title $title
"$Cli" --root "$Root" --password-file "$PasswordFile" permissions approve $Id > "$out"
rem The redirection comes first: "echo 0> file" would redirect handle 0.
> "$out.exit" echo %errorlevel%
"@
# conhost gives a classic console window even where Windows Terminal is the
# default terminal, so the window is found by its title.
$process = Start-Process conhost.exe -ArgumentList 'cmd.exe', '/c', "`"$batch`"" -PassThru

$window = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds($Seconds)
while ($window -eq [IntPtr]::Zero -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 200
    $window = [ApprovalConsole]::Find($title)
}
if ($window -eq [IntPtr]::Zero) { 'error=the approval console did not open'; exit 1 }
# Let the command reach its prompt before typing.
Start-Sleep -Seconds 2
[void][ApprovalConsole]::Raise($window)
Start-Sleep -Milliseconds 300
if ([ApprovalConsole]::GetForegroundWindow() -ne $window) {
    'error=the approval console is not in the foreground; nothing was typed'
    if (-not $process.HasExited) { $process.Kill() }
    exit 1
}
[ApprovalConsole]::Type($Answer)
# conhost may hand the console to another terminal host and exit at once,
# so wait for the batch file's result rather than for the process.
$deadline = (Get-Date).AddSeconds($Seconds)
while (-not (Test-Path "$out.exit") -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 200
}
if (-not (Test-Path "$out.exit")) { 'error=the approval did not finish'; exit 1 }
Start-Sleep -Milliseconds 200
"exit=$((Get-Content "$out.exit" -Raw).Trim())"
"stdout=$((Get-Content $out -Raw) -replace '\r?\n', ' ')"
Remove-Item $out, "$out.exit", $batch -ErrorAction SilentlyContinue
