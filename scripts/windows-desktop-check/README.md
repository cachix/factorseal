# Windows Desktop checks from WSL2

Scripts for building FactorSeal natively on Windows and checking FactorSeal
Desktop's approval popup there, driven from a WSL2 shell. They exist because
Desktop cannot be cross-compiled from Linux (its renderer needs Windows'
shader compiler) and because what matters about the popup (focus, taskbar
flashing, what reaches the vault) only shows on a real Windows desktop.

Everything runs from the WSL2 checkout. The Windows side is a mirror of it,
by default `%USERPROFILE%\Projects\factorseal`; set `FACTORSEAL_WINDOWS_TREE`
(a WSL path such as `/mnt/c/Users/me/src/factorseal`) to use another.

## Scripts

| Script | Runs on | Does |
| --- | --- | --- |
| `build-windows.sh [release] [--broker]` | WSL | Mirrors the checkout and builds Desktop, the CLI (with the SecretSpec provider), and its parser, network and browser bridge helpers natively. Refuses to start while Desktop or the CLI runs. `--broker` also cross-compiles the WSL broker. |
| `build-windows.sh check` | WSL | Mirrors, then runs clippy and Desktop's tests natively. Safe while Desktop runs. |
| `check.sh popup [--delay S] [--key K]` | WSL | Sends a request through the WSL broker and reports whether the popup opened, reached the foreground or flashed its taskbar button, with screenshots of the popup and the taskbar and a check that the vault holds the pending request. |
| `check.sh grant --key K` | WSL | After the popup was approved, resends the request and checks that it succeeds without a new popup and that the grant stays within the 300-second WSL cap. |
| `observe.ps1` | Windows | Used by `check.sh`; hooks taskbar-flash notifications and captures the screenshots. |
| `uia-dump.ps1 [-Out FILE]` | Windows | Lists what UI Automation sees in Desktop's windows: control types, names, AutomationIds, and whether a value is exposed (never the value itself). |
| `proc-watch.ps1 -Out FILE [-Seconds N]` | Windows | Logs FactorSeal processes, their helpers and WerFault starting and exiting, and whether Desktop's window responds. For diagnosing hangs and crashes. |

PowerShell scripts are run from WSL as
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\...\script.ps1' ...`,
using their path in the Windows copy.

## Typical flow

1. `./scripts/windows-desktop-check/build-windows.sh --broker`
2. The user starts Desktop on Windows
   (`C:\...\factorseal\target\release\factorseal-desktop.exe`) and unlocks the
   vault. Only a person can do this step and step 4.
3. `./scripts/windows-desktop-check/check.sh popup`. Leave the popup alone
   until the result prints. For the "behind another app" case, use
   `--delay 10` and bring another app to the front during the delay.
4. The user approves the popup (or denies it).
5. `./scripts/windows-desktop-check/check.sh grant --key CHECK_...`, with the
   key printed by step 3.

Before changing Desktop's UI, run `build-windows.sh check`; afterwards,
`build-windows.sh` and the flow above.

## Reading the results

- `check.sh popup` passes when the popup is **in the foreground or flashed its
  taskbar button**. Windows decides whether a background app may take focus
  (it depends on recent input and timing), so either outcome is correct; a
  popup that is behind and does not flash is a failure.
- `popup.png` shows what was on screen where the popup is. When the popup is
  behind another app, that is the other app; `taskbar.png` then shows the
  highlighted button.
- `FACTORSEAL_TIMINGS=1` in Desktop's environment makes Desktop and its
  worker print each startup, unlock, and parse stage with its duration to
  stderr.

## Pitfalls

- **The vault seals itself after a few idle minutes.** The pending request is
  lost and the popup closes. `check.sh` checks before sending (and again after
  `--delay`); unlock and rerun when it says the vault is sealed.
- **Desktop locks its executables.** Quit it from the tray before
  `build-windows.sh release`.
- **Desktop is run from an elevated PowerShell on this setup**, and Windows
  blocks UI Automation from a normal process into an elevated one. From WSL,
  `uia-dump.ps1` then sees only window frames; run it from an elevated
  PowerShell to see the controls.
- **The CLI needs `secretspec-provider`** for native SecretSpec on Windows.
  Packaging leaves it out until the SecretSpec IPC crate is published;
  `build-windows.sh` adds it (see `docs/development.md`).
- **Desktop needs its helpers beside the CLI.** Every request is parsed by
  `factorseal-parser.exe`; without it, unlocking can hang.
- Windows PowerShell 5.1 writes files with a UTF-8 byte-order mark and CRLF
  line endings; the scripts strip both when reading on the WSL side.
