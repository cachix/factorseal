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
| `check.sh test-desktop` | WSL | Creates the throwaway test vault if needed, starts a Desktop on it, and unlocks it through `drive.ps1`. |
| `check.sh popup --steal` | WSL | As soon as the popup takes the foreground, the observer hands it to a window of its own that stands in for another app. The popup must then flash. Needs the popup to take the foreground first, which happens when Desktop was just used, for example right after `test-desktop`. |
| `check.sh popup --test-vault --seal --then grant\|deny` | WSL | Seals the vault while the request waits and checks that the popup stays open. `grant` unlocks from the popup and grants; `deny` denies while sealed, unlocks from the main window, and checks that the request stays denied. |
| `check.sh popup --test-vault [--then grant\|deny]` | WSL | `popup` against the test vault and its Desktop; `--then` drives the popup afterwards, and `grant` also runs the grant check. `grant --test-vault` works the same way. |
| `observe.ps1` | Windows | Used by `check.sh`; hooks taskbar-flash notifications and captures the screenshots. |
| `uia-dump.ps1 [-Out FILE] [-DesktopPid P]` | Windows | Lists what UI Automation sees in Desktop's windows: control types, names, AutomationIds, and whether a value is exposed (never the value itself). |
| `test-vault.ps1 -Cli EXE` | Windows | Used by `check.sh`; creates a password-only vault in `%LOCALAPPDATA%\FactorSeal-check` with a random password in an owner-only file. Leaves an existing one alone. |
| `drive.ps1 -Action find\|unlock\|unlock-popup\|grant\|deny -DesktopPid P [-PasswordFile F]` | Windows | Used by `check.sh`; reports whether the popup is open, unlocks Desktop's main window or a popup kept open by a seal, or grants or denies the popup. Finds controls through UI Automation, then clicks and types with real input, because the popup accepts approval only after a click inside it. |
| `screenshot.ps1 -DesktopPid P -Out FILE` | Windows | Saves a PNG of the approval popup, raised and kept topmost for the capture. The popup's text is not exposed to UI Automation, so this is how a check reads what it says. |
| `provider-probe.ps1 -Cli EXE [-Root DIR] [-Method get\|set] [-Key K] [-Directory D]` | Windows | Talks to `factorseal provider` directly as SecretSpec would (initialize, then one get or set) and prints the replies and the provider's standard error. Makes requests the `secretspec` CLI cannot, such as a write to an undeclared key. A get reply contains the value, so use `-Root` with the test vault. |
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

## Automated flow on a test vault

Nobody has to type a password or click the popup when the checks run against
a throwaway vault. It runs in its own Desktop next to the user's, which keeps
its own vault and tray icon.

1. `./scripts/windows-desktop-check/check.sh test-desktop`
2. `./scripts/windows-desktop-check/check.sh popup --test-vault --then grant`
   (or `--then deny`)

The driver moves the pointer and types, so it takes over the Windows
desktop for a few seconds. It never clicks or types unless Desktop's window
is in front and under the pointer. While it acts, it keeps that window
topmost, because an always-on-top app (such as a pinned terminal) otherwise
covers it, and it releases it afterwards.

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

- **The vault seals itself after a few idle minutes.** A pending request
  survives it: the popup stays open with "Unlock to continue", and the request
  is still pending after the unlock. A new request cannot reach a sealed vault,
  so `check.sh` checks before sending (and again after `--delay`); unlock and
  rerun when it says the vault is sealed.
- **Desktop locks its executables.** Quit it from the tray before
  `build-windows.sh release`.
- **Windows blocks UI Automation from a normal process into an elevated
  one.** Desktop no longer needs elevation, but if it is started elevated,
  `uia-dump.ps1` and `drive.ps1` from WSL see only window frames.
- **A popup opened while the main window is active is owned by it.** GPUI
  makes such a dialog modal: the main window is disabled, the popup stays
  above it, and the popup has no taskbar button, so the main window's button
  flashes for it. UI Automation then lists the popup under the main window,
  so find it by its window title (as `observe.ps1` and `drive.ps1` do).
  `observe.ps1` counts the popup as in front when its owner is.
- **An always-on-top window covers the taskbar too**, so `taskbar.png` then
  shows that window; rely on the flash count instead.
- **The CLI needs `secretspec-provider`** for native SecretSpec on Windows.
  Packaging leaves it out until the SecretSpec IPC crate is published;
  `build-windows.sh` adds it (see `docs/development.md`).
- **Desktop needs its helpers beside the CLI.** Every request is parsed by
  `factorseal-parser.exe`; without it, unlocking can hang.
- Windows PowerShell 5.1 writes files with a UTF-8 byte-order mark and CRLF
  line endings; the scripts strip both when reading on the WSL side.
