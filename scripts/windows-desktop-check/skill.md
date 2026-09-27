# Windows Desktop checks from WSL2

Read `scripts/windows-desktop-check/README.md` first; it describes every
script, the flow, and the pitfalls. This file is the order of work.

## Build

- `./scripts/windows-desktop-check/build-windows.sh check` for clippy and
  Desktop's tests natively (safe while Desktop runs).
- `./scripts/windows-desktop-check/build-windows.sh --broker` for release
  binaries. If it refuses because Desktop is running, ask the user to quit
  Desktop from its tray icon, then rerun.
- Never try to cross-compile Desktop from WSL; its renderer needs Windows.

## Check the approval popup

The user must do the steps only a person can. Give them the exact commands,
say which shell they run in, and wait for them.

Without the user, use the test vault: `check.sh test-desktop`, then
`check.sh popup --test-vault --then grant` (or `--then deny`). For
SecretSpec writes and their one-time grants, `check.sh write-once` (popup)
and `check.sh write-once --via cli` (`permissions approve` in a console).
The driver takes over the pointer and keyboard for a few seconds, so say so
first. Against the
user's own vault:

1. Ask the user to start Desktop and unlock the vault, from a normal
   PowerShell: `cd <windows copy>; .\target\release\factorseal-desktop.exe`
2. Run `./scripts/windows-desktop-check/check.sh popup` (or `--delay 10` and
   ask them to bring another app to the front, for the "behind" case). Tell
   them to leave the popup alone until the result prints.
3. Read `popup.png` and `taskbar.png` from the printed paths yourself instead
   of asking for screenshots.
4. Ask the user to approve (or deny). After approving, run
   `check.sh grant --key <key from step 2>`.

If `check.sh` says the vault is sealed, ask the user to unlock and rerun
promptly; it seals itself after a few idle minutes.

## Check the browser extension

Run `./scripts/windows-desktop-check/browser-check.sh` (inside the devenv
shell) instead of asking the user to click through Edge. It uses its own Edge
profile and the test vault, and drives both the extension and Desktop's
browser prompt; say first that it takes over the pointer for a while.
`--only=STEP` reruns single steps. Ask the user only for what it cannot
judge, such as how the prompt looks.

## Inspect

- UI Automation: `uia-dump.ps1 -Out <file> [-DesktopPid <pid>]` lists the
  popup's text and which lifetime is selected, so read what the popup says
  there; `screenshot.ps1` shows how it looks. From WSL it sees only window
  frames if Desktop was started elevated.
- Hangs or crashes: start `proc-watch.ps1 -Out <file> -Seconds 600` from WSL
  in the background before the user launches Desktop, and ask them to set
  `$env:FACTORSEAL_TIMINGS = '1'` and redirect stderr to a file.

## Rules

- A change to Desktop's UI is committed only after it was seen working in a
  native Windows build.
- Report what the scripts measured (pass/fail lines, screenshots, grant
  lifetime); do not infer popup behavior from code alone.
