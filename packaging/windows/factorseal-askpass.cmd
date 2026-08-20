@echo off
rem Thin wrapper so the agent can invoke the PowerShell askpass helper as a
rem plain executable. Its standard output is the nested factor.
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0factorseal-askpass.ps1" %*
