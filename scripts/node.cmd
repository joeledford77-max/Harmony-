@echo off
rem node.cmd - runs node.ps1 (start, stop, restart, status, log) without changing PowerShell's policy.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0node.ps1" %*
