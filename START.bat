@echo off
cd /d "%~dp0"
python evilginx_setup.py
if errorlevel 1 pause
