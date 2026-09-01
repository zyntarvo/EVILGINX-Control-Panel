@echo off
cd /d "%~dp0"
python -m pip install -q pyinstaller paramiko pillow
python -m PyInstaller --noconfirm --clean --onefile --noconsole --name "EVILGINX-INSTALLER-v3.5.3" --icon icon.ico --add-data "payload;payload" --add-data "icon.png;." --add-data "icon.ico;." --hidden-import paramiko --collect-submodules paramiko evilginx_setup.py
if errorlevel 1 (
  echo BUILD FAILED
  pause
  exit /b 1
)
copy /Y "dist\EVILGINX-INSTALLER-v3.5.3.exe" "."
echo.
echo Built: %cd%\EVILGINX-INSTALLER-v3.5.3.exe
pause
