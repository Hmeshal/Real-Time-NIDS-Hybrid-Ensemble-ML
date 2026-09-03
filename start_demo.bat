@echo off
cd /d "%~dp0"
echo [1/3] Clearing previous logs...
type nul > Models\alerts.json
type nul > Models\live.log
echo [2/3] Starting Dashboard...
start "Dashboard" cmd /k "python app.py"
timeout /t 4 /nobreak >nul
echo [3/3] Opening Browser and Replaying Attacks...
start "" http://127.0.0.1:5000
timeout /t 3 /nobreak >nul
start "Demo Replay" cmd /k "python demo.py"