@echo off
cd /d "%~dp0"
echo [1/4] Clearing previous logs...
type nul > Models\alerts.json
type nul > Models\live.log
echo [2/4] Starting Sniffer and Dashboard...
start "Sniffer" cmd /k "python sniffer.py"
start "Dashboard" cmd /k "python app.py"
timeout /t 4 /nobreak >nul
echo [3/4] Opening Browser...
start "" http://127.0.0.1:5000
timeout /t 3 /nobreak >nul
echo [4/4] Launching Attacks...
start "Attacks" cmd /k "python attacks.py"