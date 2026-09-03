@echo off
cd /d "%~dp0"
echo [1/3] Clearing previous logs...
type nul > Models\alerts.json
type nul > Models\live.log
echo [2/3] Starting Sniffer and Dashboard...
start "Sniffer" cmd /k "python sniffer.py"
start "Dashboard" cmd /k "python app.py"
timeout /t 4 /nobreak >nul
echo [3/3] Opening Browser and Kali Commands...
start "" http://127.0.0.1:5000
timeout /t 2 /nobreak >nul
start "Kali Attack Commands" cmd /k "type kali_commands.txt"
echo.
echo ========================================
echo NIDS Monitoring Started Successfully!
echo ========================================
echo.
echo The sniffer is now monitoring network traffic.
echo Open your Kali VM in a separate window and run the attacks.
echo The commands are displayed in the "Kali Attack Commands" window.
echo.
echo Make sure your Kali VM is set to BRIDGED mode!
echo ========================================
pause