@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed. Download the LTS version from https://nodejs.org and run this again.
  pause
  exit /b 1
)
if not exist "node_modules\cyberchef" (
  echo First run: installing CyberChef and dependencies...
  call npm run setup
  if errorlevel 1 ( echo Setup failed. & pause & exit /b 1 )
)
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:8471"
node server.mjs
pause
