@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================================
echo  StormVR Server — captura o PC e envia para o iPhone
echo  Feche o SteamVR antes de rodar.
echo  Porta WebSocket: 5560
echo  Porta UDP runtime: 5556 (127.0.0.1 — só local)
echo ============================================================
echo.
echo IP deste PC (use este no app do iPhone):
for /f "tokens=2 delims=:" %%A in ('ipconfig ^| findstr /C:"IPv4"') do (
    set ip=%%A
    setlocal enabledelayedexpansion
    set ip=!ip: =!
    if not "!ip!"=="127.0.0.1" echo   !ip!
    endlocal
)
echo.
stormvr_server.exe
pause
