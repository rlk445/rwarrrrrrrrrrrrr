@echo off
chcp 65001 >nul
net session >nul 2>&1
if errorlevel 1 ( echo Execute como administrador. & pause & exit /b 1 )
netsh advfirewall firewall delete rule name="StormVR Server 5560" >nul 2>&1
netsh advfirewall firewall add rule name="StormVR Server 5560" dir=in action=allow protocol=TCP localport=5560 profile=private,domain
echo Porta 5560 (TCP) liberada para redes Privadas/Dominio.
echo Se a rede Wi-Fi aparecer como "Publica", mude para "Privada" nas Configuracoes do Windows.
pause
