@echo off
title Chrome SOCKS5 Auto
netstat -an | findstr "127.0.0.1:1080.*LISTENING" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [PROXY] Launching Chrome via socks5://127.0.0.1:1080
    start "" "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --proxy-server="socks5://127.0.0.1:1080" %*
) else (
    echo [DIRECT] Proxy not running, launching Chrome directly
    start "" "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" %*
)
