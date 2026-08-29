@echo off
title Wireless Security Monitor

echo ============================================
echo   Wireless Security Monitor - Launcher
echo ============================================
echo.

:: Start the FastAPI backend in a new window
echo [1] Starting FastAPI backend...
start "Backend - FastAPI" cmd /k "cd /d L:\2026-summer\IBM\backend && python main.py"

:: Wait for backend to boot
echo     Waiting 3 seconds for backend to start...
timeout /t 3 /nobreak >nul

:: Start the UART orchestrator in a new window
echo [2] Starting UART orchestrator...
start "Orchestrator - UART" cmd /k "cd /d L:\2026-summer\IBM\host_scripts && python uart_orchestrator.py"

echo.
echo ============================================
echo   Both processes launched in separate windows.
echo   Dashboard: http://localhost:8000
echo ============================================
echo.
echo Press any key to stop both...
pause >nul

:: Kill both when user presses a key
taskkill /fi "WINDOWTITLE eq Backend - FastAPI*" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq Orchestrator - UART*" /f >nul 2>&1
echo Stopped.
