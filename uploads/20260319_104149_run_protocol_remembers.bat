@echo off
:: THE PROTOCOL REMEMBERS — PDR Test Sample
:: Opens a new visible terminal window with the cinematic dialogue

set SCRIPT_DIR=%~dp0

:: Find Python
set PYTHON=
for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PYTHON set PYTHON=%%i
)

if not defined PYTHON (
    if exist "%SCRIPT_DIR%..\..\venv\Scripts\python.exe" (
        set PYTHON=%SCRIPT_DIR%..\..\venv\Scripts\python.exe
    )
)

if not defined PYTHON (
    start "Protocol Decoder Ring" cmd /k "echo Python not found & pause"
    exit /b 1
)

:: Launch a NEW visible window — /k keeps it open after script ends
start "THE PROTOCOL REMEMBERS" cmd /k ""%PYTHON%" "%SCRIPT_DIR%the_protocol_remembers.py""