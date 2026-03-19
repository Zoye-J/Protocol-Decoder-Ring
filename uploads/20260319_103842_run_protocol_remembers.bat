@echo off
:: THE PROTOCOL REMEMBERS — PDR Test Sample
:: Upload this .bat file via the PDR dashboard
:: It will run the Python script and generate detectable network traffic

:: Find python in common locations
set PYTHON=
if exist "%~dp0venv\Scripts\python.exe" set PYTHON=%~dp0venv\Scripts\python.exe
if not defined PYTHON (
    for /f "delims=" %%i in ('where python 2^>nul') do (
        set PYTHON=%%i
        goto :found
    )
)
:found

if not defined PYTHON (
    echo Python not found. Please ensure Python is installed.
    pause
    exit /b 1
)

:: Run the script from its own directory
"%PYTHON%" "%~dp0the_protocol_remembers.py"