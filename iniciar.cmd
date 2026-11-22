@echo off
setlocal
set "PYTHON_PROYECTO=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON_PROYECTO%" set "PYTHON_PROYECTO=python"
"%PYTHON_PROYECTO%" "%~dp0main.py" %*
set "CODIGO=%ERRORLEVEL%"
if not "%CODIGO%"=="0" if "%~1"=="" pause
exit /b %CODIGO%
