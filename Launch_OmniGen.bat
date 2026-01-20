@echo off
setlocal
Title Omni-Gen Launcher & Health Check
color 0A

:: --- Configuration ---
:: Ensure this matches the name of your python file
set "APP_NAME=OmniGen.py"

echo =====================================================
echo      OMNI-GEN STARTUP PROTOCOL
echo =====================================================
echo.

:: 1. Check if Python is reachable in the PATH
echo [1/3] Checking for Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Python is not detected on this system.
    echo.
    echo DIAGNOSIS:
    echo 1. Python might not be installed.
    echo 2. Python might be installed but not added to your System PATH.
    echo.
    echo ACTION:
    echo Please install Python from python.org and ensure "Add to PATH" is checked.
    pause
    exit /b
)
echo    [OK] Python found.

:: 2. Check for Tkinter (Critical GUI dependency)
echo [2/3] Verifying GUI framework (Tkinter)...
python -c "import tkinter" >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Tkinter library is missing.
    echo.
    echo DIAGNOSIS:
    echo The standard Python installation usually includes this.
    echo It may have been deselected during installation.
    echo.
    echo ACTION:
    echo Re-run the Python installer and select "tcl/tk and IDLE".
    pause
    exit /b
)
echo    [OK] GUI framework active.

:: 3. Check for external requirements (Future-Proofing)
:: If you add 'numpy' or other libs later, just create a requirements.txt file.
echo [3/3] Checking for dependency file (requirements.txt)...
if exist requirements.txt (
    echo    [INFO] File found. Updating dependencies...
    pip install -r requirements.txt >nul
    echo    [OK] Dependencies are up to date.
) else (
    echo    [INFO] No external dependencies required. Skipping.
)

:: 4. Launch Application
echo.
echo [START] Launching %APP_NAME%...
echo -----------------------------------------------------

:: Check if the python file actually exists before running
if not exist "%APP_NAME%" (
    color 0C
    echo [ERROR] Could not find "%APP_NAME%"!
    echo Please make sure the Python script is in this folder and named correctly.
    pause
    exit /b
)

:: Run the app
python "%APP_NAME%"

:: 5. Exit Handlers
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [CRITICAL] Application crashed or closed with an error.
    pause
) else (
    echo.
    echo [STOP] Application closed successfully.
)

endlocal