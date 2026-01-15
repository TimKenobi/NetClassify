@echo off
REM Enhanced Asset Classification Tool - Web GUI Launcher (Windows)
REM This script starts the web-based GUI for easy asset classification

echo 🚀 Enhanced Asset Classification Tool - Web GUI
echo ==============================================
echo.

REM Check if virtual environment exists
if not exist "myenv" (
    echo ❌ Virtual environment not found. Please run setup first:
    echo    python -m venv myenv
    echo    myenv\Scripts\activate
    echo    pip install -r requirements.txt
    pause
    exit /b 1
)

REM Activate virtual environment
echo 🔧 Activating virtual environment...
call myenv\Scripts\activate

REM Check if Flask is installed
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo ❌ Flask not installed. Installing requirements...
    pip install -r requirements.txt
)

REM Create necessary directories
echo 📁 Creating directories...
if not exist "uploads" mkdir uploads
if not exist "output" mkdir output

REM Start the web GUI
echo 🌐 Starting web GUI...
echo 📊 Access at: http://localhost:5001
echo 💡 Upload CSV files and configure scans through the web interface
echo 🔄 Press Ctrl+C to stop
echo.

python web_gui.py