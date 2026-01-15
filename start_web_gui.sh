#!/bin/bash

# Enhanced Asset Classification Tool - Web GUI Launcher
# This script starts the web-based GUI for easy asset classification

echo "🚀 Enhanced Asset Classification Tool - Web GUI"
echo "=============================================="
echo ""

# Check if virtual environment exists
if [ ! -d "myenv" ]; then
    echo "❌ Virtual environment not found. Please run setup first:"
    echo "   python -m venv myenv"
    echo "   source myenv/bin/activate  # On Windows: myenv\\Scripts\\activate"
    echo "   pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source myenv/bin/activate 2>/dev/null || source myenv/Scripts/activate 2>/dev/null

# Check if Flask is installed
if ! python -c "import flask" 2>/dev/null; then
    echo "❌ Flask not installed. Installing requirements..."
    pip install -r requirements.txt
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p uploads output

# Start the web GUI
echo "🌐 Starting web GUI..."
echo "📊 Access at: http://localhost:5001"
echo "💡 Upload CSV files and configure scans through the web interface"
echo "🔄 Press Ctrl+C to stop"
echo ""

python web_gui.py