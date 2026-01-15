#!/bin/bash

# Docker Health Check Script
# This script verifies that the container is working correctly

echo "🔍 Docker Container Health Check"
echo "================================"

# Check if Python is available
if command -v python3 &> /dev/null; then
    echo "✅ Python 3 available: $(python3 --version)"
else
    echo "❌ Python 3 not found"
    exit 1
fi

# Check if required packages are installed
echo "📦 Checking required packages..."

python3 -c "import flask; print('✅ Flask available')" 2>/dev/null || echo "❌ Flask not available"
python3 -c "import yaml; print('✅ PyYAML available')" 2>/dev/null || echo "❌ PyYAML not available"
python3 -c "import requests; print('✅ Requests available')" 2>/dev/null || echo "❌ Requests not available"
python3 -c "import dns.resolver; print('✅ DNSPython available')" 2>/dev/null || echo "❌ DNSPython not available"

# Check if directories exist
echo "📁 Checking directories..."
[ -d "uploads" ] && echo "✅ Uploads directory exists" || echo "❌ Uploads directory missing"
[ -d "output" ] && echo "✅ Output directory exists" || echo "❌ Output directory missing"

# Check if config files exist
echo "⚙️  Checking configuration..."
[ -f "config.yaml" ] && echo "✅ Config file exists" || echo "❌ Config file missing"
[ -f "OwnedAssets.txt" ] && echo "✅ OwnedAssets file exists" || echo "⚠️  OwnedAssets file missing (will use default)"

# Check if web GUI can start (basic import test)
echo "🌐 Testing web GUI imports..."
python3 -c "
try:
    import web_gui
    print('✅ Web GUI module imports successfully')
except ImportError as e:
    print(f'❌ Web GUI import failed: {e}')
except Exception as e:
    print(f'⚠️  Web GUI import warning: {e}')
"

echo ""
echo "🎉 Health check complete!"
echo "💡 If all checks pass, the container is ready to use."