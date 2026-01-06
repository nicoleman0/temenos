#!/bin/bash
# Setup script for Temenos

echo "================================="
echo "Temenos - Setup"
echo "================================="
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✓ Python version: $PYTHON_VERSION"

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip -q

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt -q

if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "❌ Error installing dependencies"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo ""
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "✓ Created .env file"
    echo ""
    echo "⚠️  IMPORTANT: Please edit .env and add your API keys:"
    echo "   - DNSDUMPSTER_API_KEY (required)"
    echo "   - VIRUSTOTAL_API_KEY (optional)"
    echo ""
    echo "Get your API keys from:"
    echo "   - DNSDumpster: https://dnsdumpster.com/membership/"
    echo "   - VirusTotal: https://www.virustotal.com/gui/my-apikey"
else
    echo "✓ .env file exists"
fi

# Make scripts executable
chmod +x temenos.py
chmod +x example_usage.py

echo ""
echo "================================="
echo "Setup Complete! 🎉"
echo "================================="
echo ""
echo "Next steps:"
echo "1. Edit .env file with your API keys"
echo "2. Run: python temenos.py check-config"
echo "3. Try a scan: python temenos.py scan example.com"
echo ""
echo "See QUICKSTART.md for more information"
echo ""
