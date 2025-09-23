#!/usr/bin/env python3
"""
Setup script for VulnScan-Pro
Automated Vulnerability Assessment Tool
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")


def check_nmap_installation():
    """Check if Nmap is installed"""
    print("\n🔍 Checking Nmap installation...")
    
    if shutil.which('nmap') is None:
        print("❌ Nmap is not installed or not in PATH")
        print("\nPlease install Nmap:")
        
        system = platform.system().lower()
        if system == 'darwin':
            print("  macOS: brew install nmap")
        elif system == 'linux':
            print("  Ubuntu/Debian: sudo apt-get install nmap")
            print("  CentOS/RHEL: sudo yum install nmap")
        elif system == 'windows':
            print("  Windows: Download from https://nmap.org/download.html")
        
        sys.exit(1)
    else:
        # Get Nmap version
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True)
            version_line = result.stdout.split('\n')[0]
            print(f"✅ {version_line}")
        except Exception:
            print("✅ Nmap is installed")


def install_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        sys.exit(1)


def setup_database():
    """Initialize the database"""
    print("\n🗄️  Setting up database...")
    
    try:
        from database import init_database
        init_database()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Error setting up database: {e}")
        sys.exit(1)


def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        'reports',
        'logs',
        'config',
        'templates',
        'scans',
        'exports'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created: {directory}")


def setup_configuration():
    """Setup default configuration"""
    print("\n⚙️  Setting up configuration...")
    
    config_content = '''# VulnScan-Pro Configuration
# Automated Vulnerability Assessment Tool

# Scanning configuration
DEFAULT_PORTS = '1-1000'
SCAN_TIMEOUT = 300  # seconds
MAX_CONCURRENT_SCANS = 10
NMAP_PATH = 'nmap'  # Path to nmap binary

# CVE API settings
CVE_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
CVE_API_KEY = None  # Optional for rate limiting
CVE_CACHE_DURATION = 3600  # seconds
CVE_API_TIMEOUT = 30  # seconds

# Reporting settings
REPORT_OUTPUT_DIR = 'reports'
REPORT_TEMPLATE_DIR = 'templates'
MAX_REPORT_SIZE_MB = 100

# Database settings
DATABASE_PATH = 'vulnscan.db'
RESULT_RETENTION_DAYS = 90

# API settings
API_HOST = '0.0.0.0'
API_PORT = 5000
API_DEBUG = False
API_THREADED = True

# Logging settings
LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FILE = 'logs/vulnscan.log'

# Performance settings
MAX_THREADS = 50
CONNECTION_TIMEOUT = 10
READ_TIMEOUT = 30

# Scan profiles
SCAN_PROFILES = {
    'quick': {
        'ports': '1-1000',
        'timing': 'T4',
        'service_detection': False
    },
    'comprehensive': {
        'ports': '1-65535',
        'timing': 'T3',
        'service_detection': True,
        'os_detection': True,
        'script_scan': True
    },
    'stealth': {
        'ports': '1-1000',
        'timing': 'T1',
        'service_detection': True,
        'stealth_scan': True
    }
}
'''
    
    config_path = Path('config/config.py')
    if not config_path.exists():
        with open(config_path, 'w') as f:
            f.write(config_content)
        print("✅ Default configuration created")
    else:
        print("✅ Configuration file already exists")


def create_startup_scripts():
    """Create startup scripts for different platforms"""
    print("\n📜 Creating startup scripts...")
    
    # Linux/macOS startup script
    bash_script = '''#!/bin/bash
# VulnScan-Pro Startup Script

echo "Starting VulnScan-Pro..."

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

# Start the API server
echo "Starting API server on port 5000..."
python api.py
'''
    
    with open('start.sh', 'w') as f:
        f.write(bash_script)
    os.chmod('start.sh', 0o755)
    print("✅ Created start.sh")
    
    # Windows startup script
    batch_script = '''@echo off
REM VulnScan-Pro Startup Script

echo Starting VulnScan-Pro...

REM Check if virtual environment exists
if exist "venv" (
    echo Activating virtual environment...
    call venv\\Scripts\\activate.bat
)

REM Start the API server
echo Starting API server on port 5000...
python api.py

pause
'''
    
    with open('start.bat', 'w') as f:
        f.write(batch_script)
    print("✅ Created start.bat")


def run_tests():
    """Run basic tests to verify installation"""
    print("\n🧪 Running installation tests...")
    
    try:
        # Test imports
        import nmap
        import requests
        import flask
        import sqlite3
        print("✅ Core modules import successfully")
        
        # Test Nmap Python integration
        nm = nmap.PortScanner()
        print("✅ Nmap Python integration working")
        
        # Test database connection
        import sqlite3
        conn = sqlite3.connect('vulnscan.db')
        conn.close()
        print("✅ Database connection test passed")
        
        # Test CVE API connectivity
        import requests
        try:
            response = requests.get('https://services.nvd.nist.gov/rest/json/cves/1.0', 
                                  timeout=5)
            if response.status_code == 200:
                print("✅ CVE API connectivity test passed")
            else:
                print("⚠️  CVE API returned non-200 status")
        except requests.RequestException:
            print("⚠️  CVE API connectivity test failed (network issue)")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
    
    return True


def print_completion_message():
    """Print setup completion message"""
    print("\n" + "=" * 60)
    print("🎉 VulnScan-Pro Setup Complete!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Review configuration in config/config.py")
    print("2. Start the API server:")
    print("   ./start.sh (Linux/macOS) or start.bat (Windows)")
    print("   OR: python api.py")
    print()
    print("3. Run your first scan:")
    print("   python vulnscan.py --target 192.168.1.100")
    print()
    print("4. Access the API:")
    print("   http://localhost:5000/api/health")
    print()
    print("For help and documentation:")
    print("- README.md")
    print("- API documentation at /api/health")
    print("- logs/ directory for troubleshooting")
    print("=" * 60)


def main():
    """Main setup function"""
    print("🚀 VulnScan-Pro Setup")
    print("Automated Vulnerability Assessment Tool")
    print("=" * 50)
    
    try:
        check_python_version()
        check_nmap_installation()
        install_dependencies()
        create_directories()
        setup_database()
        setup_configuration()
        create_startup_scripts()
        
        if run_tests():
            print_completion_message()
        else:
            print("❌ Setup completed with errors. Check logs for details.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n❌ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()