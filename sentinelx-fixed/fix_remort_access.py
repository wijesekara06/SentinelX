#!/usr/bin/env python3
"""
SentinelX Remote Access Configuration Tool
Automatically fixes frontend and CORS configuration for network access
"""

import os
import sys
import re
import shutil
from pathlib import Path


def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")


def print_success(text):
    print(f"✓ {text}")


def print_error(text):
    print(f"✗ {text}")


def print_info(text):
    print(f"ℹ {text}")


def backup_file(filepath):
    """Create a backup of the file"""
    backup_path = f"{filepath}.backup"
    if not os.path.exists(backup_path):
        shutil.copy(filepath, backup_path)
        print_success(f"Backed up: {filepath} → {backup_path}")
        return backup_path
    else:
        print_info(f"Backup already exists: {backup_path}")
        return backup_path


def fix_frontend_urls(frontend_path):
    """Fix hardcoded localhost IPs in frontend"""
    print_header("Fixing Frontend URLs")
    
    if not os.path.exists(frontend_path):
        print_error(f"File not found: {frontend_path}")
        return False
    
    backup_file(frontend_path)
    
    with open(frontend_path, 'r') as f:
        content = f.read()
    
    # Find the lines with HP and BE definitions
    original_content = content
    
    # Replace the old hardcoded URLs with dynamic detection
    old_pattern = r"const HP\s*=\s*'http://127\.0\.0\.1:5001';"
    new_code = """// Auto-detect server address from browser location
const SERVER_HOST = window.location.hostname;
const HP  = `http://${SERVER_HOST}:5001`;"""
    
    if re.search(old_pattern, content):
        content = re.sub(old_pattern, new_code, content)
        print_success("Updated HP (Honeypot) URL to use window.location.hostname")
    
    old_pattern = r"const BE\s*=\s*'http://127\.0\.0\.1:5000';"
    new_code = """const BE  = `http://${SERVER_HOST}:5000`;"""
    
    if re.search(old_pattern, content):
        content = re.sub(old_pattern, new_code, content)
        print_success("Updated BE (Backend) URL to use window.location.hostname")
    
    if content != original_content:
        with open(frontend_path, 'w') as f:
            f.write(content)
        print_success(f"Frontend configuration updated: {frontend_path}")
        return True
    else:
        print_info("Frontend URLs already configured for remote access")
        return True


def fix_backend_cors(backend_path):
    """Fix CORS configuration in backend"""
    print_header("Fixing Backend CORS")
    
    if not os.path.exists(backend_path):
        print_error(f"File not found: {backend_path}")
        return False
    
    backup_file(backend_path)
    
    with open(backend_path, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Find and replace CORS configuration
    old_cors = r'CORS\(app,\s*resources=\{r"/api/\*":\s*\{"origins":\s*"http://localhost:5000"\}\}\)'
    
    new_cors = '''CORS(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })'''
    
    if re.search(old_cors, content):
        content = re.sub(old_cors, new_cors, content)
        print_success("Updated CORS configuration to allow all origins")
    else:
        # Try a simpler pattern match
        if '"origins": "http://localhost:5000"' in content:
            content = content.replace(
                '"origins": "http://localhost:5000"',
                '"origins": "*"'
            )
            print_success("Updated CORS origins to allow all origins")
        else:
            print_info("CORS configuration not found or already updated")
    
    if content != original_content:
        with open(backend_path, 'w') as f:
            f.write(content)
        print_success(f"Backend CORS updated: {backend_path}")
        return True
    else:
        print_info("Backend CORS already allows remote access")
        return True


def fix_honeypot_cors(honeypot_path):
    """Fix CORS configuration in honeypot"""
    print_header("Fixing Honeypot CORS")
    
    if not os.path.exists(honeypot_path):
        print_error(f"File not found: {honeypot_path}")
        return False
    
    backup_file(honeypot_path)
    
    with open(honeypot_path, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Replace CORS configuration
    if '"origins": "http://localhost:5000"' in content:
        content = content.replace(
            '"origins": "http://localhost:5000"',
            '"origins": "*"'
        )
        print_success("Updated CORS origins to allow all origins")
    else:
        print_info("CORS configuration not found or already updated")
    
    if content != original_content:
        with open(honeypot_path, 'w') as f:
            f.write(content)
        print_success(f"Honeypot CORS updated: {honeypot_path}")
        return True
    else:
        print_info("Honeypot CORS already allows remote access")
        return True


def verify_changes(frontend_path, backend_path, honeypot_path):
    """Verify that changes were applied correctly"""
    print_header("Verifying Changes")
    
    all_good = True
    
    # Check frontend
    if os.path.exists(frontend_path):
        with open(frontend_path, 'r') as f:
            content = f.read()
        
        if 'window.location.hostname' in content:
            print_success("✓ Frontend: Uses window.location.hostname")
        else:
            print_error("✗ Frontend: Still has hardcoded localhost")
            all_good = False
    
    # Check backend
    if os.path.exists(backend_path):
        with open(backend_path, 'r') as f:
            content = f.read()
        
        if '"origins": "*"' in content or '"origins": "*"' in content:
            print_success("✓ Backend: CORS allows all origins")
        else:
            print_error("✗ Backend: CORS still restricted")
            all_good = False
    
    # Check honeypot
    if os.path.exists(honeypot_path):
        with open(honeypot_path, 'r') as f:
            content = f.read()
        
        if '"origins": "*"' in content or '"origins": "*"' in content:
            print_success("✓ Honeypot: CORS allows all origins")
        else:
            print_error("✗ Honeypot: CORS still restricted")
            all_good = False
    
    return all_good


def get_server_ip():
    """Attempt to get the server's IP address"""
    print_header("Server Information")
    
    import socket
    
    hostname = socket.gethostname()
    print_info(f"Hostname: {hostname}")
    
    try:
        ip_address = socket.gethostbyname(hostname)
        print_info(f"Local IP: {ip_address}")
    except Exception as e:
        print_info(f"Could not determine IP: {e}")
    
    print_info("\nTo access from another machine, use:")
    print_info("  http://<SERVER_IP>:5000/dashboard")
    print_info("  http://<SERVER_IP>:5001  (honeypot)")


def main():
    """Main execution"""
    
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " "*58 + "║")
    print("║" + "  SentinelX Remote Access Configuration Tool".center(58) + "║")
    print("║" + "  Version 1.0.0".center(58) + "║")
    print("║" + " "*58 + "║")
    print("╚" + "="*58 + "╝")
    
    # Determine paths
    script_dir = Path(__file__).parent.absolute()
    
    # Try different possible locations
    possible_locations = [
        ("./sentinelx-fixed", "./sentinelx-fixed/frontend/dashboard.html", 
         "./sentinelx-fixed/backend/app.py", "./sentinelx-fixed/honeypot/app.py"),
        ("../sentinelx-fixed", "../sentinelx-fixed/frontend/dashboard.html",
         "../sentinelx-fixed/backend/app.py", "../sentinelx-fixed/honeypot/app.py"),
        (".", "./frontend/dashboard.html", "./backend/app.py", "./honeypot/app.py"),
    ]
    
    frontend_path = None
    backend_path = None
    honeypot_path = None
    
    for base_dir, fe, be, ho in possible_locations:
        if os.path.exists(fe):
            frontend_path = fe
            backend_path = be
            honeypot_path = ho
            print_info(f"Found SentinelX in: {os.path.abspath(base_dir)}")
            break
    
    if not frontend_path:
        print_error("Could not find SentinelX directory!")
        print_info("Please run this script from the SentinelX root directory")
        print_info("or pass the directory as an argument:")
        print_info("  python fix_remote_access.py /path/to/sentinelx")
        sys.exit(1)
    
    # Apply fixes
    print_info(f"Frontend:  {os.path.abspath(frontend_path)}")
    print_info(f"Backend:   {os.path.abspath(backend_path)}")
    print_info(f"Honeypot:  {os.path.abspath(honeypot_path)}")
    
    fe_ok = fix_frontend_urls(frontend_path)
    be_ok = fix_backend_cors(backend_path)
    ho_ok = fix_honeypot_cors(honeypot_path)
    
    if verify_changes(frontend_path, backend_path, honeypot_path):
        print_header("Configuration Complete!")
        print_success("All files have been successfully updated!")
        print_info("")
        print_info("Your SentinelX system is now configured for remote access.")
        print_info("")
        print_info("Next steps:")
        print_info("  1. Start the system: python run_all.py")
        print_info("  2. Access from another machine using your server IP")
        print_info("     http://<YOUR_SERVER_IP>:5000/dashboard")
        
        get_server_ip()
        
        print_info("")
        print_info("Backups of original files have been created (.backup)")
        
    else:
        print_error("Some changes may not have been applied correctly!")
        print_info("Please check the files manually")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print_error(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
