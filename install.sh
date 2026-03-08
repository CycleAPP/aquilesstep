#!/bin/bash

# Aquiles Setup Script

set -e

echo "[*] Updating system packages..."
sudo apt-get update

echo "[*] Installing core system dependencies and hacking tools..."
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    dnsutils \
    whois \
    dnsrecon \
    gobuster \
    ffuf \
    dirb \
    whatweb \
    wafw00f \
    nikto \
    sslscan \
    exploitdb

echo "[*] Installing Go-based tools (ProjectDiscovery & others)..."
# subfinder, nuclei, httpx (ProjectDiscovery versions)
sudo apt-get install -y subfinder nuclei httpx-toolkit || echo "[!] Some Go tools might need manual installation depending on your Kali/Parrot version. You can use 'go install' for them."

echo "[*] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install rich click pyyaml requests beautifulsoup4 openai urllib3

echo ""
echo "[+] Installation complete!"
echo ""
echo "To start Aquiles, just run:"
echo "------------------------------------------------"
echo "  source venv/bin/activate"
echo "  ./aquiles.sh start"
echo "------------------------------------------------"
echo "Don't forget to set your AI API keys if you want smart planning:"
echo "  export DEEPSEEK_API_KEY='your_key' "
echo "  # or "
echo "  export OPENAI_API_KEY='your_key' "
