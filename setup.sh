#!/bin/bash
# ==============================================================================
# CS RECON — Tool & Dependency Installer Script
# Works on Kali Linux, Debian, Ubuntu, and WSL
# ==============================================================================

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${CYAN}======================================================================${NC}"
echo -e "${GREEN}          CS RECON — Installation & Setup Assistant                   ${NC}"
echo -e "${CYAN}======================================================================${NC}\n"

if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}[!] Warning: Running without sudo. Some apt installations may require root permissions.${NC}"
fi

echo -e "${GREEN}[+] Updating package repository index...${NC}"
sudo apt update -y

echo -e "${GREEN}[+] Installing core security binaries and tools via apt...${NC}"
TOOLS=(
    "python3"
    "python3-pip"
    "nmap"
    "whois"
    "dnsutils"
    "whatweb"
    "nikto"
    "gobuster"
    "ffuf"
    "wafw00f"
    "subfinder"
    "amass"
    "httpx-toolkit"
    "nuclei"
    "curl"
    "git"
    "jq"
)

for tool in "${TOOLS[@]}"; do
    echo -e "${CYAN}[*] Installing ${tool}...${NC}"
    sudo apt install -y "$tool"
done

echo -e "\n${GREEN}[+] Making cs_recon.py executable...${NC}"
chmod +x cs_recon.py

echo -e "\n${GREEN}[+] Verifying CS Recon Installation...${NC}"
python3 cs_recon.py --check-deps

echo -e "\n${CYAN}======================================================================${NC}"
echo -e "${GREEN}[+] CS RECON Installation Complete!${NC}"
echo -e "${GREEN}[+] Usage: python3 cs_recon.py  or  ./cs_recon.py${NC}"
echo -e "${CYAN}======================================================================${NC}"
