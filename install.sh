#!/usr/bin/env bash
# AEGIS Installer — sets up AEGIS on Darknode OS
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}AEGIS Installer${RESET}"
echo ""

# Install to /opt/darknode/aegis
INSTALL_DIR="/opt/darknode/aegis"
DESKTOP_DIR="/usr/share/applications"
BIN_DIR="/usr/local/bin"

echo -e "${CYAN}[1/5] Installing AEGIS to ${INSTALL_DIR}...${RESET}"
sudo mkdir -p "$INSTALL_DIR"
sudo cp -r . "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/aegis.sh"

echo -e "${CYAN}[2/5] Creating command-line shortcut...${RESET}"
sudo tee "$BIN_DIR/aegis" > /dev/null << 'WRAPPER'
#!/usr/bin/env bash
cd /opt/darknode/aegis && exec bash aegis.sh "$@"
WRAPPER
sudo chmod +x "$BIN_DIR/aegis"

echo -e "${CYAN}[3/5] Installing desktop entries...${RESET}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_SRC="$(dirname "$SCRIPT_DIR")/desktop"
if [ -d "$DESKTOP_SRC" ]; then
    for f in "$DESKTOP_SRC"/aegis*.desktop; do
        [ -f "$f" ] && sudo cp "$f" "$DESKTOP_DIR/" 2>/dev/null || true
    done
fi
# Also install the main entry if desktop files are in our directory
for f in ../desktop/aegis*.desktop; do
    [ -f "$f" ] && sudo cp "$f" "$DESKTOP_DIR/" 2>/dev/null || true
done

echo -e "${CYAN}[4/5] Installing Python dependencies...${RESET}"
pip3 install --user --quiet rich pyyaml 2>/dev/null || pip3 install --quiet rich pyyaml 2>/dev/null || {
    echo -e "${YELLOW}[WARN] Some Python packages could not be installed. AEGIS will run in basic mode.${RESET}"
}

echo -e "${CYAN}[5/5] Checking security tools...${RESET}"
FOUND=0
MISSING=""
for tool in nmap nikto gobuster sqlmap hydra john hashcat searchsploit nuclei sslscan dig whois curl tshark; do
    if command -v "$tool" &>/dev/null; then
        FOUND=$((FOUND + 1))
    else
        MISSING="$MISSING $tool"
    fi
done
echo -e "${GREEN}  $FOUND tools found${RESET}"
if [ -n "$MISSING" ]; then
    echo -e "${YELLOW}  Missing (optional):${MISSING}${RESET}"
    echo -e "${YELLOW}  Install with: sudo apt install${MISSING}${RESET}"
fi

echo ""
echo -e "${GREEN}${BOLD}AEGIS installed successfully.${RESET}"
echo ""
echo "  Launch from terminal:   aegis"
echo "  Launch from app menu:   Search 'AEGIS'"
echo "  Quick scan:             aegis --quick 10.0.0.1"
echo "  List modules:           aegis --list"
echo "  Run a module:           aegis --module recon/passive-recon"
echo ""
