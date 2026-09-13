#!/usr/bin/env bash
# AEGIS — Autonomous Electronic Governance & Intelligence System
# Launcher script for the cyber operations platform
set -euo pipefail

AEGIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$AEGIS_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

clear
echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
    ___    _______________  _____
   /   |  / ____/ ____/  |/  /  |
  / /| | / __/ / / __/ /|_/ / /| |
 / ___ |/ /___/ /_/ / /  / / ___ |
/_/  |_/_____/\____/_/  /_/_/  |_|

  Autonomous Electronic Governance
  & Intelligence System v1.0
BANNER
echo -e "${RESET}"
echo -e "${DIM}  Darknode Cyber Operations Platform${RESET}"
echo -e "${DIM}  Use only on systems you own or are authorized to test.${RESET}"
echo ""

# --- Quick launch modes ---
if [ "${1:-}" = "--module" ] && [ -n "${2:-}" ]; then
    # Direct module launch: aegis.sh --module recon/passive-recon
    MODULE="modules/${2}.py"
    if [ -f "$MODULE" ]; then
        echo -e "${CYAN}[AEGIS] Launching module: ${2}${RESET}"
        exec python3 "$MODULE" "${@:3}"
    else
        echo -e "${RED}[ERROR] Module not found: ${2}${RESET}"
        echo "Available modules:"
        find modules -name "*.py" -not -name "__*" | sed 's|modules/||;s|\.py||' | sort | sed 's/^/  /'
        exit 1
    fi
fi

if [ "${1:-}" = "--list" ]; then
    echo -e "${CYAN}[AEGIS] Available modules:${RESET}"
    echo ""
    for domain in recon vuln exploit intel defense crypto network ai reporting; do
        echo -e "${BOLD}  ${domain^^}${RESET}"
        find "modules/$domain" -name "*.py" -not -name "__*" 2>/dev/null | while read -r f; do
            name=$(basename "$f" .py)
            desc=$(head -3 "$f" | grep -oP '""".*"""' | tr -d '"' || echo "")
            printf "    %-25s %s\n" "$name" "${DIM}${desc}${RESET}"
        done
        echo ""
    done
    exit 0
fi

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    echo "Usage: aegis.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  (none)                Launch the TUI dashboard"
    echo "  --module <name>       Run a module directly (e.g. recon/passive-recon)"
    echo "  --list                List all available modules"
    echo "  --quick <target>      Quick scan: passive recon + port scan + CVE match"
    echo "  --mission <name>      Create and activate a new mission"
    echo "  --help                Show this help"
    echo ""
    echo "Examples:"
    echo "  aegis.sh                           # Full dashboard"
    echo "  aegis.sh --quick 10.0.0.1          # Quick recon"
    echo "  aegis.sh --module vuln/vuln-scanner # Run one module"
    echo "  aegis.sh --mission 'Op Sunrise'    # New mission"
    exit 0
fi

# --- Dependency check ---
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[ERROR] Python 3 is required but not found.${RESET}"
    echo "Install with: sudo apt install python3 python3-pip"
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    echo -e "${RED}[ERROR] Python 3.8+ required. Found: $PY_VERSION${RESET}"
    exit 1
fi

# Install rich for TUI
if ! python3 -c "import rich" 2>/dev/null; then
    echo -e "${CYAN}[AEGIS] Installing rich library for TUI...${RESET}"
    pip3 install --user --quiet rich 2>/dev/null || pip3 install --quiet rich 2>/dev/null || {
        echo -e "${YELLOW}[WARN] Could not install rich. Running in plain mode.${RESET}"
    }
fi

# Check for security tools
echo -e "${DIM}[AEGIS] Checking available tools...${RESET}"
TOOLS_FOUND=0
TOOLS_TOTAL=0
for tool in nmap nikto gobuster sqlmap hydra john hashcat searchsploit nuclei ffuf masscan whatweb wpscan sslscan dig whois curl tshark volatility3 yara; do
    TOOLS_TOTAL=$((TOOLS_TOTAL + 1))
    if command -v "$tool" &>/dev/null; then
        TOOLS_FOUND=$((TOOLS_FOUND + 1))
    fi
done
echo -e "${GREEN}[AEGIS] ${TOOLS_FOUND}/${TOOLS_TOTAL} security tools available${RESET}"

# Create workspace
mkdir -p missions

# Quick scan mode
if [ "${1:-}" = "--quick" ] && [ -n "${2:-}" ]; then
    echo -e "${CYAN}[AEGIS] Quick scan mode: ${2}${RESET}"
    echo -e "${DIM}Running: passive recon + port scan + CVE matching${RESET}"
    echo ""
    python3 -c "
import sys
sys.path.insert(0, '.')
target = '${2}'
print('[1/3] Passive Reconnaissance...')
try:
    from modules.recon import passive_recon
    # Run if module supports it
except: pass
print('[2/3] Port Scanning...')
try:
    from modules.recon import active_recon
except: pass
print('[3/3] CVE Matching...')
try:
    from modules.vuln import vuln_scanner
except: pass
print()
print('Quick scan complete. Run aegis.sh for the full dashboard.')
" 2>/dev/null || echo -e "${YELLOW}Quick scan modules not fully loaded. Use the dashboard instead.${RESET}"
    exit 0
fi

# New mission shortcut
if [ "${1:-}" = "--mission" ] && [ -n "${2:-}" ]; then
    echo -e "${CYAN}[AEGIS] Creating mission: ${2}${RESET}"
    exec python3 ui/dashboard.py --new-mission "${2}" "${@:3}"
fi

echo -e "${GREEN}[AEGIS] Launching operations dashboard...${RESET}"
echo ""
exec python3 ui/dashboard.py "$@"
