#!/usr/bin/env bash
# ==============================================================================
# HackRF Smart Spectrum Scanner - Automated Tool & Service Manager
# (Sub-GHz Penetration + 1-3 GHz Round-the-Clock 24/7 + Mesh & Pulsed Hunter)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_PY="${SCRIPT_DIR}/hackrf_penetration_scanner.py"
ANALYZER_PY="${SCRIPT_DIR}/analyze_scan_data.py"
VERIFIER_PY="${SCRIPT_DIR}/verify_rf_devices.py"
DASHBOARD_PY="${SCRIPT_DIR}/web_dashboard.py"
MONITOR_PY="${SCRIPT_DIR}/monitor_flagged.py"
CELL_INTEL_PY="${SCRIPT_DIR}/cell_tower_intel.py"
DF_PY="${SCRIPT_DIR}/direction_finder.py"
LOG_FILE="${SCRIPT_DIR}/penetration_scan_hits.log"
PID_FILE="${SCRIPT_DIR}/.hackrf_scanner.pid"
SERVICE_NAME="hackrf-penetration-scanner.service"
UDEV_RULE_FILE="/etc/udev/rules.d/99-hackrf-penetration-scanner.rules"
DESKTOP_FILE="${SCRIPT_DIR}/HackRF_Penetration_Scanner.desktop"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}   $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERR]${NC}  $*" >&2; }

check_dependencies() {
    local auto_install="${1:-false}"
    if ! command -v python3 >/dev/null 2>&1; then
        log_error "python3 is not installed."
        return 1
    fi

    if ! command -v hackrf_sweep >/dev/null 2>&1; then
        log_warn "'hackrf_sweep' was not found in PATH."
        if [[ "${auto_install}" == "true" ]]; then
            install_dependencies
        else
            log_info "Run '${0} --install-deps' (or select Option 11 in the menu) to install HackRF tools automatically."
            return 1
        fi
    fi
    return 0
}

install_dependencies() {
    log_info "Installing HackRF command-line tools (hackrf)..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y hackrf libhackrf0
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y hackrf
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm hackrf
    else
        log_error "Unsupported package manager. Please install 'hackrf' manually."
        return 1
    fi
    log_ok "HackRF tools installed successfully."
}

check_hardware() {
    if command -v hackrf_info >/dev/null 2>&1; then
        if hackrf_info >/dev/null 2>&1; then
            log_ok "HackRF hardware detected and ready."
            return 0
        else
            log_warn "No HackRF board detected over USB (or USB permission denied)."
            return 1
        fi
    fi
    return 1
}

run_foreground() {
    check_dependencies "false" || return 1
    check_hardware || log_warn "Starting scanner anyway (hackrf_sweep will report if device is missing)..."
    log_info "Saving all detected hits to: ${LOG_FILE}"
    python3 "${SCANNER_PY}" -o "${LOG_FILE}" "$@" || true
    echo ""
    log_ok "Scan finished. Log saved at: ${LOG_FILE}"
    read -rp "Would you like to analyze pulsed/mesh/24-7 signals & verify devices right now? [Y/n]: " ans
    if [[ "${ans:-Y}" =~ ^[Yy]$ ]]; then
        analyze_logs
        echo ""
        verify_devices
    fi
}

start_daemon() {
    check_dependencies "false" || exit 1
    if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        log_warn "Scanner daemon is already running (PID: $(cat "${PID_FILE}"))."
        return 0
    fi

    log_info "Starting HackRF Smart Scanner in background..."
    nohup python3 "${SCANNER_PY}" -o "${LOG_FILE}" "$@" >> "${SCRIPT_DIR}/scanner_stdout.log" 2>&1 &
    local pid=$!
    echo "${pid}" > "${PID_FILE}"
    sleep 1
    if kill -0 "${pid}" 2>/dev/null; then
        log_ok "Background scanner started (PID: ${pid})."
        log_info "Hits log : ${LOG_FILE}"
        log_info "Output   : ${SCRIPT_DIR}/scanner_stdout.log"
    else
        log_error "Scanner exited immediately. Check ${SCRIPT_DIR}/scanner_stdout.log"
        rm -f "${PID_FILE}"
        return 1
    fi
}

stop_daemon() {
    if [[ -f "${PID_FILE}" ]]; then
        local pid
        pid="$(cat "${PID_FILE}")"
        if kill -0 "${pid}" 2>/dev/null; then
            log_info "Stopping background scanner (PID: ${pid})..."
            kill -SIGINT "${pid}" 2>/dev/null || kill -SIGTERM "${pid}" 2>/dev/null || true
            for _ in {1..20}; do
                if ! kill -0 "${pid}" 2>/dev/null; then
                    break
                fi
                sleep 0.2
            done
            if kill -0 "${pid}" 2>/dev/null; then
                kill -9 "${pid}" 2>/dev/null || true
            fi
            log_ok "Scanner stopped cleanly."
        else
            log_warn "PID ${pid} is not running."
        fi
        rm -f "${PID_FILE}"
    else
        log_warn "No background PID file found."
    fi
}

status_daemon() {
    echo -e "${BOLD}=== HackRF Smart Spectrum Scanner Status ===${NC}"
    if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        log_ok "Background Daemon : RUNNING (PID: $(cat "${PID_FILE}"))"
    else
        log_info "Background Daemon : STOPPED"
    fi

    if systemctl --user is-active "${SERVICE_NAME}" >/dev/null 2>&1; then
        log_ok "User Systemd Svc  : ACTIVE"
    elif systemctl is-active "${SERVICE_NAME}" >/dev/null 2>&1; then
        log_ok "Systemd Service   : ACTIVE"
    else
        log_info "Systemd Service   : INACTIVE"
    fi

    if [[ -f "${LOG_FILE}" ]]; then
        local hit_count
        hit_count=$(grep -v '^#' "${LOG_FILE}" 2>/dev/null | wc -l || echo 0)
        log_info "Logged RF Hits    : ${hit_count} (${LOG_FILE})"
        echo -e "\n${BOLD}Last 5 Recorded Hits:${NC}"
        grep -v '^#' "${LOG_FILE}" | tail -n 5 || echo "  (no hits yet)"
    else
        log_info "Logged RF Hits    : No log file yet (${LOG_FILE})"
    fi
}

install_systemd_and_udev() {
    log_info "Installing systemd service and USB udev auto-start rule..."
    local svc_path="/etc/systemd/system/${SERVICE_NAME}"
    local current_user
    current_user="$(id -un)"

    sudo tee "${svc_path}" >/dev/null <<EOF
[Unit]
Description=HackRF Smart Spectrum Auto-Scanner (Sub-GHz + 1-3 GHz + Mesh/Pulsed)
After=network.target

[Service]
Type=simple
User=${current_user}
WorkingDirectory=${SCRIPT_DIR}
ExecStart=/usr/bin/env python3 ${SCANNER_PY} --mode full -o ${LOG_FILE}
KillSignal=SIGINT
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Create udev rule for HackRF One (Vendor ID 1d50, Product ID 6089)
    sudo tee "${UDEV_RULE_FILE}" >/dev/null <<EOF
# Automatically start HackRF Smart Scanner when HackRF One is plugged in via USB
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="6089", MODE="0666", TAG+="systemd", ENV{SYSTEMD_WANTS}="${SERVICE_NAME}"
ACTION=="remove", SUBSYSTEM=="usb", ENV{ID_VENDOR_ID}=="1d50", ENV{ID_MODEL_ID}=="6089", RUN+="/bin/systemctl stop ${SERVICE_NAME}"
EOF

    sudo systemctl daemon-reload
    sudo udevadm control --reload-rules
    log_ok "Installed ${svc_path}"
    log_ok "Installed ${UDEV_RULE_FILE} (auto-starts scan on HackRF USB plug-in!)"
    log_info "You can also manually control it with: sudo systemctl start|stop|enable ${SERVICE_NAME}"
}

uninstall_systemd_and_udev() {
    log_info "Removing systemd service and udev rule..."
    sudo systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    sudo systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    sudo rm -f "/etc/systemd/system/${SERVICE_NAME}" "${UDEV_RULE_FILE}"
    sudo systemctl daemon-reload
    sudo udevadm control --reload-rules
    log_ok "Removed systemd service and udev auto-trigger rule."
}

create_desktop_shortcut() {
    cat > "${DESKTOP_FILE}" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=HackRF Smart Scanner
Comment=Scan Sub-GHz Penetration Bands, 1-3 GHz 24/7 Carriers, Pulsed Signals & Mesh Networks
Path=${SCRIPT_DIR}
Exec=${SCRIPT_DIR}/auto_scanner.sh --menu
Icon=utilities-terminal
Terminal=true
Categories=Utility;System;Security;
EOF
    chmod +x "${DESKTOP_FILE}"
    if [[ -d "${HOME}/Desktop" ]]; then
        cp -f "${DESKTOP_FILE}" "${HOME}/Desktop/HackRF_Penetration_Scanner.desktop"
        chmod +x "${HOME}/Desktop/HackRF_Penetration_Scanner.desktop"
        log_ok "Created desktop launcher at ${HOME}/Desktop/HackRF_Penetration_Scanner.desktop"
    fi
    log_ok "Created launcher at ${DESKTOP_FILE}"
}

analyze_logs() {
    python3 "${ANALYZER_PY}" -f "${LOG_FILE}" "$@"
}

verify_devices() {
    python3 "${VERIFIER_PY}" -f "${LOG_FILE}" "$@"
}

export_reports() {
    local csv_out="${SCRIPT_DIR}/scan_analysis_summary.csv"
    local json_out="${SCRIPT_DIR}/scan_analysis_summary.json"
    local html_out="${SCRIPT_DIR}/scan_dashboard.html"
    python3 "${ANALYZER_PY}" -f "${LOG_FILE}" --export-csv "${csv_out}" --export-json "${json_out}" "$@"
    python3 "${VERIFIER_PY}" -f "${LOG_FILE}"
    python3 "${MONITOR_PY}" -f "${LOG_FILE}"
    python3 "${DASHBOARD_PY}" -f "${LOG_FILE}" -o "${html_out}"
}

start_web_dashboard() {
    python3 "${DASHBOARD_PY}" -f "${LOG_FILE}" --serve --open-browser "$@"
}

show_watchlist() {
    python3 "${MONITOR_PY}" -f "${LOG_FILE}" "$@"
}

monitor_flagged_live() {
    check_dependencies "false" || return 1
    check_hardware || log_warn "Starting Lock-On Sentinel anyway..."
    python3 "${MONITOR_PY}" -f "${LOG_FILE}" --live "$@" || true
}

show_cell_report() {
    python3 "${CELL_INTEL_PY}" -f "${LOG_FILE}" "$@"
}

run_direction_finder() {
    local freq="${1:-}"
    if [[ -z "${freq}" ]]; then
        read -rp "Enter target frequency in MHz (e.g. 890.25 or 934.35): " freq
    fi
    if [[ -n "${freq}" ]]; then
        python3 "${DF_PY}" --freq "${freq}"
    fi
}

configure_location() {
    echo "Select your Location / Spectrum Region:"
    echo "  1) UK  - United Kingdom (Ofcom / ITU Region 1)"
    echo "  2) US  - United States & Canada (FCC / ITU Region 2)"
    echo "  3) EU  - European Union (ETSI / CEPT / ITU Region 1)"
    echo "  4) AU  - Australia & New Zealand (ACMA / ITU Region 3)"
    echo "  5) GLOBAL - Multi-Region Fallback"
    read -rp "Region [1-5]: " r_choice
    local reg="UK"
    case "${r_choice}" in
        1) reg="UK" ;;
        2) reg="US" ;;
        3) reg="EU" ;;
        4) reg="AU" ;;
        5) reg="GLOBAL" ;;
    esac
    read -rp "Optional Latitude (press Enter to skip): " lat_in
    read -rp "Optional Longitude (press Enter to skip): " lon_in
    echo "Environment for dB Distance Model: 1) suburban (default), 2) outdoor_los, 3) urban_indoor"
    read -rp "Environment [1-3]: " e_choice
    local env_val="suburban"
    case "${e_choice}" in
        2) env_val="outdoor_los" ;;
        3) env_val="urban_indoor" ;;
    esac
    local extra_args=(--region "${reg}" --env "${env_val}" --save-config)
    if [[ -n "${lat_in}" && -n "${lon_in}" ]]; then
        extra_args+=(--lat "${lat_in}" --lon "${lon_in}")
    fi
    python3 "${CELL_INTEL_PY}" "${extra_args[@]}" --print-cell-ranges >/dev/null
    log_ok "Saved location config: Region=${reg}, Env=${env_val}"
}

show_menu() {
    while true; do
        echo ""
        echo -e "${BOLD}==============================================================================${NC}"
        echo -e "${BOLD}   HackRF Cell Tower, Direction Finder & Smart Spectrum Intelligence Suite${NC}"
        echo -e "${BOLD}==============================================================================${NC}"
        echo "  1) Search Cell Towers Only (Region-Aware Real vs. Fake Tower Scan)"
        echo "  2) Search PULSED Cell Tower Signals Only (Mute 24/7 & Wi-Fi Clutter)"
        echo "  3) Run Compass Direction Finder (Find Incoming Direction & Distance)"
        echo "  4) View Cell Tower Real-vs-Fake & Real Research Flags Report"
        echo "  5) Configure Your Location / Region & dB Distance Calibration"
        echo "  6) Launch Live Web Dashboard (http://127.0.0.1:8080 + scan_dashboard.html)"
        echo "  7) Start Full Live Scan (Sub-GHz + Cellular + 1-3 GHz)"
        echo "  8) Start Pulsed Frequencies Only Scan (Non-WiFi)"
        echo "  9) Start Fast Mesh & Pulsed Hunter Scan (433, 868/915 & 2.4 GHz)"
        echo " 10) Start Live Lock-On Sentinel (Flagged Frequencies Only)"
        echo " 11) Start Auto Background Daemon Scan"
        echo " 12) Stop Background Daemon Scan"
        echo " 13) Check Scanner Status & Recent Hits"
        echo " 14) Analyze Scanned Data in Terminal (Pulsed PRI, Mesh & 24/7)"
        echo " 15) Identify Devices & Audit Compliance in Terminal"
        echo " 16) Export All Reports (HTML Web Page + Watchlist + CSV + JSON)"
        echo " 17) Install 'hackrf' System Dependencies"
        echo " 18) Enable / Remove USB Auto-Scan or Desktop Shortcut"
        echo "  q) Quit"
        echo "------------------------------------------------------------------------------"
        read -rp "Select an option [1-18, q]: " choice
        echo ""
        case "${choice}" in
            1) run_foreground --mode cell ;;
            2) run_foreground --mode cell-pulsed ;;
            3) run_direction_finder ;;
            4) show_cell_report ;;
            5) configure_location ;;
            6) start_web_dashboard ;;
            7) run_foreground --mode full ;;
            8) run_foreground --mode pulsed ;;
            9) run_foreground --mode mesh ;;
            10) monitor_flagged_live ;;
            11) start_daemon --mode cell ;;
            12) stop_daemon ;;
            13) status_daemon ;;
            14) analyze_logs ;;
            15) verify_devices ;;
            16) export_reports ;;
            17) install_dependencies ;;
            18) create_desktop_shortcut ;;
            q|Q) exit 0 ;;
            *) log_warn "Invalid selection." ;;
        esac
    done
}

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTION] [SCANNER_OR_ANALYZER_ARGS...]

Cell Tower Authenticity, Direction Finder, Location Audit & Smart Spectrum Suite.

Options:
  --web, -w           Launch Live Interactive Web Dashboard (http://127.0.0.1:8080) & generate scan_dashboard.html
  --html              Generate standalone scan_dashboard.html file (offline-ready web report)
  --cell              Search Cell Towers ONLY (auto-tuned to your configured region's cellular bands)
  --cell-pulsed       Search PULSED Cell Tower signals ONLY (filters out 24/7 & Wi-Fi clutter)
  --pulsed            Pull Pulsed Frequencies ONLY across non-WiFi spectrum
  --cell-report       Print Real vs. Fake Cell Tower, Location Belonging & Real Research Flags Report
  --df <MHz>          Run Interactive Compass Direction Finder & Distance Estimator on <MHz>
  --set-location      Configure your Region (US/UK/EU/AU), GPS Lat/Lon & dB Distance Model
  --watchlist         Show Flagged Frequency Watchlist & Cross-Spectrum Characteristic Matches
  --monitor           Start Live High-Speed Lock-On Sentinel monitoring ONLY Flagged Frequencies & Clones
  --run, -r           Run live scan in foreground (supports --mode cell|cell-pulsed|pulsed|full|highband|mesh|subghz)
  --highband          Shortcut to run live 1-3 GHz (1000-3000 MHz) scan in foreground
  --mesh              Shortcut to run fast Mesh & Pulsed Hunter scan (433, 868/915, 2.4 GHz)
  --subghz            Shortcut to run Sub-GHz Penetration & Low-Band Cellular scan (1-30, 400-450, 600-960 MHz)
  --daemon, -d        Start scanner automatically in background daemon mode
  --stop, -s          Stop background daemon gracefully
  --status            Show daemon/service status and latest logged RF hits
  --analyze, -a       Analyze logged RF scan data (Pulsed timing, Mesh topology & 24/7 carriers)
  --verify, -v        Identify devices & audit signal characteristics for legal compliance
  --export            Analyze logged RF data and export HTML + Watchlist + CSV + JSON summary files
  --install-deps      Auto-install 'hackrf' package via apt/dnf/pacman
  --install-service   Install systemd service & USB udev plug-and-play auto-trigger
  --remove-service    Remove systemd service & USB udev rule
  --desktop-shortcut  Create a double-clickable .desktop shortcut on your Desktop
  --menu, -m          Open interactive management menu (default if no args given)
  --help, -h          Show this help message
EOF
}

main() {
    if [[ $# -eq 0 ]]; then
        show_menu
        exit 0
    fi

    case "$1" in
        --web|-w)
            shift
            start_web_dashboard "$@"
            ;;
        --html)
            shift
            python3 "${DASHBOARD_PY}" -f "${LOG_FILE}" "$@"
            ;;
        --cell)
            shift
            run_foreground --mode cell "$@"
            ;;
        --cell-pulsed)
            shift
            run_foreground --mode cell-pulsed "$@"
            ;;
        --pulsed)
            shift
            run_foreground --mode pulsed "$@"
            ;;
        --cell-report)
            shift
            show_cell_report "$@"
            ;;
        --df)
            shift
            run_direction_finder "${1:-}"
            ;;
        --set-location)
            configure_location
            ;;
        --watchlist)
            shift
            show_watchlist "$@"
            ;;
        --monitor)
            shift
            monitor_flagged_live "$@"
            ;;
        --run|-r)
            shift
            run_foreground "$@"
            ;;
        --highband)
            shift
            run_foreground --mode highband "$@"
            ;;
        --mesh)
            shift
            run_foreground --mode mesh "$@"
            ;;
        --subghz)
            shift
            run_foreground --mode subghz "$@"
            ;;
        --daemon|-d)
            shift
            start_daemon "$@"
            ;;
        --stop|-s)
            stop_daemon
            ;;
        --status)
            status_daemon
            ;;
        --analyze|-a)
            shift
            analyze_logs "$@"
            ;;
        --verify|-v)
            shift
            verify_devices "$@"
            ;;
        --export)
            shift
            export_reports "$@"
            ;;
        --install-deps)
            install_dependencies
            ;;
        --install-service)
            install_systemd_and_udev
            ;;
        --remove-service)
            uninstall_systemd_and_udev
            ;;
        --desktop-shortcut)
            create_desktop_shortcut
            ;;
        --menu|-m)
            show_menu
            ;;
        --help|-h)
            usage
            ;;
        *)
            run_foreground "$@"
            ;;
    esac
}

main "$@"
