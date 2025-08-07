#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_banner() {
    echo -e "${BLUE}"
    echo "  ____       ___ ____    _       ___ ____  ____  "
    echo " / ___| ___ |_ _|  _ \  / \     |_ _|  _ \/ ___| "
    echo "| |  _ / _ \ | || | | |/ _ \     | || |_) \___ \ "
    echo "| |_| | (_) | || |_| / ___ \    | ||  __/ ___) |"
    echo " \____|\___/___|____/_/   \_\  |___|_|   |____/ "
    echo "                                               "
    echo -e "${NC}"
    echo -e "${GREEN}GoIDA Intrusion Prevention System${NC}"
    echo -e "${YELLOW}Minimalistic High-Performance IDS/IPS${NC}"
    echo
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

check_system() {
    echo -e "${BLUE}Checking system requirements...${NC}"

    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}Error: Python 3 is required but not installed${NC}"
        exit 1
    fi

    if ! command -v pip3 &> /dev/null; then
        echo -e "${YELLOW}Warning: pip3 not found, installing...${NC}"
        apt-get update
        apt-get install -y python3-pip
    fi

    if ! command -v iptables &> /dev/null; then
        echo -e "${RED}Error: iptables is required but not installed${NC}"
        exit 1
    fi

    echo -e "${GREEN}System requirements satisfied${NC}"
}

install_system_deps() {
    echo -e "${BLUE}Installing system dependencies...${NC}"

    apt-get update
    apt-get install -y \
        build-essential \
        python3-dev \
        libnetfilter-queue-dev \
        libnetfilter-queue1 \
        libnfnetlink-dev \
        libnfnetlink0 \
        iptables \
        python3-pip \
        git

    echo -e "${GREEN}System dependencies installed${NC}"
}

install_python_deps() {
    echo -e "${BLUE}Installing Python dependencies...${NC}"

    if [[ ! -f "requirements.txt" ]]; then
        echo -e "${RED}Error: requirements.txt not found${NC}"
        exit 1
    fi

    pip3 install -r requirements.txt --break-system-packages

    echo -e "${GREEN}Python dependencies installed${NC}"
}

setup_directories() {
    echo -e "${BLUE}Setting up directories...${NC}"

    mkdir -p logs
    mkdir -p alerts
    mkdir -p pcaps

    chown -R $SUDO_USER:$SUDO_USER logs alerts pcaps 2>/dev/null || true

    echo -e "${GREEN}Directories created${NC}"
}

configure_system() {
    echo -e "${BLUE}Configuring system settings...${NC}"

    echo "net.netfilter.nf_conntrack_max = 1048576" >> /etc/sysctl.conf
    echo "net.core.netdev_max_backlog = 5000" >> /etc/sysctl.conf
    echo "net.core.rmem_max = 134217728" >> /etc/sysctl.conf
    echo "net.core.wmem_max = 134217728" >> /etc/sysctl.conf

    sysctl -p

    echo -e "${GREEN}System configured for high performance${NC}"
}

create_service_file() {
    echo -e "${BLUE}Creating systemd service file...${NC}"

    cat > /etc/systemd/system/goida-ips.service << EOF
[Unit]
Description=GoIDA Intrusion Prevention System
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=/usr/bin/python3 $SCRIPT_DIR/main.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    echo -e "${GREEN}Service file created${NC}"
}

show_iptables_setup() {
    echo -e "${BLUE}IPTables Setup Instructions:${NC}"
    echo
    echo -e "${YELLOW}To start monitoring traffic, run these commands:${NC}"
    echo

    QUEUES=$(grep "queues:" config.yaml | awk '{print $2}' 2>/dev/null || echo "4")

    for ((i=0; i<$QUEUES; i++)); do
        echo "iptables -I FORWARD -j NFQUEUE --queue-num $i"
    done

    echo
    echo -e "${YELLOW}To monitor specific traffic only (recommended):${NC}"
    echo "iptables -I FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0"
    echo "iptables -I FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num 1"
    echo
    echo -e "${YELLOW}To remove rules later:${NC}"
    for ((i=0; i<$QUEUES; i++)); do
        echo "iptables -D FORWARD -j NFQUEUE --queue-num $i"
    done
    echo
}

test_installation() {
    echo -e "${BLUE}Testing installation...${NC}"

    if python3 -c "import netfilterqueue, dpkt, ahocorasick, flask, yaml" 2>/dev/null; then
        echo -e "${GREEN}Python dependencies OK${NC}"
    else
        echo -e "${RED}Python dependencies test failed${NC}"
        exit 1
    fi

    if [[ -f "main.py" && -f "config.yaml" ]]; then
        echo -e "${GREEN}Core files OK${NC}"
    else
        echo -e "${RED}Core files missing${NC}"
        exit 1
    fi

    echo -e "${GREEN}Installation test passed${NC}"
}

show_usage() {
    echo -e "${BLUE}Usage Instructions:${NC}"
    echo
    echo -e "${YELLOW}1. Start the service:${NC}"
    echo "   systemctl start goida-ips"
    echo
    echo -e "${YELLOW}2. Enable auto-start:${NC}"
    echo "   systemctl enable goida-ips"
    echo
    echo -e "${YELLOW}3. Check status:${NC}"
    echo "   systemctl status goida-ips"
    echo
    echo -e "${YELLOW}4. View logs:${NC}"
    echo "   journalctl -u goida-ips -f"
    echo
    echo -e "${YELLOW}5. View metrics:${NC}"
    echo "   curl http://127.0.0.1:8080/stats"
    echo
    echo -e "${YELLOW}6. Manual run (for testing):${NC}"
    echo "   python3 main.py"
    echo
    echo -e "${YELLOW}7. Edit configuration:${NC}"
    echo "   nano config.yaml"
    echo
}

main() {
    print_banner

    check_root
    check_system
    install_system_deps
    install_python_deps
    setup_directories
    configure_system
    create_service_file
    test_installation

    echo
    echo -e "${GREEN}Installation completed successfully!${NC}"
    echo

    show_iptables_setup
    show_usage

    echo -e "${BLUE}Setup complete. GoIDA IPS is ready to use.${NC}"
}

main "$@"
