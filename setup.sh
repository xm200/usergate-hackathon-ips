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
    echo " ___ ____  ____  "
    echo "|_ _|  _ \/ ___| "
    echo " | || |_) \___ \ "
    echo " | ||  __/ ___) |"
    echo "|___|_|   |____/ "
    echo "                                               "
    echo -e "${NC}"
    echo -e "${GREEN}Intrusion Prevention System${NC}"
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

configure_system() {
    echo -e "${BLUE}Configuring system settings...${NC}"

    echo "net.netfilter.nf_conntrack_max = 1048576" >> /etc/sysctl.conf
    echo "net.core.netdev_max_backlog = 5000" >> /etc/sysctl.conf
    echo "net.core.rmem_max = 134217728" >> /etc/sysctl.conf
    echo "net.core.wmem_max = 134217728" >> /etc/sysctl.conf

    sysctl -p

    echo -e "${GREEN}System configured for high performance${NC}"
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

main() {
    print_banner

    check_root
    check_system
    install_system_deps
    install_python_deps
    test_installation

    echo
    echo -e "${GREEN}Installation completed successfully!${NC}"
    echo

    show_iptables_setup
    show_usage

    echo -e "${BLUE}Setup complete. IPS is ready to use.${NC}"
}

main "$@"
