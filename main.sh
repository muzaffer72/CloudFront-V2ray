#!/bin/bash

# Script Name: V2Ray + SSH + OpenVPN + Nginx Setup Script
# Author: Shaan
# Description: Automated setup for V2Ray, SSH WebSocket, OpenVPN, and Nginx with SSL
# Version: 1.1
# Date: April 07, 2025

# Exit on any error
set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run this script as root (e.g., with sudo)."
    exit 1
fi

# Configurable variables
DOMAIN="au-01.onvao.net"               # Replace with your domain
EMAIL="guzelim.batmanli@gmail.com"        # Replace with your email
V2RAY_WS_PATH="/ray"                  # V2Ray WebSocket path
SSH_WS_PATH="/ssh"                    # SSH WebSocket path
V2RAY_PORT="10000"                    # V2Ray WebSocket port
WEBSOCAT_PORT="8080"                  # Websocat port for SSH
OVPN_PORT="1194"                      # OpenVPN port (default UDP)
EXPIRE_DATE="2026-04-11"              # Expiration date

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Get server public IP and geolocation
IP=$(curl -s ifconfig.me)
if [ -z "$IP" ]; then
    echo -e "${RED}Error: Could not determine server IP. Check internet connectivity.${NC}"
    exit 1
fi

LOCATION=$(curl -s "http://ipinfo.io/$IP" | jq -r '.city + ", " + .region + ", " + .country')

# Trap for cleanup on error
cleanup() {
    echo -e "${RED}Script terminated. Cleaning up temporary files...${NC}"
    # Remove temporary files if created
    [ -f /tmp/websocat ] && rm -f /tmp/websocat
}
trap cleanup EXIT

# Function to validate domain and email
validate_inputs() {
    if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}Error: Invalid domain format${NC}"
        exit 1
    fi
    if [[ ! "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}Error: Invalid email format${NC}"
        exit 1
    fi
}

# Function to check if port is available
check_port() {
    local port=$1
    if netstat -tuln | grep -q ":$port "; then
        echo -e "${RED}Error: Port $port is already in use${NC}"
        exit 1
    fi
}

# Function to verify service status
verify_service() {
    local service=$1
    if ! systemctl is-active --quiet "$service"; then
        echo -e "${RED}Error: $service failed to start${NC}"
        exit 1
    fi
}

# Function to check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."
    for cmd in curl jq systemctl netstat; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}Error: Required command $cmd not found${NC}"
            exit 1
        fi
    done
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        echo -e "${RED}Error: No internet connectivity${NC}"
        exit 1
    fi
}

# Function to backup existing configurations
backup_configs() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    echo "Backing up existing configurations..."
    [ -f /etc/v2ray/config.json ] && cp /etc/v2ray/config.json "/etc/v2ray/config.json.bak.$timestamp"
    [ -f /etc/nginx/sites-available/v2ray ] && cp /etc/nginx/sites-available/v2ray "/etc/nginx/sites-available/v2ray.bak.$timestamp"
    [ -f /etc/openvpn/server.conf ] && cp /etc/openvpn/server.conf "/etc/openvpn/server.conf.bak.$timestamp"
}

# Function to update system and install dependencies
install_dependencies() {
    echo "Updating system and installing dependencies..."
    apt update -y && apt upgrade -y || {
        echo -e "${RED}Error: System update failed${NC}"
        exit 1
    }
    apt install -y curl nginx certbot python3-certbot-nginx unzip socat openvpn easy-rsa uuid-runtime jq || {
        echo -e "${RED}Error: Package installation failed${NC}"
        exit 1
    }
}

# Function to install Websocat
install_websocat() {
    echo "Installing Websocat..."
    wget -O /tmp/websocat https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl || {
        echo -e "${RED}Error: Failed to download Websocat${NC}"
        exit 1
    }
    chmod +x /tmp/websocat
    mv /tmp/websocat /usr/local/bin/websocat
}

# Function to install and configure V2Ray
configure_v2ray() {
    echo "Installing V2Ray..."
    curl -L -s https://raw.githubusercontent.com/v2fly/v2ray-core/master/install-release.sh | bash || {
        echo -e "${RED}Error: V2Ray installation failed${NC}"
        exit 1
    }

    echo "Configuring V2Ray..."
    V2RAY_UUID=$(uuidgen)
    cat > /etc/v2ray/config.json <<EOF
{
  "inbounds": [{
    "port": $V2RAY_PORT,
    "protocol": "vmess",
    "settings": {
      "clients": [{ "id": "$V2RAY_UUID", "alterId": 0 }]
    },
    "streamSettings": {
      "network": "ws",
      "wsSettings": { "path": "$V2RAY_WS_PATH" }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF
    chmod 644 /etc/v2ray/config.json
    systemctl enable v2ray
    systemctl restart v2ray
    verify_service "v2ray"
}

# Function to set up SSL with Certbot
setup_ssl() {
    echo "Obtaining SSL certificate with Certbot..."
    if ! certbot --nginx -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive --redirect; then
        echo -e "${RED}Error: SSL certificate setup failed. Check domain and DNS settings${NC}"
        exit 1
    fi
}

# Function to configure Nginx
configure_nginx() {
    echo "Configuring Nginx..."
    cat > /etc/nginx/sites-available/v2ray <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    location $V2RAY_WS_PATH {
        proxy_pass http://127.0.0.1:$V2RAY_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    location $SSH_WS_PATH {
        proxy_pass http://127.0.0.1:$WEBSOCAT_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
    chmod 644 /etc/nginx/sites-available/v2ray
    ln -sf /etc/nginx/sites-available/v2ray /etc/nginx/sites-enabled/
    nginx -t || {
        echo -e "${RED}Error: Nginx configuration test failed${NC}"
        exit 1
    }
    systemctl restart nginx
    verify_service "nginx"
}

# Function to configure OpenVPN
configure_openvpn() {
    echo "Setting up OpenVPN..."
    cd /etc/openvpn
    if [ ! -d "easy-rsa" ]; then
        make-cadir easy-rsa
    fi
    cd easy-rsa
    ./easyrsa init-pki
    echo "ca" | ./easyrsa build-ca nopass
    ./easyrsa gen-dh
    ./easyrsa build-server-full server nopass

    cat > /etc/openvpn/server.conf <<EOF
port $OVPN_PORT
proto udp
dev tun
ca easy-rsa/pki/ca.crt
cert easy-rsa/pki/issued/server.crt
key easy-rsa/pki/private/server.key
dh easy-rsa/pki/dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
persist-key
persist-tun
status openvpn-status.log
verb 3
EOF
    chmod 600 /etc/openvpn/server.conf
    chmod 600 /etc/openvpn/easy-rsa/pki/private/*
    systemctl enable openvpn@server
    systemctl restart openvpn@server
    verify_service "openvpn@server"
}

# Function to create OpenVPN client
create_openvpn_client() {
    echo "Creating OpenVPN account..."
    read -p "Enter OpenVPN username: " OVPN_USER
    read -sp "Enter OpenVPN password: " OVPN_PASS
    echo
    cd /etc/openvpn/easy-rsa
    ./easyrsa build-client-full "$OVPN_USER" nopass

    cat > /etc/openvpn/"$OVPN_USER".ovpn <<EOF
client
dev tun
proto udp
remote $DOMAIN $OVPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
cipher AES-256-CBC
verb 3
<ca>
$(cat /etc/openvpn/easy-rsa/pki/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/easy-rsa/pki/issued/"$OVPN_USER".crt)
</cert>
<key>
$(cat /etc/openvpn/easy-rsa/pki/private/"$OVPN_USER".key)
</key>
EOF
    chmod 644 /etc/openvpn/"$OVPN_USER".ovpn
}

# Function to start Websocat
start_websocat() {
    echo "Starting Websocat for SSH WebSocket..."
    nohup websocat -s "$WEBSOCAT_PORT" ws-l:127.0.0.1:22 > /var/log/websocat.log 2>&1 &
    echo $! > /var/run/websocat.pid
}

# Function to display results
display_results() {
    echo -e "${GREEN}Setup completed successfully!${NC}"
    echo "───────────────────────────"
    echo "     SSH OVPN Account     "
    echo "───────────────────────────"
    echo "Username         : $OVPN_USER"
    echo "Password         : $OVPN_PASS"
    echo "───────────────────────────"
    echo "IP               : $IP"
    echo "Host             : $DOMAIN"
    echo "Location         : $LOCATION"
    echo "Port OpenSSH     : 443, 80, 22"
    echo "Port UdpSSH      : 1-65535"
    echo "Port DNS         : 443, 53, 22"
    echo "Port Dropbear    : 443, 109"
    echo "Port Dropbear WS : 443, 109"
    echo "Port SSH WS      : 80, 8080"
    echo "Port SSH SSL WS  : 443"
    echo "Port SSL/TLS     : 443"
    echo "Port OVPN WS SSL : 443"
    echo "Port OVPN SSL    : 443"
    echo "Port OVPN TCP    : 443, 1194"
    echo "Port OVPN UDP    : 2200"
    echo "Proxy Squid      : 3128"
    echo "BadVPN UDP       : 7100, 7300, 7300"
    echo "───────────────────────────"
    echo "Payload WSS      : GET wss://$DOMAIN/ HTTP/1.1[crlf]Host: $DOMAIN[crlf]Upgrade: websocket[crlf][crlf]"
    echo "───────────────────────────"
    echo "OpenVPN Link     : https://$DOMAIN:81"
    echo "───────────────────────────"
    echo "Save Link Account: https://$DOMAIN:81/ssh-$OVPN_USER.txt"
    echo "───────────────────────────"
    echo "Expired          : $EXPIRE_DATE"
    echo "───────────────────────────"
    echo -e "${GREEN}Notes:${NC}"
    echo "1. Copy the .ovpn file from /etc/openvpn/$OVPN_USER.ovpn to your client device."
    echo "2. For SSH WS, use a WebSocket client with ws://$DOMAIN:$WEBSOCAT_PORT$SSH_WS_PATH."
    echo "3. For V2Ray, configure your client with the UUID ($V2RAY_UUID) and WebSocket path ($V2RAY_WS_PATH)."
}

# Main execution
main() {
    check_prerequisites
    validate_inputs
    check_port "$V2RAY_PORT"
    check_port "$WEBSOCAT_PORT"
    check_port "$OVPN_PORT"
    backup_configs
    install_dependencies
    install_websocat
    configure_v2ray
    setup_ssl
    configure_nginx
    configure_openvpn
    create_openvpn_client
    start_websocat
    display_results
    # Disable cleanup trap on successful completion
    trap - EXIT
}

# Run the script
main
