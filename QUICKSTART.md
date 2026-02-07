# WS-VPN Quick Start Guide

This guide will help you set up WS-VPN between an Ubuntu server and Windows clients.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Server Setup (Ubuntu)](#server-setup-ubuntu)
3. [Client Setup (Windows)](#client-setup-windows)
4. [Testing the VPN](#testing-the-vpn)
5. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Server Requirements (Ubuntu)

- **OS**: Ubuntu 20.04 LTS or later (22.04 LTS recommended)
- **Architecture**: x86_64 (amd64)
- **Access**: Root or sudo privileges
- **Network**:
  - Public IP address or accessible from clients
  - Port 443 open (inbound TCP)
- **Software**: None required (binary is statically compiled)

### Client Requirements (Windows)

- **OS**: Windows 10/11 (64-bit)
- **Access**: Administrator privileges
- **Network**: Outbound access to port 443
- **Software**: None required (Wintun driver is bundled)

---

## Server Setup (Ubuntu)

### Step 1: Download the Server Binary

```bash
# Create directory for VPN
sudo mkdir -p /opt/vpn
cd /opt/vpn

# Download the binary (or copy from build)
# If you built it yourself:
sudo cp /path/to/vpn-server /opt/vpn/

# Make it executable
sudo chmod +x /opt/vpn/vpn-server
```

### Step 2: Generate TLS Certificate

For **testing** (self-signed certificate):

```bash
# Create certificate directory
sudo mkdir -p /etc/vpn

# Generate self-signed certificate (valid for 1 year)
sudo openssl req -x509 -newkey rsa:4096 \
  -keyout /etc/vpn/server.key \
  -out /etc/vpn/server.crt \
  -days 365 \
  -nodes \
  -subj "/CN=vpn-server"

# Set proper permissions
sudo chmod 600 /etc/vpn/server.key
sudo chmod 644 /etc/vpn/server.crt
```

For **production** (Let's Encrypt):

```bash
# Install certbot
sudo apt update
sudo apt install -y certbot

# Get certificate (replace with your domain)
sudo certbot certonly --standalone -d vpn.yourdomain.com

# Link certificates
sudo ln -sf /etc/letsencrypt/live/vpn.yourdomain.com/fullchain.pem /etc/vpn/server.crt
sudo ln -sf /etc/letsencrypt/live/vpn.yourdomain.com/privkey.pem /etc/vpn/server.key
```

### Step 3: Create Configuration File

```bash
sudo nano /etc/vpn/server.yaml
```

Add the following content:

```yaml
server:
  listen_addr: "0.0.0.0:443"
  tls_cert: "/etc/vpn/server.crt"
  tls_key: "/etc/vpn/server.key"

vpn:
  subnet: "10.100.0.0/24"
  server_ip: "10.100.0.1"
  mtu: 1420
  interface_name: "tun0"

auth:
  tokens:
    - "REPLACE-WITH-SECURE-TOKEN-1"
    - "REPLACE-WITH-SECURE-TOKEN-2"

logging:
  level: "info"
```

**Generate secure tokens:**

```bash
# Generate random tokens
openssl rand -hex 32
openssl rand -hex 32
```

Replace `REPLACE-WITH-SECURE-TOKEN-X` with the generated tokens.

### Step 4: Enable IP Forwarding

```bash
# Enable immediately
sudo sysctl -w net.ipv4.ip_forward=1

# Make permanent
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

### Step 5: Configure Firewall

```bash
# If using UFW
sudo ufw allow 443/tcp
sudo ufw reload

# If using iptables directly
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

### Step 6: Load TUN Module

```bash
# Load the tun module
sudo modprobe tun

# Make it permanent
echo "tun" | sudo tee -a /etc/modules
```

### Step 7: Run the Server

**Manual start (for testing):**

```bash
sudo /opt/vpn/vpn-server -config /etc/vpn/server.yaml
```

**As a systemd service (recommended for production):**

```bash
# Create service file
sudo nano /etc/systemd/system/vpn-server.service
```

Add:

```ini
[Unit]
Description=WS-VPN Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/vpn/vpn-server -config /etc/vpn/server.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable vpn-server
sudo systemctl start vpn-server

# Check status
sudo systemctl status vpn-server

# View logs
sudo journalctl -u vpn-server -f
```

### Step 8: Verify Server is Running

```bash
# Check if listening
sudo ss -tlnp | grep 443

# Check health endpoint (from server)
curl -k https://localhost:443/health
```

Expected output:

```json
{"bytes_forwarded":0,"clients":0,"packets_forwarded":0,"status":"ok"}
```

---

## Client Setup (Windows)

### Step 1: Download the Client

1. Copy `vpn-client.exe` to a folder (e.g., `C:\VPN\`)
2. Copy the example config and rename it to `client.yaml`

### Step 2: Create Configuration File

Create `C:\VPN\client.yaml`:

```yaml
server:
  url: "wss://YOUR-SERVER-IP:443/vpn"
  verify_tls: false  # Set to true if using valid certificate

auth:
  token: "REPLACE-WITH-YOUR-TOKEN"

vpn:
  interface_name: "WS-VPN"
  mtu: 1420

reconnect:
  min_backoff: "1s"
  max_backoff: "60s"

logging:
  level: "info"
```

**Important:**
- Replace `YOUR-SERVER-IP` with your server's public IP or domain
- Replace `REPLACE-WITH-YOUR-TOKEN` with one of the tokens from server config
- Set `verify_tls: true` if using a valid certificate (Let's Encrypt)

### Step 3: Run as Administrator

**Option A: Command Prompt (Admin)**

1. Press `Win + X`, select "Terminal (Admin)" or "Command Prompt (Admin)"
2. Navigate to the VPN folder:
   ```cmd
   cd C:\VPN
   ```
3. Run the client:
   ```cmd
   vpn-client.exe -config client.yaml
   ```

**Option B: PowerShell (Admin)**

1. Press `Win + X`, select "Windows PowerShell (Admin)"
2. Navigate and run:
   ```powershell
   cd C:\VPN
   .\vpn-client.exe -config client.yaml
   ```

### Step 4: Verify Connection

You should see output like:

```
time=2024-01-15T10:30:00.000Z level=INFO msg="WS-VPN Client starting" version=1.0.0
time=2024-01-15T10:30:00.100Z level=INFO msg="connecting to VPN server" url=wss://...
time=2024-01-15T10:30:00.500Z level=INFO msg="TUN device created" name=WS-VPN mtu=1420
time=2024-01-15T10:30:00.600Z level=INFO msg="connected to VPN" assigned_ip=10.100.0.2 subnet=10.100.0.0/24
```

### Step 5: (Optional) Create a Batch File for Easy Start

Create `C:\VPN\start-vpn.bat`:

```batch
@echo off
cd /d C:\VPN
vpn-client.exe -config client.yaml
pause
```

Right-click the batch file and select "Run as administrator".

---

## Testing the VPN

### Test 1: Ping the Server

From the Windows client:

```cmd
ping 10.100.0.1
```

Expected output:

```
Pinging 10.100.0.1 with 32 bytes of data:
Reply from 10.100.0.1: bytes=32 time=15ms TTL=64
Reply from 10.100.0.1: bytes=32 time=14ms TTL=64
```

### Test 2: Check Assigned IP

```cmd
ipconfig
```

Look for the "WS-VPN" adapter:

```
Ethernet adapter WS-VPN:
   IPv4 Address. . . . . . . . . . . : 10.100.0.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
```

### Test 3: Ping Between Clients

If you have two Windows clients connected:

- Client 1 (10.100.0.2): `ping 10.100.0.3`
- Client 2 (10.100.0.3): `ping 10.100.0.2`

### Test 4: Check Server Health

From your web browser or curl:

```
https://YOUR-SERVER-IP:443/health
```

(Accept the self-signed certificate warning if testing)

---

## Troubleshooting

### Server Issues

#### "Failed to create TUN device"

```bash
# Check if tun module is loaded
lsmod | grep tun

# Load it if not
sudo modprobe tun

# Check if running as root
whoami
```

#### "Address already in use"

```bash
# Find what's using port 443
sudo ss -tlnp | grep 443
sudo lsof -i :443

# Stop the conflicting service or use a different port
```

#### "Permission denied" for certificate files

```bash
sudo chmod 600 /etc/vpn/server.key
sudo chmod 644 /etc/vpn/server.crt
sudo chown root:root /etc/vpn/*
```

### Client Issues

#### "Failed to create TUN device"

1. Ensure running as Administrator
2. Try restarting Windows
3. Check if another VPN is running (disable it first)

#### "Connection refused"

1. Verify server is running: `sudo systemctl status vpn-server`
2. Check firewall allows port 443
3. Verify server IP/domain is correct

#### "Certificate verify failed"

1. Set `verify_tls: false` in client config (testing only!)
2. Or install the server's certificate on the client

#### "Authentication failed"

1. Verify the token in client config matches server config exactly
2. Check for trailing spaces or newlines in the token

#### Slow Connection / Packet Loss

1. Check MTU settings (try reducing to 1400)
2. Check for network congestion
3. Enable debug logging: `level: "debug"`

### Viewing Logs

**Server:**

```bash
# If running as service
sudo journalctl -u vpn-server -f

# If running manually, logs appear in console
```

**Client:**

Logs appear in the console window.

For debug output, change `level: "info"` to `level: "debug"` in the config.

---

## Security Recommendations

1. **Use strong tokens**: Generate with `openssl rand -hex 32`
2. **Use valid TLS certificates**: Let's Encrypt is free
3. **Set `verify_tls: true`** in production
4. **Regularly rotate tokens**: Change tokens periodically
5. **Monitor logs**: Watch for failed authentication attempts
6. **Keep software updated**: Update the VPN software regularly

---

## Network Diagram

```
                     Internet
                        │
                        │ Port 443 (HTTPS/WSS)
                        ▼
               ┌────────────────┐
               │  Ubuntu Server │
               │   10.100.0.1   │
               │     (tun0)     │
               └───────┬────────┘
                       │
            ┌──────────┴──────────┐
            │                     │
     ┌──────▼──────┐       ┌──────▼──────┐
     │  Windows    │       │  Windows    │
     │  Client 1   │       │  Client 2   │
     │ 10.100.0.2  │       │ 10.100.0.3  │
     │  (WS-VPN)   │       │  (WS-VPN)   │
     └─────────────┘       └─────────────┘
```

---

## Quick Reference

### Server Commands

```bash
# Start server
sudo systemctl start vpn-server

# Stop server
sudo systemctl stop vpn-server

# Restart server
sudo systemctl restart vpn-server

# View logs
sudo journalctl -u vpn-server -f

# Check status
sudo systemctl status vpn-server
```

### Client Commands

```cmd
# Start client (run as admin)
vpn-client.exe -config client.yaml

# Start with debug logging
vpn-client.exe -config client.yaml -log-level debug
```

### Configuration Locations

| Component | Location |
|-----------|----------|
| Server binary | `/opt/vpn/vpn-server` |
| Server config | `/etc/vpn/server.yaml` |
| TLS certificate | `/etc/vpn/server.crt` |
| TLS key | `/etc/vpn/server.key` |
| Client binary | `C:\VPN\vpn-client.exe` |
| Client config | `C:\VPN\client.yaml` |

---

## Support

For issues and feature requests, please open an issue on the GitHub repository.
