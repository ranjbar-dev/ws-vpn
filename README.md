# WS-VPN

A WebSocket-based VPN solution that creates a virtual LAN network between Windows clients through an Ubuntu server.

## Features

- **WebSocket over HTTPS**: Uses port 443 with TLS encryption for transport
- **Layer 3 VPN**: TUN-based virtual network interface
- **Automatic Reconnection**: Exponential backoff (1s-60s) with infinite retry
- **IP Persistence**: Attempts to reassign the same IP on reconnection
- **Client-to-Client Communication**: Clients can communicate directly through the VPN
- **Simple Authentication**: Token-based authentication
- **Cross-Platform**: Server runs on Ubuntu, clients on Windows

## Architecture

```
┌─────────────────┐         WSS/443         ┌─────────────────┐
│  Windows Client │ ◄─────────────────────► │  Ubuntu Server  │
│   (10.100.0.2)  │                         │   (10.100.0.1)  │
│      TUN        │                         │      TUN        │
└─────────────────┘                         └─────────────────┘
        │                                           │
        │                                           │
        ▼                                           ▼
┌─────────────────┐         WSS/443         ┌─────────────────┐
│  Windows Client │ ◄─────────────────────► │   VPN Network   │
│   (10.100.0.3)  │                         │  10.100.0.0/24  │
│      TUN        │                         └─────────────────┘
└─────────────────┘
```

## Prerequisites

### Server (Ubuntu)
- Go 1.21 or later
- Root access (for TUN interface)
- TLS certificate and key

### Client (Windows)
- Go 1.21 or later (for building)
- Administrator privileges (for TUN interface)
- Wintun driver (automatically bundled with wireguard/tun)

## Building

### Build Server (Linux)
```bash
# On Linux or cross-compile from any OS
GOOS=linux GOARCH=amd64 go build -o vpn-server ./cmd/server
```

### Build Client (Windows)
```bash
# On Windows
go build -o vpn-client.exe ./cmd/client

# Cross-compile from Linux
GOOS=windows GOARCH=amd64 go build -o vpn-client.exe ./cmd/client
```

### Build Both
```bash
# Download dependencies first
go mod download

# Build for respective platforms
make build
```

## Configuration

### Server Configuration

Create `/etc/vpn/server.yaml`:

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
    - "your-secret-token-here"

logging:
  level: "info"
```

### Client Configuration

Create `client.yaml`:

```yaml
server:
  url: "wss://your-server-ip:443/vpn"
  verify_tls: false  # Set to true with valid certificates

auth:
  token: "your-secret-token-here"

vpn:
  interface_name: "WS-VPN"
  mtu: 1420

reconnect:
  min_backoff: "1s"
  max_backoff: "60s"

logging:
  level: "info"
```

## TLS Certificate Setup

### For Testing (Self-Signed)
```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout server.key \
  -out server.crt \
  -days 365 \
  -nodes \
  -subj "/CN=vpn-server"

# Copy to server
sudo mkdir -p /etc/vpn
sudo cp server.crt server.key /etc/vpn/
sudo chmod 600 /etc/vpn/server.key
```

### For Production
Use Let's Encrypt or a proper CA-signed certificate.

## Server Setup (Ubuntu)

1. **Enable IP Forwarding**
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

2. **Configure Firewall**
```bash
sudo ufw allow 443/tcp
```

3. **Create Configuration**
```bash
sudo mkdir -p /etc/vpn
sudo cp configs/server.yaml.example /etc/vpn/server.yaml
sudo nano /etc/vpn/server.yaml  # Edit with your settings
```

4. **Run Server**
```bash
sudo ./vpn-server -config /etc/vpn/server.yaml
```

### Systemd Service (Optional)

Create `/etc/systemd/system/vpn-server.service`:

```ini
[Unit]
Description=WS-VPN Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vpn-server -config /etc/vpn/server.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable vpn-server
sudo systemctl start vpn-server
```

## Client Setup (Windows)

1. **Copy Files**
   - `vpn-client.exe`
   - `client.yaml`

2. **Edit Configuration**
   - Set the server URL
   - Set the authentication token

3. **Run as Administrator**
```powershell
.\vpn-client.exe -config client.yaml
```

## Usage

### Testing Connectivity

After connecting:

```powershell
# From Client 1 (10.100.0.2)
ping 10.100.0.1      # Ping server
ping 10.100.0.3      # Ping Client 2

# Check assigned IP
ipconfig
```

### Health Check Endpoint

The server exposes a health endpoint:

```bash
curl -k https://your-server:443/health
```

Returns:
```json
{
  "status": "ok",
  "clients": 2,
  "packets_forwarded": 1234,
  "bytes_forwarded": 567890
}
```

## Protocol

### Control Messages (JSON over WebSocket Text)

**Authentication:**
```json
{"type": "auth", "token": "secret-token"}
```

**Reconnection:**
```json
{"type": "reconnect", "token": "secret-token", "previous_ip": "10.100.0.2"}
```

**Authentication Response:**
```json
{
  "type": "auth_response",
  "success": true,
  "assigned_ip": "10.100.0.2",
  "subnet": "10.100.0.0/24",
  "server_ip": "10.100.0.1",
  "mtu": 1420
}
```

**Keepalive:**
```json
{"type": "ping"}
{"type": "pong"}
```

### Data Messages (Binary over WebSocket Binary)

Raw IPv4 packets are sent as binary WebSocket messages.

## Troubleshooting

### Server

**"Failed to create TUN device"**
- Ensure you're running as root
- Check if the tun module is loaded: `lsmod | grep tun`
- Load if needed: `sudo modprobe tun`

**"Address already in use"**
- Another process is using port 443
- Check: `sudo netstat -tlnp | grep 443`

### Client

**"Failed to create TUN device"**
- Run as Administrator
- Ensure Wintun driver is available

**"Connection failed"**
- Verify server URL is correct
- Check if firewall allows outbound 443
- Verify TLS settings match (verify_tls)

**"Authentication failed"**
- Ensure token matches server configuration

### Debugging

Enable debug logging:
```bash
# Server
./vpn-server -config server.yaml -log-level debug

# Client
./vpn-client.exe -config client.yaml -log-level debug
```

## Security Considerations

1. **Use Strong Tokens**: Generate random tokens for production
2. **Enable TLS Verification**: Use valid certificates in production
3. **Firewall**: Only expose port 443
4. **IP Spoofing Prevention**: Server validates source IPs match assigned IPs

## Performance

- **Buffer Size**: 256 packets per client queue
- **MTU**: 1420 bytes (accounts for WebSocket overhead)
- **Keepalive**: 54-second ping interval

## Limitations

- IPv4 only (IPv6 not supported)
- No compression
- No split tunneling (all traffic through VPN)
- Single server (no failover)

## License

MIT License

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
