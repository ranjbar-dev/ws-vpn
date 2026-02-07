# VPN Server/Client MVP Specification

## Project Overview
WebSocket-based VPN solution creating a virtual LAN network between Windows clients through an Ubuntu server, using HTTPS on port 443 without payload encryption.

## Architecture

### Technology Stack
- **Protocol**: WebSocket over HTTPS (TLS for transport only, no payload encryption)
- **Port**: 443
- **Server OS**: Ubuntu Server
- **Client OS**: Windows
- **Language**: Go
- **Network Interface**: TUN device for Layer 3 VPN

### Components
1. **VPN Server** (Ubuntu)
2. **VPN Client** (Windows)
3. **Shared Protocol** (common packet structures)

## Core Features Required

### 1. Server Features

#### Network Management
- Create and manage TUN interface (e.g., `tun0`)
- Assign subnet for VPN network (e.g., `10.100.0.0/24`)
- Server gets first IP (e.g., `10.100.0.1`)
- Dynamically assign IPs to clients (e.g., `10.100.0.2`, `10.100.0.3`, etc.)
- Maintain routing table of client IPs to WebSocket connections
- Forward packets between clients based on destination IP

#### WebSocket Server
- Listen on port 443 with TLS
- Accept WebSocket connections from clients
- Handle client authentication (simple token-based)
- Maintain active client registry (IP → WebSocket mapping)
- Handle client disconnections and cleanup

#### Packet Handling
- Read IP packets from TUN interface
- Determine destination client from packet destination IP
- Send packet through appropriate client's WebSocket connection
- Receive packets from WebSocket clients
- Write packets to TUN interface for local processing or forward to other clients

#### Configuration
- Configurable via YAML/JSON file:
  - Listen address and port
  - TLS certificate and key paths
  - VPN subnet (CIDR)
  - Authentication tokens
  - MTU settings
  - Log level

#### Logging & Monitoring
- Client connection/disconnection events
- IP assignment logs
- Packet forwarding statistics
- Error logging

### 2. Client Features (Windows)

#### Network Management
- Create and manage TUN interface using `wintun.dll`
- Receive IP address from server during handshake
- Configure assigned IP on TUN interface
- Set appropriate routes for VPN subnet

#### WebSocket Client
- Connect to server via WSS (WebSocket Secure)
- Authenticate using configured token
- Handle handshake to receive assigned IP

#### Reconnection Mechanism (Critical)
- Exponential backoff retry strategy
- Initial retry: 1 second
- Max retry interval: 60 seconds
- Infinite retry attempts
- Preserve assigned IP during reconnection if possible
- Resume packet forwarding after reconnection
- Log all reconnection attempts

#### Packet Handling
- Read IP packets from TUN interface
- Send packets to server via WebSocket
- Receive packets from WebSocket
- Write packets to TUN interface

#### Configuration
- Configurable via YAML/JSON file:
  - Server URL (wss://server-ip:443)
  - Authentication token
  - Local TUN interface name
  - MTU settings
  - Reconnection settings (min/max backoff)
  - Log level

#### Windows-Specific
- Run as Windows service (optional but recommended)
- Handle Windows network interface management
- Proper cleanup on shutdown

### 3. Protocol Specification

#### WebSocket Message Types

**Control Messages (JSON)**:
```json
// Client → Server: Authentication
{
  "type": "auth",
  "token": "secret-token-here"
}

// Server → Client: Authentication Response + IP Assignment
{
  "type": "auth_response",
  "success": true,
  "assigned_ip": "10.100.0.2",
  "subnet": "10.100.0.0/24",
  "server_ip": "10.100.0.1",
  "mtu": 1420
}

// Bidirectional: Heartbeat/Keepalive
{
  "type": "ping"
}
{
  "type": "pong"
}

// Client → Server: Reconnection with previous IP
{
  "type": "reconnect",
  "token": "secret-token-here",
  "previous_ip": "10.100.0.2"
}
```

**Data Messages (Binary)**:
- Raw IP packets
- No additional framing needed (WebSocket handles framing)
- Binary WebSocket messages contain complete IP packets

#### Connection Flow

**Initial Connection**:
1. Client connects to wss://server:443
2. Client sends `auth` message
3. Server validates token
4. Server assigns IP from pool
5. Server sends `auth_response` with assigned IP
6. Client configures TUN interface with assigned IP
7. Data forwarding begins

**Reconnection Flow**:
1. Client detects disconnection
2. Client waits (exponential backoff)
3. Client connects to wss://server:443
4. Client sends `reconnect` message with previous IP
5. Server validates and attempts to reassign same IP (if available)
6. Server sends `auth_response` (same or new IP)
7. Client reconfigures TUN if IP changed
8. Data forwarding resumes

### 4. IP Packet Routing Logic

#### Server Routing
```
1. Read packet from TUN interface
2. Parse destination IP from packet header
3. If destination IP is in VPN subnet:
   a. Look up client WebSocket by destination IP
   b. Send packet through that WebSocket
4. If no client found, drop packet (log warning)

5. Receive packet from client WebSocket
6. Parse destination IP from packet header
7. If destination is server IP (10.100.0.1):
   a. Write to TUN interface (local processing)
8. Else if destination is another client:
   a. Look up destination client WebSocket
   b. Forward packet to that WebSocket
9. Else:
   a. Write to TUN interface (internet routing if configured)
```

#### Client Routing
```
1. Read packet from TUN interface
2. Send packet to server via WebSocket

3. Receive packet from server WebSocket
4. Write packet to TUN interface
```

### 5. Implementation Requirements

#### Dependencies
- **Server**: 
  - `github.com/gorilla/websocket` - WebSocket server
  - `github.com/songgao/water` - TUN interface (Linux)
  - `gopkg.in/yaml.v3` or `encoding/json` - Configuration
  
- **Client**:
  - `github.com/gorilla/websocket` - WebSocket client
  - `golang.zx2c4.com/wireguard/tun` - TUN interface (Windows/Wintun)
  - `gopkg.in/yaml.v3` or `encoding/json` - Configuration

#### TUN Interface Setup

**Server (Linux)**:
- Use `water` library or `os/exec` with `ip tuntap` commands
- Set IP: `ip addr add 10.100.0.1/24 dev tun0`
- Bring up: `ip link set tun0 up`

**Client (Windows)**:
- Use Wintun library (requires wintun.dll)
- Configure interface using Windows API or `netsh` commands
- Set IP and routes programmatically

#### Packet Reading/Writing
- Read packets in goroutines (continuous loop)
- Use channels for packet queuing if needed
- Handle MTU properly (default 1420 to account for overhead)
- Parse IP headers to extract source/destination IPs

#### Error Handling
- Graceful shutdown on SIGTERM/SIGINT
- Proper cleanup of TUN interfaces
- Connection timeout handling
- Invalid packet handling (drop and log)

### 6. Security Considerations

- TLS certificate validation on client (or allow insecure for testing)
- Token-based authentication (simple shared secret)
- No IP spoofing allowed (server validates source IP matches assigned IP)
- Rate limiting considerations (optional for MVP)

### 7. Testing Requirements

#### Server Testing
- Can create TUN interface
- Can accept WebSocket connections
- Can assign IPs sequentially
- Can route packets between two clients
- Can handle client disconnections
- Can reassign IPs on reconnection

#### Client Testing
- Can connect to server
- Can receive IP assignment
- Can configure TUN interface
- Can send/receive packets
- Reconnection works with exponential backoff
- Can handle server restarts

#### Integration Testing
- Ping between two Windows clients through VPN
- File sharing between clients (SMB)
- Remote desktop between clients (RDP)
- Internet traffic routing (optional)

### 8. Configuration Examples

#### Server Config (server.yaml)
```yaml
server:
  listen_addr: "0.0.0.0:443"
  tls_cert: "/etc/vpn/server.crt"
  tls_key: "/etc/vpn/server.key"
  
vpn:
  subnet: "10.100.0.0/24"
  server_ip: "10.100.0.1"
  mtu: 1420
  
auth:
  tokens:
    - "secret-token-1"
    - "secret-token-2"
    
logging:
  level: "info"  # debug, info, warn, error
```

#### Client Config (client.yaml)
```yaml
server:
  url: "wss://your-server-ip:443"
  verify_tls: false  # true in production with valid cert
  
auth:
  token: "secret-token-1"
  
vpn:
  interface_name: "VPN"
  mtu: 1420
  
reconnect:
  min_backoff: 1s
  max_backoff: 60s
  
logging:
  level: "info"
```

### 9. File Structure

```
vpn-project/
├── cmd/
│   ├── server/
│   │   └── main.go          # Server entry point
│   └── client/
│       └── main.go          # Client entry point
├── internal/
│   ├── protocol/
│   │   └── messages.go      # Shared message structures
│   ├── server/
│   │   ├── config.go        # Server configuration
│   │   ├── server.go        # Server implementation
│   │   ├── client_manager.go  # Client registry
│   │   └── tun_linux.go     # TUN interface for Linux
│   └── client/
│       ├── config.go        # Client configuration
│       ├── client.go        # Client implementation
│       ├── reconnect.go     # Reconnection logic
│       └── tun_windows.go   # TUN interface for Windows
├── configs/
│   ├── server.yaml.example
│   └── client.yaml.example
├── go.mod
├── go.sum
└── README.md
```

### 10. Deliverables

1. **Server binary**: Runs on Ubuntu, creates VPN network
2. **Client binary**: Runs on Windows, connects to VPN
3. **Configuration files**: Examples for both server and client
4. **README.md**: Setup and usage instructions
5. **Build scripts**: For cross-compilation (Linux server, Windows client)

### 11. Success Criteria

- [ ] Two Windows clients can ping each other through VPN
- [ ] Client automatically reconnects when connection drops
- [ ] Server handles multiple clients (at least 10)
- [ ] Packet forwarding works correctly between clients
- [ ] Configuration is easy to modify
- [ ] Logs provide useful debugging information
- [ ] Clean shutdown without leaving orphaned interfaces

### 12. Optional Enhancements (Post-MVP)

- Web UI for server monitoring
- Dynamic routing (BGP-like)
- Traffic shaping/QoS
- Client-to-client direct connections (P2P mode)
- Multiple server support (load balancing)
- Persistent IP assignment (based on client ID)
- Compression
- Authentication via API instead of static tokens

---

## Implementation Notes for Claude Code

- Use standard Go project layout
- Write clean, documented code
- Use structured logging (e.g., `log/slog`)
- Handle errors explicitly
- Use contexts for graceful shutdown
- Write unit tests for protocol parsing
- Keep packet handling performant (minimize allocations)
- Use goroutines appropriately with proper synchronization

## Additional Technical Details

### IP Header Parsing
The server and client need to parse IP packet headers to determine routing. Here's the minimal IPv4 header structure needed:

```go
// IPv4 header (first 20 bytes minimum)
// Byte 0: Version (4 bits) + IHL (4 bits)
// Bytes 12-15: Source IP
// Bytes 16-19: Destination IP

func parseIPPacket(packet []byte) (srcIP, dstIP net.IP, err error) {
    if len(packet) < 20 {
        return nil, nil, errors.New("packet too short")
    }
    srcIP = net.IPv4(packet[12], packet[13], packet[14], packet[15])
    dstIP = net.IPv4(packet[16], packet[17], packet[18], packet[19])
    return srcIP, dstIP, nil
}
```

### Client IP Assignment Logic (Server)
```go
// Simple sequential assignment from subnet
// Track assigned IPs in a map
// On reconnect, try to reassign same IP if available
// If not available, assign next available IP

type IPPool struct {
    subnet    *net.IPNet
    assigned  map[string]bool  // IP string -> assigned
    nextIP    net.IP
}
```

### Reconnection Backoff Algorithm (Client)
```go
backoff := time.Second  // Start at 1 second
maxBackoff := 60 * time.Second

for {
    err := connect()
    if err == nil {
        backoff = time.Second  // Reset on success
        break
    }
    
    log.Printf("Connection failed, retrying in %v", backoff)
    time.Sleep(backoff)
    
    backoff *= 2  // Exponential backoff
    if backoff > maxBackoff {
        backoff = maxBackoff
    }
}
```

### Goroutine Structure

**Server**:
- Main goroutine: WebSocket server accept loop
- Per-client goroutines:
  - WebSocket read loop (receive packets from client)
  - WebSocket write loop (send packets to client via channel)
- TUN read goroutine: Read packets from TUN, route to clients

**Client**:
- Main goroutine: Connection management and reconnection
- WebSocket read goroutine: Receive packets from server
- WebSocket write goroutine: Send packets to server via channel
- TUN read goroutine: Read packets from TUN interface
- TUN write goroutine: Write packets to TUN interface via channel

### Performance Considerations

- Use buffered channels for packet queuing (buffer size: 256-1024)
- Avoid allocations in hot path (reuse buffers)
- Use `sync.Pool` for packet buffers if needed
- Monitor goroutine count and memory usage
- Set reasonable timeouts for WebSocket operations
- Use `SetReadDeadline`/`SetWriteDeadline` appropriately

### Windows-Specific Considerations

**Running as Service**:
- Use `golang.org/x/sys/windows/svc` for Windows service support
- Handle service control signals properly
- Log to Windows Event Log or file (not stdout)

**Administrator Privileges**:
- Client must run as Administrator to create TUN interface
- Add UAC manifest if building GUI version

**Wintun DLL**:
- Include wintun.dll with client distribution
- Load from executable directory or system path
- Version 0.14 or higher recommended

### TLS Certificate Generation (for testing)

```bash
# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=vpn-server"

# For production, use Let's Encrypt or proper CA-signed certificate
```

### Deployment Considerations

**Server (Ubuntu)**:
```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# Install as systemd service
sudo systemctl enable vpn-server
sudo systemctl start vpn-server

# Firewall rules
sudo ufw allow 443/tcp
```

**Client (Windows)**:
```powershell
# Run as Administrator
# Install wintun.dll to System32 or app directory
# Configure firewall to allow VPN client
# Optionally install as Windows service
```

### Monitoring and Debugging

**Key Metrics to Log**:
- Active client count
- Packets forwarded per second
- Bytes transferred per client
- Connection/disconnection events
- Reconnection attempts and success rate
- Dropped packets (destination unreachable)

**Debug Mode**:
- Packet-level logging (source/destination IPs)
- WebSocket frame logging
- TUN interface state
- IP assignment history

### Error Scenarios to Handle

1. **Client disconnects abruptly**: Server should detect and clean up
2. **Server restarts**: Clients should reconnect automatically
3. **Network partition**: Both sides should handle timeout gracefully
4. **IP exhaustion**: Server should reject new clients or reuse IPs
5. **Invalid packets**: Drop and log, don't crash
6. **TUN interface creation fails**: Proper error message and exit
7. **Certificate issues**: Clear error messages for TLS problems
8. **Port already in use**: Detect and report clearly

---

This MVP should provide a fully functional VPN solution that creates a virtual LAN between your Windows systems through an Ubuntu server using WebSocket over HTTPS on port 443.
