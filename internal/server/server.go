package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ws-vpn/internal/protocol"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 65535
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  65535,
	WriteBufferSize: 65535,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Server represents the VPN server
type Server struct {
	config        *Config
	tun           *TUNDevice
	clientManager *ClientManager
	ipPool        *IPPool
	httpServer    *http.Server
	logger        *slog.Logger
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup

	// Statistics
	packetsForwarded atomic.Uint64
	bytesForwarded   atomic.Uint64
}

// New creates a new VPN server
func New(config *Config, logger *slog.Logger) (*Server, error) {
	ipPool, err := NewIPPool(config.VPN.Subnet, config.VPN.ServerIP, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create IP pool: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:        config,
		ipPool:        ipPool,
		clientManager: NewClientManager(ipPool, logger),
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
	}

	return s, nil
}

// Start starts the VPN server
func (s *Server) Start() error {
	// Create TUN device
	tun, err := NewTUNDevice(
		s.config.VPN.InterfaceName,
		s.config.VPN.ServerIP,
		s.config.VPN.Subnet,
		s.config.VPN.MTU,
		s.logger,
	)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	s.tun = tun

	// Start TUN reader
	s.wg.Add(1)
	go s.tunReader()

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn", s.handleWebSocket)
	mux.HandleFunc("/health", s.handleHealth)

	s.httpServer = &http.Server{
		Addr:         s.config.Server.ListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	s.logger.Info("starting VPN server",
		"addr", s.config.Server.ListenAddr,
		"subnet", s.config.VPN.Subnet,
		"server_ip", s.config.VPN.ServerIP,
	)

	// Start HTTPS server
	go func() {
		if err := s.httpServer.ListenAndServeTLS(s.config.Server.TLSCert, s.config.Server.TLSKey); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTPS server error", "error", err)
		}
	}()

	return nil
}

// Stop gracefully stops the server
func (s *Server) Stop() error {
	s.logger.Info("stopping VPN server")
	s.cancel()

	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.Error("HTTP server shutdown error", "error", err)
	}

	// Close all clients
	s.clientManager.CloseAll()

	// Close TUN device
	if s.tun != nil {
		s.tun.Close()
	}

	// Wait for goroutines
	s.wg.Wait()

	s.logger.Info("VPN server stopped",
		"packets_forwarded", s.packetsForwarded.Load(),
		"bytes_forwarded", s.bytesForwarded.Load(),
	)

	return nil
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":            "ok",
		"clients":           s.clientManager.ClientCount(),
		"packets_forwarded": s.packetsForwarded.Load(),
		"bytes_forwarded":   s.bytesForwarded.Load(),
	})
}

// handleWebSocket handles incoming WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("WebSocket upgrade failed", "error", err, "remote", r.RemoteAddr)
		return
	}

	s.logger.Info("new WebSocket connection", "remote", r.RemoteAddr)

	// Handle authentication
	client, err := s.authenticateClient(conn, r.RemoteAddr)
	if err != nil {
		s.logger.Warn("authentication failed", "error", err, "remote", r.RemoteAddr)
		conn.Close()
		return
	}

	// Add client to manager
	s.clientManager.AddClient(client)

	// Start client handlers
	s.wg.Add(2)
	go s.clientReader(client)
	go s.clientWriter(client)
}

// authenticateClient handles the authentication handshake
func (s *Server) authenticateClient(conn *websocket.Conn, remoteAddr string) (*Client, error) {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	_, message, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to read auth message: %w", err)
	}

	msgType, err := protocol.ParseMessage(message)
	if err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	var token string
	var preferredIP string

	switch msgType {
	case protocol.TypeAuth:
		authMsg, err := protocol.ParseAuthMessage(message)
		if err != nil {
			return nil, fmt.Errorf("failed to parse auth message: %w", err)
		}
		token = authMsg.Token

	case protocol.TypeReconnect:
		reconnectMsg, err := protocol.ParseReconnectMessage(message)
		if err != nil {
			return nil, fmt.Errorf("failed to parse reconnect message: %w", err)
		}
		token = reconnectMsg.Token
		preferredIP = reconnectMsg.PreviousIP
		s.logger.Info("reconnection attempt", "preferred_ip", preferredIP, "remote", remoteAddr)

	default:
		return nil, fmt.Errorf("unexpected message type: %s", msgType)
	}

	// Validate token
	if !s.config.IsValidToken(token) {
		resp := protocol.NewAuthResponseError("invalid token")
		s.sendJSON(conn, resp)
		return nil, fmt.Errorf("invalid token")
	}

	// Allocate IP
	clientID := fmt.Sprintf("client-%s-%d", remoteAddr, time.Now().UnixNano())
	ip, err := s.ipPool.AllocateIP(clientID, preferredIP)
	if err != nil {
		resp := protocol.NewAuthResponseError(err.Error())
		s.sendJSON(conn, resp)
		return nil, fmt.Errorf("failed to allocate IP: %w", err)
	}

	// Send success response
	resp := protocol.NewAuthResponseSuccess(
		ip.String(),
		s.config.VPN.Subnet,
		s.config.VPN.ServerIP,
		s.config.VPN.MTU,
	)
	if err := s.sendJSON(conn, resp); err != nil {
		s.ipPool.ReleaseIP(ip)
		return nil, fmt.Errorf("failed to send auth response: %w", err)
	}

	conn.SetReadDeadline(time.Time{})

	client := NewClient(clientID, ip, conn, s.logger)
	s.logger.Info("client authenticated", "ip", ip.String(), "remote", remoteAddr)

	return client, nil
}

func (s *Server) sendJSON(conn *websocket.Conn, v interface{}) error {
	conn.SetWriteDeadline(time.Now().Add(writeWait))
	return conn.WriteJSON(v)
}

// clientReader reads packets from a client's WebSocket
func (s *Server) clientReader(client *Client) {
	defer s.wg.Done()
	defer s.clientManager.RemoveClient(client.IP)

	conn := client.Conn
	conn.SetReadLimit(maxMessageSize)
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-client.Done:
			return
		default:
		}

		messageType, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				s.logger.Warn("client read error", "error", err, "ip", client.IP.String())
			}
			return
		}

		if messageType == websocket.TextMessage {
			// Handle control messages
			s.handleControlMessage(client, message)
		} else if messageType == websocket.BinaryMessage {
			// Handle IP packet
			s.handlePacket(client, message)
		}
	}
}

// clientWriter writes packets to a client's WebSocket
func (s *Server) clientWriter(client *Client) {
	defer s.wg.Done()

	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-client.Done:
			return
		case packet := <-client.SendChan:
			client.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := client.Conn.WriteMessage(websocket.BinaryMessage, packet); err != nil {
				s.logger.Warn("client write error", "error", err, "ip", client.IP.String())
				return
			}
		case <-ticker.C:
			client.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := client.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				s.logger.Warn("ping failed", "error", err, "ip", client.IP.String())
				return
			}
		}
	}
}

// handleControlMessage handles JSON control messages
func (s *Server) handleControlMessage(client *Client, message []byte) {
	msgType, err := protocol.ParseMessage(message)
	if err != nil {
		s.logger.Warn("failed to parse control message", "error", err, "ip", client.IP.String())
		return
	}

	switch msgType {
	case protocol.TypePing:
		pong := protocol.NewPongMessage()
		data, _ := json.Marshal(pong)
		client.Conn.SetWriteDeadline(time.Now().Add(writeWait))
		client.Conn.WriteMessage(websocket.TextMessage, data)
	}
}

// handlePacket processes an IP packet from a client
func (s *Server) handlePacket(client *Client, packet []byte) {
	srcIP, dstIP, err := protocol.ParseIPPacket(packet)
	if err != nil {
		s.logger.Debug("invalid IP packet", "error", err, "ip", client.IP.String())
		return
	}

	// Verify source IP matches client's assigned IP (prevent spoofing)
	if !srcIP.Equal(client.IP) {
		s.logger.Warn("source IP mismatch", "expected", client.IP.String(), "got", srcIP.String())
		return
	}

	s.packetsForwarded.Add(1)
	s.bytesForwarded.Add(uint64(len(packet)))

	// Check if destination is in VPN subnet
	_, subnet, _ := net.ParseCIDR(s.config.VPN.Subnet)
	serverIP := net.ParseIP(s.config.VPN.ServerIP)

	// Check if this is a broadcast packet
	if s.isBroadcastAddress(dstIP, subnet) {
		// Broadcast to all clients except sender
		sent := s.clientManager.BroadcastToAll(client.IP, packet)
		s.logger.Debug("broadcast packet sent", "from", srcIP.String(), "to", dstIP.String(), "clients", sent)
		return
	}

	if dstIP.Equal(serverIP) {
		// Packet for the server - write to TUN
		if _, err := s.tun.Write(packet); err != nil {
			s.logger.Warn("failed to write to TUN", "error", err)
		}
	} else if subnet.Contains(dstIP) {
		// Packet for another client - forward via WebSocket
		if !s.clientManager.SendToClient(dstIP, packet) {
			s.logger.Debug("destination client not found", "dst", dstIP.String())
		}
	} else {
		// External packet - write to TUN for routing (if configured)
		if _, err := s.tun.Write(packet); err != nil {
			s.logger.Warn("failed to write to TUN", "error", err)
		}
	}
}

// isBroadcastAddress checks if an IP is a broadcast address
func (s *Server) isBroadcastAddress(ip net.IP, subnet *net.IPNet) bool {
	// Check for global broadcast
	if ip.Equal(net.IPv4bcast) {
		return true
	}

	// Check for subnet broadcast (e.g., 10.100.0.255 for 10.100.0.0/24)
	if subnet != nil {
		// Calculate broadcast address for subnet
		broadcast := make(net.IP, len(subnet.IP))
		for i := range subnet.IP {
			broadcast[i] = subnet.IP[i] | ^subnet.Mask[i]
		}
		if ip.Equal(broadcast) {
			return true
		}
	}

	// Check for limited broadcast
	if ip.Equal(net.ParseIP("255.255.255.255")) {
		return true
	}

	return false
}

// tunReader reads packets from the TUN device and routes them
func (s *Server) tunReader() {
	defer s.wg.Done()

	buf := make([]byte, s.config.VPN.MTU+100)
	_, subnet, _ := net.ParseCIDR(s.config.VPN.Subnet)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, err := s.tun.Read(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				s.logger.Warn("TUN read error", "error", err)
				continue
			}
		}

		if n == 0 {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		_, dstIP, err := protocol.ParseIPPacket(packet)
		if err != nil {
			s.logger.Debug("invalid IP packet from TUN", "error", err)
			continue
		}

		// Check if this is a broadcast
		if s.isBroadcastAddress(dstIP, subnet) {
			sent := s.clientManager.BroadcastToAll(nil, packet)
			s.logger.Debug("broadcast from TUN sent", "dst", dstIP.String(), "clients", sent)
			continue
		}

		// Route to appropriate client
		if !s.clientManager.SendToClient(dstIP, packet) {
			s.logger.Debug("destination client not found for TUN packet", "dst", dstIP.String())
		}
	}
}
