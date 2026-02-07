package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ws-vpn/internal/protocol"
)

const (
	// Internet connectivity check settings
	connectivityCheckTimeout = 5 * time.Second
	connectivityCheckRetries = 3
	connectivityRetryDelay   = 5 * time.Second
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 65535
)

// Client represents the VPN client
type Client struct {
	config      *Config
	conn        *websocket.Conn
	tun         *TUNDevice
	reconnector *ReconnectionManager
	logger      *slog.Logger
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	connMu      sync.Mutex

	// Connection state
	assignedIP string
	subnet     string
	serverIP   string
	mtu        int
	connected  atomic.Bool

	// Channels
	sendChan chan []byte
	done     chan struct{}

	// Statistics
	packetsSent     atomic.Uint64
	packetsReceived atomic.Uint64
	bytesSent       atomic.Uint64
	bytesReceived   atomic.Uint64
}

// New creates a new VPN client
func New(config *Config, logger *slog.Logger) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		config:      config,
		reconnector: NewReconnectionManager(config.Reconnect.MinBackoff, config.Reconnect.MaxBackoff, logger),
		logger:      logger,
		ctx:         ctx,
		cancel:      cancel,
		sendChan:    make(chan []byte, 256),
		done:        make(chan struct{}),
	}
}

// Start starts the VPN client with automatic reconnection
func (c *Client) Start() error {
	c.logger.Info("starting VPN client", "server", c.config.Server.URL)

	// Main connection loop with reconnection
	go c.connectionLoop()

	return nil
}

// connectionLoop manages the connection with automatic reconnection
func (c *Client) connectionLoop() {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("panic in connectionLoop recovered",
				"panic", r,
				"stack", string(debug.Stack()),
			)
			// Restart the connection loop after panic
			go c.connectionLoop()
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Check internet connectivity before attempting to connect
		if !c.waitForInternetConnectivity() {
			return // Context cancelled
		}

		err := c.connect()
		if err != nil {
			c.reconnector.OnConnectionFailure(err)

			if !c.reconnector.WaitForReconnect(c.ctx) {
				return
			}
			continue
		}

		// Connection successful
		c.reconnector.OnConnectionSuccess(c.assignedIP)

		// Run the connection until it fails
		c.runConnection()

		// Connection lost, prepare for reconnection
		c.connected.Store(false)
		c.closeTUN()

		if !c.reconnector.ShouldReconnect(c.ctx) {
			return
		}

		if !c.reconnector.WaitForReconnect(c.ctx) {
			return
		}
	}
}

// checkInternetConnectivity checks if there is internet connectivity
func (c *Client) checkInternetConnectivity() bool {
	// Try to connect to common DNS servers to check connectivity
	targets := []string{
		"8.8.8.8:53",       // Google DNS
		"1.1.1.1:53",       // Cloudflare DNS
		"208.67.222.222:53", // OpenDNS
	}

	for _, target := range targets {
		conn, err := net.DialTimeout("tcp", target, connectivityCheckTimeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// waitForInternetConnectivity waits until internet is available
func (c *Client) waitForInternetConnectivity() bool {
	retryCount := 0

	for {
		select {
		case <-c.ctx.Done():
			return false
		default:
		}

		if c.checkInternetConnectivity() {
			if retryCount > 0 {
				c.logger.Info("internet connectivity restored")
			}
			return true
		}

		retryCount++
		c.logger.Warn("no internet connectivity, waiting...",
			"retry", retryCount,
			"retry_delay", connectivityRetryDelay,
		)

		select {
		case <-c.ctx.Done():
			return false
		case <-time.After(connectivityRetryDelay):
		}
	}
}

// connect establishes a connection to the VPN server
func (c *Client) connect() error {
	c.logger.Info("connecting to VPN server", "url", c.config.Server.URL)

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !c.config.Server.VerifyTLS,
		},
		HandshakeTimeout: 30 * time.Second,
	}

	conn, _, err := dialer.Dial(c.config.Server.URL, http.Header{})
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	// Authenticate
	if err := c.authenticate(); err != nil {
		conn.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Setup TUN device
	if err := c.setupTUN(); err != nil {
		conn.Close()
		return fmt.Errorf("TUN setup failed: %w", err)
	}

	c.connected.Store(true)
	c.logger.Info("connected to VPN",
		"assigned_ip", c.assignedIP,
		"subnet", c.subnet,
		"server_ip", c.serverIP,
	)

	return nil
}

// authenticate performs the authentication handshake
func (c *Client) authenticate() error {
	var authMsg interface{}

	previousIP := c.reconnector.GetPreviousIP()
	if previousIP != "" {
		authMsg = protocol.NewReconnectMessage(c.config.Auth.Token, previousIP)
		c.logger.Debug("sending reconnect message", "previous_ip", previousIP)
	} else {
		authMsg = protocol.NewAuthMessage(c.config.Auth.Token)
		c.logger.Debug("sending auth message")
	}

	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	if err := c.conn.WriteJSON(authMsg); err != nil {
		return fmt.Errorf("failed to send auth message: %w", err)
	}

	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, message, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	resp, err := protocol.ParseAuthResponseMessage(message)
	if err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("authentication rejected: %s", resp.Error)
	}

	c.assignedIP = resp.AssignedIP
	c.subnet = resp.Subnet
	c.serverIP = resp.ServerIP
	c.mtu = resp.MTU

	c.conn.SetReadDeadline(time.Time{})

	return nil
}

// setupTUN creates and configures the TUN device
func (c *Client) setupTUN() error {
	// Close existing TUN if any
	c.closeTUN()

	tun, err := NewTUNDevice(c.config.VPN.InterfaceName, c.mtu, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}

	if err := tun.Configure(c.assignedIP, c.subnet, c.serverIP, c.mtu); err != nil {
		tun.Close()
		return fmt.Errorf("failed to configure TUN device: %w", err)
	}

	c.tun = tun
	return nil
}

// closeTUN closes the TUN device if it exists
func (c *Client) closeTUN() {
	if c.tun != nil {
		c.tun.Close()
		c.tun = nil
	}
}

// runConnection runs the main packet forwarding loops
func (c *Client) runConnection() {
	c.done = make(chan struct{})

	c.wg.Add(3)
	go c.wsReader()
	go c.wsWriter()
	go c.tunReader()

	// Wait for any goroutine to exit
	<-c.done

	// Signal all goroutines to stop
	close(c.done)

	// Close WebSocket
	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connMu.Unlock()

	c.wg.Wait()
}

// wsReader reads packets from the WebSocket and writes to TUN
func (c *Client) wsReader() {
	defer c.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("panic in wsReader recovered",
				"panic", r,
				"stack", string(debug.Stack()),
			)
		}
		select {
		case <-c.done:
		default:
			close(c.done)
		}
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.done:
			return
		default:
		}

		messageType, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.logger.Warn("WebSocket read error", "error", err)
			}
			return
		}

		if messageType == websocket.TextMessage {
			c.handleControlMessage(message)
		} else if messageType == websocket.BinaryMessage {
			c.handlePacket(message)
		}
	}
}

// wsWriter writes packets to the WebSocket
func (c *Client) wsWriter() {
	defer c.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("panic in wsWriter recovered",
				"panic", r,
				"stack", string(debug.Stack()),
			)
		}
	}()

	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.done:
			return
		case packet := <-c.sendChan:
			c.connMu.Lock()
			if c.conn == nil {
				c.connMu.Unlock()
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			err := c.conn.WriteMessage(websocket.BinaryMessage, packet)
			c.connMu.Unlock()

			if err != nil {
				c.logger.Warn("WebSocket write error", "error", err)
				return
			}

			c.packetsSent.Add(1)
			c.bytesSent.Add(uint64(len(packet)))

		case <-ticker.C:
			c.connMu.Lock()
			if c.conn == nil {
				c.connMu.Unlock()
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			err := c.conn.WriteMessage(websocket.PingMessage, nil)
			c.connMu.Unlock()

			if err != nil {
				c.logger.Warn("ping failed", "error", err)
				return
			}
		}
	}
}

// tunReader reads packets from TUN and sends to WebSocket
func (c *Client) tunReader() {
	defer c.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("panic in tunReader recovered",
				"panic", r,
				"stack", string(debug.Stack()),
			)
		}
	}()

	buf := make([]byte, c.mtu+100)

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.done:
			return
		default:
		}

		if c.tun == nil {
			return
		}

		n, err := c.tun.Read(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			case <-c.done:
				return
			default:
				c.logger.Warn("TUN read error", "error", err)
				continue
			}
		}

		if n == 0 {
			continue
		}

		if !protocol.IsIPv4Packet(buf[:n]) {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		select {
		case c.sendChan <- packet:
		case <-c.done:
			return
		default:
			c.logger.Warn("send buffer full, dropping packet")
		}
	}
}

// handleControlMessage processes control messages from the server
func (c *Client) handleControlMessage(message []byte) {
	msgType, err := protocol.ParseMessage(message)
	if err != nil {
		c.logger.Warn("failed to parse control message", "error", err)
		return
	}

	switch msgType {
	case protocol.TypePing:
		pong := protocol.NewPongMessage()
		data, _ := json.Marshal(pong)
		c.connMu.Lock()
		if c.conn != nil {
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			c.conn.WriteMessage(websocket.TextMessage, data)
		}
		c.connMu.Unlock()

	case protocol.TypePong:
		// Pong received, connection is alive
	}
}

// handlePacket processes an IP packet from the server
func (c *Client) handlePacket(packet []byte) {
	if c.tun == nil {
		return
	}

	if !protocol.IsIPv4Packet(packet) {
		return
	}

	if _, err := c.tun.Write(packet); err != nil {
		c.logger.Warn("failed to write to TUN", "error", err)
		return
	}

	c.packetsReceived.Add(1)
	c.bytesReceived.Add(uint64(len(packet)))
}

// Stop gracefully stops the client
func (c *Client) Stop() error {
	c.logger.Info("stopping VPN client")
	c.cancel()

	// Close connection
	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
	}
	c.connMu.Unlock()

	// Close TUN
	c.closeTUN()

	c.logger.Info("VPN client stopped",
		"packets_sent", c.packetsSent.Load(),
		"packets_received", c.packetsReceived.Load(),
		"bytes_sent", c.bytesSent.Load(),
		"bytes_received", c.bytesReceived.Load(),
	)

	return nil
}

// IsConnected returns whether the client is connected
func (c *Client) IsConnected() bool {
	return c.connected.Load()
}

// AssignedIP returns the assigned IP address
func (c *Client) AssignedIP() string {
	return c.assignedIP
}

// Stats returns connection statistics
func (c *Client) Stats() map[string]uint64 {
	return map[string]uint64{
		"packets_sent":     c.packetsSent.Load(),
		"packets_received": c.packetsReceived.Load(),
		"bytes_sent":       c.bytesSent.Load(),
		"bytes_received":   c.bytesReceived.Load(),
	}
}
