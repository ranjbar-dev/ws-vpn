package server

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/gorilla/websocket"
)

// Client represents a connected VPN client
type Client struct {
	ID         string
	IP         net.IP
	Conn       *websocket.Conn
	SendChan   chan []byte
	Done       chan struct{}
	mu         sync.Mutex
	logger     *slog.Logger
}

// NewClient creates a new client instance
func NewClient(id string, ip net.IP, conn *websocket.Conn, logger *slog.Logger) *Client {
	return &Client{
		ID:       id,
		IP:       ip,
		Conn:     conn,
		SendChan: make(chan []byte, 256),
		Done:     make(chan struct{}),
		logger:   logger,
	}
}

// Send queues a packet to be sent to the client
func (c *Client) Send(packet []byte) bool {
	select {
	case c.SendChan <- packet:
		return true
	case <-c.Done:
		return false
	default:
		c.logger.Warn("client send buffer full, dropping packet", "client_ip", c.IP.String())
		return false
	}
}

// Close closes the client connection
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.Done:
		return
	default:
		close(c.Done)
		if c.Conn != nil {
			c.Conn.Close()
		}
	}
}

// IPPool manages IP address allocation
type IPPool struct {
	subnet   *net.IPNet
	serverIP net.IP
	assigned map[string]string // IP string -> client ID
	reserved map[string]string // IP string -> client ID (for reconnection)
	mu       sync.Mutex
	logger   *slog.Logger
}

// NewIPPool creates a new IP pool from a CIDR subnet
func NewIPPool(cidr string, serverIP string, logger *slog.Logger) (*IPPool, error) {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	srvIP := net.ParseIP(serverIP)
	if srvIP == nil {
		return nil, fmt.Errorf("invalid server IP: %s", serverIP)
	}

	return &IPPool{
		subnet:   subnet,
		serverIP: srvIP,
		assigned: make(map[string]string),
		reserved: make(map[string]string),
		logger:   logger,
	}, nil
}

// AllocateIP assigns an IP address to a client
func (p *IPPool) AllocateIP(clientID string, preferredIP string) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to use preferred IP if available
	if preferredIP != "" {
		ip := net.ParseIP(preferredIP)
		if ip != nil && p.subnet.Contains(ip) && !ip.Equal(p.serverIP) {
			if _, exists := p.assigned[ip.String()]; !exists {
				p.assigned[ip.String()] = clientID
				p.logger.Info("allocated preferred IP", "ip", ip.String(), "client", clientID)
				return ip, nil
			}
		}
	}

	// Find next available IP
	ip := p.nextAvailableIP()
	if ip == nil {
		return nil, fmt.Errorf("IP pool exhausted")
	}

	p.assigned[ip.String()] = clientID
	p.logger.Info("allocated new IP", "ip", ip.String(), "client", clientID)
	return ip, nil
}

// ReleaseIP releases an IP address back to the pool
func (p *IPPool) ReleaseIP(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.assigned, ip.String())
	p.logger.Info("released IP", "ip", ip.String())
}

// ReserveIP reserves an IP for reconnection
func (p *IPPool) ReserveIP(ip net.IP, clientID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reserved[ip.String()] = clientID
}

// ClearReservation clears a reserved IP
func (p *IPPool) ClearReservation(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.reserved, ip.String())
}

func (p *IPPool) nextAvailableIP() net.IP {
	// Start from the first usable IP in the subnet
	ip := make(net.IP, len(p.subnet.IP))
	copy(ip, p.subnet.IP)

	// Increment to get first host IP
	incrementIP(ip)

	for p.subnet.Contains(ip) {
		ipStr := ip.String()
		if !ip.Equal(p.serverIP) {
			if _, assigned := p.assigned[ipStr]; !assigned {
				result := make(net.IP, len(ip))
				copy(result, ip)
				return result
			}
		}
		incrementIP(ip)
	}
	return nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// ClientManager manages all connected clients
type ClientManager struct {
	clients  map[string]*Client // IP string -> Client
	ipPool   *IPPool
	mu       sync.RWMutex
	logger   *slog.Logger
}

// NewClientManager creates a new client manager
func NewClientManager(ipPool *IPPool, logger *slog.Logger) *ClientManager {
	return &ClientManager{
		clients: make(map[string]*Client),
		ipPool:  ipPool,
		logger:  logger,
	}
}

// AddClient adds a new client
func (m *ClientManager) AddClient(client *Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[client.IP.String()] = client
	m.logger.Info("client added", "ip", client.IP.String(), "id", client.ID, "total_clients", len(m.clients))
}

// RemoveClient removes a client
func (m *ClientManager) RemoveClient(ip net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if client, exists := m.clients[ip.String()]; exists {
		client.Close()
		delete(m.clients, ip.String())
		m.ipPool.ReleaseIP(ip)
		m.logger.Info("client removed", "ip", ip.String(), "total_clients", len(m.clients))
	}
}

// GetClient returns a client by IP
func (m *ClientManager) GetClient(ip net.IP) *Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clients[ip.String()]
}

// GetClientByID returns a client by ID
func (m *ClientManager) GetClientByID(id string) *Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, client := range m.clients {
		if client.ID == id {
			return client
		}
	}
	return nil
}

// SendToClient sends a packet to a specific client by destination IP
func (m *ClientManager) SendToClient(dstIP net.IP, packet []byte) bool {
	m.mu.RLock()
	client := m.clients[dstIP.String()]
	m.mu.RUnlock()

	if client != nil {
		return client.Send(packet)
	}
	return false
}

// BroadcastToAll sends a packet to all connected clients except the sender
func (m *ClientManager) BroadcastToAll(senderIP net.IP, packet []byte) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sent := 0
	for ipStr, client := range m.clients {
		// Don't send back to sender
		if senderIP != nil && ipStr == senderIP.String() {
			continue
		}
		if client.Send(packet) {
			sent++
		}
	}
	return sent
}

// ClientCount returns the number of connected clients
func (m *ClientManager) ClientCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.clients)
}

// GetAllClients returns a copy of all clients
func (m *ClientManager) GetAllClients() []*Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	clients := make([]*Client, 0, len(m.clients))
	for _, c := range m.clients {
		clients = append(clients, c)
	}
	return clients
}

// CloseAll closes all client connections
func (m *ClientManager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, client := range m.clients {
		client.Close()
	}
	m.clients = make(map[string]*Client)
	m.logger.Info("all clients disconnected")
}
