package server

import (
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
)

// ============================================================================
// IPPool Tests
// ============================================================================

func TestIPPoolCreation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name     string
		cidr     string
		serverIP string
		wantErr  bool
	}{
		{"valid /24", "10.100.0.0/24", "10.100.0.1", false},
		{"valid /16", "172.16.0.0/16", "172.16.0.1", false},
		{"valid /8", "10.0.0.0/8", "10.0.0.1", false},
		{"valid /30", "192.168.1.0/30", "192.168.1.1", false},
		{"invalid cidr", "invalid", "10.100.0.1", true},
		{"invalid cidr format", "10.100.0.0", "10.100.0.1", true},
		{"invalid server IP", "10.100.0.0/24", "invalid", true},
		{"empty cidr", "", "10.100.0.1", true},
		{"empty server IP", "10.100.0.0/24", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := NewIPPool(tt.cidr, tt.serverIP, logger)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if pool == nil {
					t.Error("expected pool, got nil")
				}
			}
		})
	}
}

func TestIPPoolAllocateSequential(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, err := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	if err != nil {
		t.Fatalf("failed to create IP pool: %v", err)
	}

	// First allocation should be .2 (skipping server at .1)
	ip1, err := pool.AllocateIP("client1", "")
	if err != nil {
		t.Fatalf("failed to allocate IP: %v", err)
	}
	expected1 := net.IPv4(10, 100, 0, 2)
	if !ip1.Equal(expected1) {
		t.Errorf("expected %s, got %s", expected1, ip1)
	}

	// Second allocation should be .3
	ip2, err := pool.AllocateIP("client2", "")
	if err != nil {
		t.Fatalf("failed to allocate IP: %v", err)
	}
	expected2 := net.IPv4(10, 100, 0, 3)
	if !ip2.Equal(expected2) {
		t.Errorf("expected %s, got %s", expected2, ip2)
	}

	// Third allocation should be .4
	ip3, err := pool.AllocateIP("client3", "")
	if err != nil {
		t.Fatalf("failed to allocate IP: %v", err)
	}
	expected3 := net.IPv4(10, 100, 0, 4)
	if !ip3.Equal(expected3) {
		t.Errorf("expected %s, got %s", expected3, ip3)
	}
}

func TestIPPoolAllocatePreferred(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, err := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	if err != nil {
		t.Fatalf("failed to create IP pool: %v", err)
	}

	// Request specific IP
	ip, err := pool.AllocateIP("client1", "10.100.0.50")
	if err != nil {
		t.Fatalf("failed to allocate preferred IP: %v", err)
	}
	expected := net.IPv4(10, 100, 0, 50)
	if !ip.Equal(expected) {
		t.Errorf("expected %s, got %s", expected, ip)
	}
}

func TestIPPoolAllocatePreferredInUse(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, err := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	if err != nil {
		t.Fatalf("failed to create IP pool: %v", err)
	}

	// Allocate 10.100.0.5
	_, err = pool.AllocateIP("client1", "10.100.0.5")
	if err != nil {
		t.Fatalf("failed to allocate: %v", err)
	}

	// Try to allocate same IP - should get different one
	ip2, err := pool.AllocateIP("client2", "10.100.0.5")
	if err != nil {
		t.Fatalf("failed to allocate: %v", err)
	}

	if ip2.Equal(net.IPv4(10, 100, 0, 5)) {
		t.Error("should not have allocated the same IP")
	}
}

func TestIPPoolAllocatePreferredOutOfSubnet(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, err := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	if err != nil {
		t.Fatalf("failed to create IP pool: %v", err)
	}

	// Request IP outside subnet - should get one from pool
	ip, err := pool.AllocateIP("client1", "192.168.1.100")
	if err != nil {
		t.Fatalf("failed to allocate: %v", err)
	}

	// Should be in 10.100.0.0/24
	_, subnet, _ := net.ParseCIDR("10.100.0.0/24")
	if !subnet.Contains(ip) {
		t.Errorf("IP %s is not in subnet %s", ip, subnet)
	}
}

func TestIPPoolAllocatePreferredServerIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, err := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	if err != nil {
		t.Fatalf("failed to create IP pool: %v", err)
	}

	// Try to request server IP - should get different one
	ip, err := pool.AllocateIP("client1", "10.100.0.1")
	if err != nil {
		t.Fatalf("failed to allocate: %v", err)
	}

	if ip.Equal(net.IPv4(10, 100, 0, 1)) {
		t.Error("should not have allocated server IP")
	}
}

func TestIPPoolRelease(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, err := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	if err != nil {
		t.Fatalf("failed to create IP pool: %v", err)
	}

	// Allocate
	ip1, _ := pool.AllocateIP("client1", "")
	ip2, _ := pool.AllocateIP("client2", "")

	// Release first IP
	pool.ReleaseIP(ip1)

	// Next allocation should reuse the released IP
	ip3, _ := pool.AllocateIP("client3", "")
	if !ip3.Equal(ip1) {
		t.Errorf("expected to reuse released IP %s, got %s", ip1, ip3)
	}

	// Release second IP
	pool.ReleaseIP(ip2)
}

func TestIPPoolExhaustion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	// /30 subnet has only 4 IPs: .0 (network), .1 (server), .2 and .3 (usable)
	pool, err := NewIPPool("192.168.1.0/30", "192.168.1.1", logger)
	if err != nil {
		t.Fatalf("failed to create IP pool: %v", err)
	}

	// Allocate .2
	ip1, err := pool.AllocateIP("client1", "")
	if err != nil {
		t.Fatalf("failed to allocate first IP: %v", err)
	}
	if !ip1.Equal(net.IPv4(192, 168, 1, 2)) {
		t.Errorf("expected 192.168.1.2, got %s", ip1)
	}

	// Allocate .3
	ip2, err := pool.AllocateIP("client2", "")
	if err != nil {
		t.Fatalf("failed to allocate second IP: %v", err)
	}
	if !ip2.Equal(net.IPv4(192, 168, 1, 3)) {
		t.Errorf("expected 192.168.1.3, got %s", ip2)
	}

	// Pool should be exhausted
	_, err = pool.AllocateIP("client3", "")
	if err == nil {
		t.Error("expected error for exhausted pool")
	}
}

func TestIPPoolConcurrentAllocation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, err := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	if err != nil {
		t.Fatalf("failed to create IP pool: %v", err)
	}

	var wg sync.WaitGroup
	allocatedIPs := make(chan string, 100)

	// Allocate 50 IPs concurrently
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			ip, err := pool.AllocateIP(string(rune('A'+clientID)), "")
			if err != nil {
				t.Errorf("failed to allocate: %v", err)
				return
			}
			allocatedIPs <- ip.String()
		}(i)
	}

	wg.Wait()
	close(allocatedIPs)

	// Check for duplicates
	seen := make(map[string]bool)
	for ip := range allocatedIPs {
		if seen[ip] {
			t.Errorf("duplicate IP allocated: %s", ip)
		}
		seen[ip] = true
	}
}

// ============================================================================
// Client Tests
// ============================================================================

func TestClientCreation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ip := net.IPv4(10, 100, 0, 2)

	client := NewClient("test-id", ip, nil, logger)

	if client.ID != "test-id" {
		t.Errorf("expected ID 'test-id', got %s", client.ID)
	}
	if !client.IP.Equal(ip) {
		t.Errorf("expected IP %s, got %s", ip, client.IP)
	}
	if client.SendChan == nil {
		t.Error("expected SendChan to be initialized")
	}
	if client.Done == nil {
		t.Error("expected Done channel to be initialized")
	}
}

func TestClientSend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	client := &Client{
		ID:       "test",
		IP:       net.IPv4(10, 100, 0, 2),
		SendChan: make(chan []byte, 2),
		Done:     make(chan struct{}),
		logger:   logger,
	}

	// Should succeed
	if !client.Send([]byte("packet1")) {
		t.Error("expected Send to succeed")
	}
	if !client.Send([]byte("packet2")) {
		t.Error("expected Send to succeed")
	}

	// Buffer full - should drop
	if client.Send([]byte("packet3")) {
		t.Error("expected Send to fail when buffer full")
	}

	// Verify packets in channel
	pkt1 := <-client.SendChan
	if string(pkt1) != "packet1" {
		t.Errorf("expected 'packet1', got %s", string(pkt1))
	}
	pkt2 := <-client.SendChan
	if string(pkt2) != "packet2" {
		t.Errorf("expected 'packet2', got %s", string(pkt2))
	}
}

func TestClientSendAfterClose(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	client := &Client{
		ID:       "test",
		IP:       net.IPv4(10, 100, 0, 2),
		SendChan: make(chan []byte, 1),
		Done:     make(chan struct{}),
		logger:   logger,
	}

	// Fill the buffer first
	client.SendChan <- []byte("fill")

	client.Close()

	// Send should fail after close (buffer is full, Done is closed)
	if client.Send([]byte("test")) {
		t.Error("expected Send to fail after close")
	}
}

func TestClientClose(t *testing.T) {
	client := &Client{
		ID:       "test",
		IP:       net.IPv4(10, 100, 0, 2),
		SendChan: make(chan []byte, 2),
		Done:     make(chan struct{}),
		Conn:     nil,
	}

	// Close should not panic
	client.Close()

	// Verify Done channel is closed
	select {
	case <-client.Done:
		// Expected
	default:
		t.Error("expected Done channel to be closed")
	}
}

func TestClientDoubleClose(t *testing.T) {
	client := &Client{
		ID:       "test",
		IP:       net.IPv4(10, 100, 0, 2),
		SendChan: make(chan []byte, 2),
		Done:     make(chan struct{}),
		Conn:     nil,
	}

	// Should not panic on double close
	client.Close()
	client.Close()
}

// ============================================================================
// ClientManager Tests
// ============================================================================

func TestClientManagerAddRemove(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, _ := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	manager := NewClientManager(pool, logger)

	ip := net.IPv4(10, 100, 0, 2)
	client := &Client{
		ID:       "test-client",
		IP:       ip,
		SendChan: make(chan []byte, 10),
		Done:     make(chan struct{}),
	}

	// Add
	manager.AddClient(client)
	if manager.ClientCount() != 1 {
		t.Errorf("expected 1 client, got %d", manager.ClientCount())
	}

	// Get by IP
	got := manager.GetClient(ip)
	if got != client {
		t.Error("expected to get the same client")
	}

	// Get by ID
	got = manager.GetClientByID("test-client")
	if got != client {
		t.Error("expected to get the same client by ID")
	}

	// Remove
	manager.RemoveClient(ip)
	if manager.ClientCount() != 0 {
		t.Errorf("expected 0 clients, got %d", manager.ClientCount())
	}

	// Get should return nil
	if manager.GetClient(ip) != nil {
		t.Error("expected nil after removal")
	}
}

func TestClientManagerGetNonExistent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, _ := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	manager := NewClientManager(pool, logger)

	// Get non-existent client by IP
	if manager.GetClient(net.IPv4(10, 100, 0, 99)) != nil {
		t.Error("expected nil for non-existent client")
	}

	// Get non-existent client by ID
	if manager.GetClientByID("non-existent") != nil {
		t.Error("expected nil for non-existent client ID")
	}
}

func TestClientManagerBroadcast(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, _ := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	manager := NewClientManager(pool, logger)

	ip := net.IPv4(10, 100, 0, 2)
	client := &Client{
		ID:       "test-client",
		IP:       ip,
		SendChan: make(chan []byte, 10),
		Done:     make(chan struct{}),
		logger:   logger,
	}

	manager.AddClient(client)

	// Send to existing client
	packet := []byte("test packet")
	if !manager.SendToClient(ip, packet) {
		t.Error("expected send to succeed")
	}

	// Verify packet was queued
	select {
	case received := <-client.SendChan:
		if string(received) != string(packet) {
			t.Errorf("expected %s, got %s", string(packet), string(received))
		}
	default:
		t.Error("expected packet in channel")
	}

	// Send to non-existent client
	if manager.SendToClient(net.IPv4(10, 100, 0, 99), packet) {
		t.Error("expected send to fail for non-existent client")
	}
}

func TestClientManagerGetAllClients(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, _ := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	manager := NewClientManager(pool, logger)

	// Add multiple clients
	for i := 2; i <= 5; i++ {
		ip := net.IPv4(10, 100, 0, byte(i))
		client := &Client{
			ID:       "client-" + string(rune('0'+i)),
			IP:       ip,
			SendChan: make(chan []byte, 10),
			Done:     make(chan struct{}),
		}
		manager.AddClient(client)
	}

	clients := manager.GetAllClients()
	if len(clients) != 4 {
		t.Errorf("expected 4 clients, got %d", len(clients))
	}
}

func TestClientManagerCloseAll(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, _ := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	manager := NewClientManager(pool, logger)

	// Add multiple clients
	for i := 2; i <= 5; i++ {
		ip := net.IPv4(10, 100, 0, byte(i))
		client := &Client{
			ID:       "client-" + string(rune('0'+i)),
			IP:       ip,
			SendChan: make(chan []byte, 10),
			Done:     make(chan struct{}),
		}
		manager.AddClient(client)
	}

	if manager.ClientCount() != 4 {
		t.Errorf("expected 4 clients, got %d", manager.ClientCount())
	}

	manager.CloseAll()

	if manager.ClientCount() != 0 {
		t.Errorf("expected 0 clients after CloseAll, got %d", manager.ClientCount())
	}
}

func TestClientManagerConcurrentAccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, _ := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	manager := NewClientManager(pool, logger)

	var wg sync.WaitGroup

	// Concurrent adds
	for i := 2; i <= 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := net.IPv4(10, 100, 0, byte(idx))
			client := &Client{
				ID:       "client-" + string(rune('0'+idx)),
				IP:       ip,
				SendChan: make(chan []byte, 10),
				Done:     make(chan struct{}),
			}
			manager.AddClient(client)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = manager.ClientCount()
			_ = manager.GetAllClients()
		}()
	}

	wg.Wait()
}

func TestClientManagerRemoveNonExistent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, _ := NewIPPool("10.100.0.0/24", "10.100.0.1", logger)
	manager := NewClientManager(pool, logger)

	// Should not panic when removing non-existent client
	manager.RemoveClient(net.IPv4(10, 100, 0, 99))
}

// ============================================================================
// IP Increment Helper Tests
// ============================================================================

func TestIncrementIP(t *testing.T) {
	tests := []struct {
		input    net.IP
		expected net.IP
	}{
		{net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)},
		{net.IPv4(10, 0, 0, 255), net.IPv4(10, 0, 1, 0)},
		{net.IPv4(10, 0, 255, 255), net.IPv4(10, 1, 0, 0)},
		{net.IPv4(10, 255, 255, 255), net.IPv4(11, 0, 0, 0)},
	}

	for _, tt := range tests {
		ip := make(net.IP, len(tt.input))
		copy(ip, tt.input)
		incrementIP(ip)
		if !ip.Equal(tt.expected) {
			t.Errorf("incrementIP(%s) = %s, expected %s", tt.input, ip, tt.expected)
		}
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkIPPoolAllocate(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, _ := NewIPPool("10.0.0.0/8", "10.0.0.1", logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.AllocateIP(string(rune('A'+i%26)), "")
	}
}

func BenchmarkClientManagerAddRemove(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	pool, _ := NewIPPool("10.0.0.0/8", "10.0.0.1", logger)
	manager := NewClientManager(pool, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		client := &Client{
			ID:       "client",
			IP:       ip,
			SendChan: make(chan []byte, 1),
			Done:     make(chan struct{}),
		}
		manager.AddClient(client)
		manager.RemoveClient(ip)
	}
}

func BenchmarkClientSend(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	client := &Client{
		ID:       "test",
		IP:       net.IPv4(10, 0, 0, 1),
		SendChan: make(chan []byte, 1000),
		Done:     make(chan struct{}),
		logger:   logger,
	}

	packet := make([]byte, 1420)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.Send(packet)
		select {
		case <-client.SendChan:
		default:
		}
	}
}
