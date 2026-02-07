package protocol

import (
	"encoding/json"
	"net"
	"testing"
)

// ============================================================================
// AuthMessage Tests
// ============================================================================

func TestNewAuthMessage(t *testing.T) {
	msg := NewAuthMessage("test-token")

	if msg.Type != TypeAuth {
		t.Errorf("expected type %s, got %s", TypeAuth, msg.Type)
	}
	if msg.Token != "test-token" {
		t.Errorf("expected token 'test-token', got %s", msg.Token)
	}
}

func TestNewAuthMessageEmptyToken(t *testing.T) {
	msg := NewAuthMessage("")
	if msg.Token != "" {
		t.Errorf("expected empty token, got %s", msg.Token)
	}
	if msg.Type != TypeAuth {
		t.Errorf("expected type %s, got %s", TypeAuth, msg.Type)
	}
}

func TestNewAuthMessageSpecialCharacters(t *testing.T) {
	specialTokens := []string{
		"token with spaces",
		"token\twith\ttabs",
		"token\nwith\nnewlines",
		"token-with-dashes",
		"token_with_underscores",
		"token.with.dots",
		"token@with#special$chars%",
		"日本語トークン",
		"🔑🔐🔒",
	}

	for _, token := range specialTokens {
		t.Run(token, func(t *testing.T) {
			msg := NewAuthMessage(token)
			if msg.Token != token {
				t.Errorf("expected token %q, got %q", token, msg.Token)
			}

			// Verify JSON round-trip
			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			parsed, err := ParseAuthMessage(data)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}

			if parsed.Token != token {
				t.Errorf("round-trip failed: expected %q, got %q", token, parsed.Token)
			}
		})
	}
}

// ============================================================================
// ReconnectMessage Tests
// ============================================================================

func TestNewReconnectMessage(t *testing.T) {
	msg := NewReconnectMessage("test-token", "10.100.0.5")

	if msg.Type != TypeReconnect {
		t.Errorf("expected type %s, got %s", TypeReconnect, msg.Type)
	}
	if msg.Token != "test-token" {
		t.Errorf("expected token 'test-token', got %s", msg.Token)
	}
	if msg.PreviousIP != "10.100.0.5" {
		t.Errorf("expected previous IP '10.100.0.5', got %s", msg.PreviousIP)
	}
}

func TestNewReconnectMessageEmptyPreviousIP(t *testing.T) {
	msg := NewReconnectMessage("token", "")
	if msg.PreviousIP != "" {
		t.Errorf("expected empty previous IP, got %s", msg.PreviousIP)
	}
}

func TestNewReconnectMessageInvalidIP(t *testing.T) {
	// The message struct doesn't validate IPs, it just stores strings
	invalidIPs := []string{
		"not-an-ip",
		"999.999.999.999",
		"256.1.1.1",
		"1.2.3",
		"1.2.3.4.5",
		"",
		"   ",
	}

	for _, ip := range invalidIPs {
		msg := NewReconnectMessage("token", ip)
		if msg.PreviousIP != ip {
			t.Errorf("expected previous IP %q, got %q", ip, msg.PreviousIP)
		}
	}
}

// ============================================================================
// AuthResponseMessage Tests
// ============================================================================

func TestNewAuthResponseSuccess(t *testing.T) {
	msg := NewAuthResponseSuccess("10.100.0.2", "10.100.0.0/24", "10.100.0.1", 1420)

	if msg.Type != TypeAuthResponse {
		t.Errorf("expected type %s, got %s", TypeAuthResponse, msg.Type)
	}
	if !msg.Success {
		t.Error("expected success to be true")
	}
	if msg.AssignedIP != "10.100.0.2" {
		t.Errorf("expected assigned IP '10.100.0.2', got %s", msg.AssignedIP)
	}
	if msg.Subnet != "10.100.0.0/24" {
		t.Errorf("expected subnet '10.100.0.0/24', got %s", msg.Subnet)
	}
	if msg.ServerIP != "10.100.0.1" {
		t.Errorf("expected server IP '10.100.0.1', got %s", msg.ServerIP)
	}
	if msg.MTU != 1420 {
		t.Errorf("expected MTU 1420, got %d", msg.MTU)
	}
	if msg.Error != "" {
		t.Errorf("expected no error, got %s", msg.Error)
	}
}

func TestNewAuthResponseError(t *testing.T) {
	msg := NewAuthResponseError("invalid token")

	if msg.Type != TypeAuthResponse {
		t.Errorf("expected type %s, got %s", TypeAuthResponse, msg.Type)
	}
	if msg.Success {
		t.Error("expected success to be false")
	}
	if msg.Error != "invalid token" {
		t.Errorf("expected error 'invalid token', got %s", msg.Error)
	}
	if msg.AssignedIP != "" {
		t.Errorf("expected no assigned IP, got %s", msg.AssignedIP)
	}
}

func TestNewAuthResponseSuccessVariousMTUs(t *testing.T) {
	mtus := []int{576, 1280, 1420, 1500, 9000, 65535}

	for _, mtu := range mtus {
		msg := NewAuthResponseSuccess("10.0.0.1", "10.0.0.0/24", "10.0.0.1", mtu)
		if msg.MTU != mtu {
			t.Errorf("expected MTU %d, got %d", mtu, msg.MTU)
		}
	}
}

func TestNewAuthResponseSuccessVariousSubnets(t *testing.T) {
	subnets := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"10.100.0.0/24",
		"10.100.0.0/28",
		"10.100.0.0/30",
	}

	for _, subnet := range subnets {
		msg := NewAuthResponseSuccess("10.0.0.2", subnet, "10.0.0.1", 1420)
		if msg.Subnet != subnet {
			t.Errorf("expected subnet %s, got %s", subnet, msg.Subnet)
		}
	}
}

// ============================================================================
// Ping/Pong Tests
// ============================================================================

func TestNewPingMessage(t *testing.T) {
	msg := NewPingMessage()
	if msg.Type != TypePing {
		t.Errorf("expected type %s, got %s", TypePing, msg.Type)
	}
}

func TestNewPongMessage(t *testing.T) {
	msg := NewPongMessage()
	if msg.Type != TypePong {
		t.Errorf("expected type %s, got %s", TypePong, msg.Type)
	}
}

// ============================================================================
// ParseMessage Tests
// ============================================================================

func TestParseMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"auth", NewAuthMessage("token"), TypeAuth},
		{"reconnect", NewReconnectMessage("token", "10.0.0.1"), TypeReconnect},
		{"auth_response", NewAuthResponseSuccess("10.0.0.1", "10.0.0.0/24", "10.0.0.1", 1420), TypeAuthResponse},
		{"ping", NewPingMessage(), TypePing},
		{"pong", NewPongMessage(), TypePong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			msgType, err := ParseMessage(data)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}

			if msgType != tt.expected {
				t.Errorf("expected type %s, got %s", tt.expected, msgType)
			}
		})
	}
}

func TestParseMessageInvalidJSON(t *testing.T) {
	invalidInputs := []string{
		"invalid json",
		"{",
		"}",
		"",
		"   ",
		"{\"type\":",
		"{\"type\": }",
	}

	for _, input := range invalidInputs {
		t.Run(input, func(t *testing.T) {
			_, err := ParseMessage([]byte(input))
			if err == nil {
				t.Errorf("expected error for input %q", input)
			}
		})
	}
}

func TestParseMessageMissingType(t *testing.T) {
	data := []byte(`{"token": "test"}`)
	msgType, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != "" {
		t.Errorf("expected empty type, got %s", msgType)
	}
}

func TestParseMessageUnknownType(t *testing.T) {
	data := []byte(`{"type": "unknown_type"}`)
	msgType, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != "unknown_type" {
		t.Errorf("expected 'unknown_type', got %s", msgType)
	}
}

func TestParseMessageExtraFields(t *testing.T) {
	data := []byte(`{"type": "auth", "token": "test", "extra_field": "ignored"}`)
	msgType, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgType != TypeAuth {
		t.Errorf("expected type %s, got %s", TypeAuth, msgType)
	}
}

// ============================================================================
// ParseAuthMessage Tests
// ============================================================================

func TestParseAuthMessage(t *testing.T) {
	original := NewAuthMessage("secret-token")
	data, _ := json.Marshal(original)

	parsed, err := ParseAuthMessage(data)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if parsed.Token != original.Token {
		t.Errorf("expected token %s, got %s", original.Token, parsed.Token)
	}
}

func TestParseAuthMessageWrongType(t *testing.T) {
	data := []byte(`{"type": "ping"}`)
	_, err := ParseAuthMessage(data)
	if err == nil {
		t.Error("expected error for wrong message type")
	}
}

func TestParseAuthMessageInvalidJSON(t *testing.T) {
	_, err := ParseAuthMessage([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ============================================================================
// ParseReconnectMessage Tests
// ============================================================================

func TestParseReconnectMessage(t *testing.T) {
	original := NewReconnectMessage("secret-token", "10.100.0.5")
	data, _ := json.Marshal(original)

	parsed, err := ParseReconnectMessage(data)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if parsed.Token != original.Token {
		t.Errorf("expected token %s, got %s", original.Token, parsed.Token)
	}
	if parsed.PreviousIP != original.PreviousIP {
		t.Errorf("expected previous IP %s, got %s", original.PreviousIP, parsed.PreviousIP)
	}
}

func TestParseReconnectMessageWrongType(t *testing.T) {
	data := []byte(`{"type": "auth", "token": "test"}`)
	_, err := ParseReconnectMessage(data)
	if err == nil {
		t.Error("expected error for wrong message type")
	}
}

func TestParseReconnectMessageNoPreviousIP(t *testing.T) {
	data := []byte(`{"type": "reconnect", "token": "test"}`)
	parsed, err := ParseReconnectMessage(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.PreviousIP != "" {
		t.Errorf("expected empty previous IP, got %s", parsed.PreviousIP)
	}
}

// ============================================================================
// ParseAuthResponseMessage Tests
// ============================================================================

func TestParseAuthResponseMessage(t *testing.T) {
	original := NewAuthResponseSuccess("10.100.0.2", "10.100.0.0/24", "10.100.0.1", 1420)
	data, _ := json.Marshal(original)

	parsed, err := ParseAuthResponseMessage(data)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if !parsed.Success {
		t.Error("expected success to be true")
	}
	if parsed.AssignedIP != original.AssignedIP {
		t.Errorf("expected assigned IP %s, got %s", original.AssignedIP, parsed.AssignedIP)
	}
	if parsed.Subnet != original.Subnet {
		t.Errorf("expected subnet %s, got %s", original.Subnet, parsed.Subnet)
	}
	if parsed.ServerIP != original.ServerIP {
		t.Errorf("expected server IP %s, got %s", original.ServerIP, parsed.ServerIP)
	}
	if parsed.MTU != original.MTU {
		t.Errorf("expected MTU %d, got %d", original.MTU, parsed.MTU)
	}
}

func TestParseAuthResponseMessageError(t *testing.T) {
	original := NewAuthResponseError("test error")
	data, _ := json.Marshal(original)

	parsed, err := ParseAuthResponseMessage(data)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if parsed.Success {
		t.Error("expected success to be false")
	}
	if parsed.Error != "test error" {
		t.Errorf("expected error 'test error', got %s", parsed.Error)
	}
}

func TestParseAuthResponseMessageWrongType(t *testing.T) {
	data := []byte(`{"type": "auth", "token": "test"}`)
	_, err := ParseAuthResponseMessage(data)
	if err == nil {
		t.Error("expected error for wrong message type")
	}
}

// ============================================================================
// ParseIPPacket Tests
// ============================================================================

func TestParseIPPacket(t *testing.T) {
	// Create a minimal valid IPv4 packet header
	packet := make([]byte, 20)
	packet[0] = 0x45 // Version 4, IHL 5

	// Source IP: 10.100.0.2
	packet[12] = 10
	packet[13] = 100
	packet[14] = 0
	packet[15] = 2

	// Destination IP: 10.100.0.1
	packet[16] = 10
	packet[17] = 100
	packet[18] = 0
	packet[19] = 1

	srcIP, dstIP, err := ParseIPPacket(packet)
	if err != nil {
		t.Fatalf("failed to parse IP packet: %v", err)
	}

	expectedSrc := net.IPv4(10, 100, 0, 2)
	expectedDst := net.IPv4(10, 100, 0, 1)

	if !srcIP.Equal(expectedSrc) {
		t.Errorf("expected source IP %s, got %s", expectedSrc, srcIP)
	}
	if !dstIP.Equal(expectedDst) {
		t.Errorf("expected destination IP %s, got %s", expectedDst, dstIP)
	}
}

func TestParseIPPacketVariousAddresses(t *testing.T) {
	tests := []struct {
		name   string
		srcIP  [4]byte
		dstIP  [4]byte
	}{
		{"localhost", [4]byte{127, 0, 0, 1}, [4]byte{127, 0, 0, 1}},
		{"private_10", [4]byte{10, 0, 0, 1}, [4]byte{10, 255, 255, 254}},
		{"private_172", [4]byte{172, 16, 0, 1}, [4]byte{172, 31, 255, 254}},
		{"private_192", [4]byte{192, 168, 0, 1}, [4]byte{192, 168, 255, 254}},
		{"public", [4]byte{8, 8, 8, 8}, [4]byte{1, 1, 1, 1}},
		{"broadcast", [4]byte{192, 168, 1, 1}, [4]byte{255, 255, 255, 255}},
		{"zero", [4]byte{0, 0, 0, 0}, [4]byte{0, 0, 0, 0}},
		{"max", [4]byte{255, 255, 255, 255}, [4]byte{255, 255, 255, 255}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := make([]byte, 20)
			packet[0] = 0x45

			copy(packet[12:16], tt.srcIP[:])
			copy(packet[16:20], tt.dstIP[:])

			srcIP, dstIP, err := ParseIPPacket(packet)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}

			expectedSrc := net.IPv4(tt.srcIP[0], tt.srcIP[1], tt.srcIP[2], tt.srcIP[3])
			expectedDst := net.IPv4(tt.dstIP[0], tt.dstIP[1], tt.dstIP[2], tt.dstIP[3])

			if !srcIP.Equal(expectedSrc) {
				t.Errorf("expected source %s, got %s", expectedSrc, srcIP)
			}
			if !dstIP.Equal(expectedDst) {
				t.Errorf("expected dest %s, got %s", expectedDst, dstIP)
			}
		})
	}
}

func TestParseIPPacketTooShort(t *testing.T) {
	sizes := []int{0, 1, 5, 10, 15, 19}

	for _, size := range sizes {
		t.Run(string(rune('0'+size)), func(t *testing.T) {
			packet := make([]byte, size)
			if size > 0 {
				packet[0] = 0x45
			}
			_, _, err := ParseIPPacket(packet)
			if err == nil {
				t.Errorf("expected error for packet size %d", size)
			}
		})
	}
}

func TestParseIPPacketExactly20Bytes(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[12] = 10
	packet[13] = 0
	packet[14] = 0
	packet[15] = 1
	packet[16] = 10
	packet[17] = 0
	packet[18] = 0
	packet[19] = 2

	_, _, err := ParseIPPacket(packet)
	if err != nil {
		t.Errorf("unexpected error for 20-byte packet: %v", err)
	}
}

func TestParseIPPacketLargerPacket(t *testing.T) {
	// Simulate a packet with payload
	packet := make([]byte, 1500)
	packet[0] = 0x45
	packet[12] = 192
	packet[13] = 168
	packet[14] = 1
	packet[15] = 100
	packet[16] = 192
	packet[17] = 168
	packet[18] = 1
	packet[19] = 1

	srcIP, dstIP, err := ParseIPPacket(packet)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if !srcIP.Equal(net.IPv4(192, 168, 1, 100)) {
		t.Errorf("wrong source IP: %s", srcIP)
	}
	if !dstIP.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("wrong dest IP: %s", dstIP)
	}
}

func TestParseIPPacketWrongVersion(t *testing.T) {
	versions := []byte{0x00, 0x10, 0x20, 0x30, 0x50, 0x60, 0x70, 0x80, 0x90, 0xF0}

	for _, v := range versions {
		t.Run(string(rune('0'+v)), func(t *testing.T) {
			packet := make([]byte, 20)
			packet[0] = v

			_, _, err := ParseIPPacket(packet)
			if err == nil {
				t.Errorf("expected error for version byte 0x%02x", v)
			}
		})
	}
}

func TestParseIPPacketIPv4VersionByte(t *testing.T) {
	// Various valid IPv4 version bytes (version 4 with different IHL values)
	validBytes := []byte{0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F}

	for _, v := range validBytes {
		t.Run(string(rune(v)), func(t *testing.T) {
			packet := make([]byte, 60) // Max header size
			packet[0] = v
			packet[12] = 10
			packet[13] = 0
			packet[14] = 0
			packet[15] = 1
			packet[16] = 10
			packet[17] = 0
			packet[18] = 0
			packet[19] = 2

			_, _, err := ParseIPPacket(packet)
			if err != nil {
				t.Errorf("unexpected error for version byte 0x%02x: %v", v, err)
			}
		})
	}
}

// ============================================================================
// IsIPv4Packet Tests
// ============================================================================

func TestIsIPv4Packet(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		expected bool
	}{
		{"valid IPv4 0x45", []byte{0x45, 0x00}, true},
		{"valid IPv4 0x4F", []byte{0x4F, 0x00}, true},
		{"IPv6", []byte{0x60, 0x00}, false},
		{"empty", []byte{}, false},
		{"version 0", []byte{0x00}, false},
		{"version 1", []byte{0x10}, false},
		{"version 2", []byte{0x20}, false},
		{"version 3", []byte{0x30}, false},
		{"version 5", []byte{0x50}, false},
		{"version 6", []byte{0x60}, false},
		{"version 7", []byte{0x70}, false},
		{"version 8", []byte{0x80}, false},
		{"version 15", []byte{0xF0}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsIPv4Packet(tt.packet)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsIPv4PacketNilSlice(t *testing.T) {
	var packet []byte = nil
	if IsIPv4Packet(packet) {
		t.Error("expected false for nil slice")
	}
}

// ============================================================================
// JSON Serialization Tests
// ============================================================================

func TestJSONSerialization(t *testing.T) {
	// Test that messages serialize to expected JSON format
	auth := NewAuthMessage("secret")
	data, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	expected := `{"type":"auth","token":"secret"}`
	if string(data) != expected {
		t.Errorf("expected %s, got %s", expected, string(data))
	}
}

func TestJSONSerializationPing(t *testing.T) {
	ping := NewPingMessage()
	data, err := json.Marshal(ping)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	expected := `{"type":"ping"}`
	if string(data) != expected {
		t.Errorf("expected %s, got %s", expected, string(data))
	}
}

func TestJSONSerializationPong(t *testing.T) {
	pong := NewPongMessage()
	data, err := json.Marshal(pong)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	expected := `{"type":"pong"}`
	if string(data) != expected {
		t.Errorf("expected %s, got %s", expected, string(data))
	}
}

func TestJSONSerializationReconnect(t *testing.T) {
	msg := NewReconnectMessage("token123", "10.100.0.5")
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify it can be parsed back
	parsed, err := ParseReconnectMessage(data)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if parsed.Token != "token123" || parsed.PreviousIP != "10.100.0.5" {
		t.Errorf("round-trip failed")
	}
}

func TestJSONSerializationAuthResponse(t *testing.T) {
	msg := NewAuthResponseSuccess("10.100.0.2", "10.100.0.0/24", "10.100.0.1", 1420)
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	parsed, err := ParseAuthResponseMessage(data)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if !parsed.Success {
		t.Error("expected success")
	}
	if parsed.AssignedIP != "10.100.0.2" {
		t.Errorf("wrong assigned IP: %s", parsed.AssignedIP)
	}
	if parsed.MTU != 1420 {
		t.Errorf("wrong MTU: %d", parsed.MTU)
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkParseIPPacket(b *testing.B) {
	packet := make([]byte, 1420)
	packet[0] = 0x45
	packet[12] = 10
	packet[13] = 100
	packet[14] = 0
	packet[15] = 2
	packet[16] = 10
	packet[17] = 100
	packet[18] = 0
	packet[19] = 1

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseIPPacket(packet)
	}
}

func BenchmarkParseMessage(b *testing.B) {
	msg := NewAuthMessage("secret-token")
	data, _ := json.Marshal(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseMessage(data)
	}
}

func BenchmarkIsIPv4Packet(b *testing.B) {
	packet := make([]byte, 1420)
	packet[0] = 0x45

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsIPv4Packet(packet)
	}
}

func BenchmarkNewAuthMessage(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewAuthMessage("benchmark-token")
	}
}

func BenchmarkJSONMarshalAuth(b *testing.B) {
	msg := NewAuthMessage("benchmark-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(msg)
	}
}

func BenchmarkJSONUnmarshalAuth(b *testing.B) {
	msg := NewAuthMessage("benchmark-token")
	data, _ := json.Marshal(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseAuthMessage(data)
	}
}
