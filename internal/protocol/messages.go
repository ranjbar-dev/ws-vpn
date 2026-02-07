// Package protocol defines the shared message structures for VPN communication.
package protocol

import (
	"encoding/json"
	"errors"
	"net"
)

// Message types for control messages
const (
	TypeAuth         = "auth"
	TypeAuthResponse = "auth_response"
	TypeReconnect    = "reconnect"
	TypePing         = "ping"
	TypePong         = "pong"
)

// Message is the base structure for all control messages
type Message struct {
	Type string `json:"type"`
}

// AuthMessage is sent by client to authenticate
type AuthMessage struct {
	Type  string `json:"type"`
	Token string `json:"token"`
}

// ReconnectMessage is sent by client to reconnect with previous IP
type ReconnectMessage struct {
	Type       string `json:"type"`
	Token      string `json:"token"`
	PreviousIP string `json:"previous_ip,omitempty"`
}

// AuthResponseMessage is sent by server after successful authentication
type AuthResponseMessage struct {
	Type       string `json:"type"`
	Success    bool   `json:"success"`
	AssignedIP string `json:"assigned_ip,omitempty"`
	Subnet     string `json:"subnet,omitempty"`
	ServerIP   string `json:"server_ip,omitempty"`
	MTU        int    `json:"mtu,omitempty"`
	Error      string `json:"error,omitempty"`
}

// PingMessage is used for keepalive
type PingMessage struct {
	Type string `json:"type"`
}

// PongMessage is the response to ping
type PongMessage struct {
	Type string `json:"type"`
}

// NewAuthMessage creates a new authentication message
func NewAuthMessage(token string) *AuthMessage {
	return &AuthMessage{
		Type:  TypeAuth,
		Token: token,
	}
}

// NewReconnectMessage creates a new reconnection message
func NewReconnectMessage(token, previousIP string) *ReconnectMessage {
	return &ReconnectMessage{
		Type:       TypeReconnect,
		Token:      token,
		PreviousIP: previousIP,
	}
}

// NewAuthResponseSuccess creates a successful auth response
func NewAuthResponseSuccess(assignedIP, subnet, serverIP string, mtu int) *AuthResponseMessage {
	return &AuthResponseMessage{
		Type:       TypeAuthResponse,
		Success:    true,
		AssignedIP: assignedIP,
		Subnet:     subnet,
		ServerIP:   serverIP,
		MTU:        mtu,
	}
}

// NewAuthResponseError creates a failed auth response
func NewAuthResponseError(err string) *AuthResponseMessage {
	return &AuthResponseMessage{
		Type:    TypeAuthResponse,
		Success: false,
		Error:   err,
	}
}

// NewPingMessage creates a new ping message
func NewPingMessage() *PingMessage {
	return &PingMessage{Type: TypePing}
}

// NewPongMessage creates a new pong message
func NewPongMessage() *PongMessage {
	return &PongMessage{Type: TypePong}
}

// ParseMessage parses a JSON message and returns its type
func ParseMessage(data []byte) (string, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return "", err
	}
	return msg.Type, nil
}

// ParseAuthMessage parses an auth message
func ParseAuthMessage(data []byte) (*AuthMessage, error) {
	var msg AuthMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	if msg.Type != TypeAuth {
		return nil, errors.New("invalid message type")
	}
	return &msg, nil
}

// ParseReconnectMessage parses a reconnect message
func ParseReconnectMessage(data []byte) (*ReconnectMessage, error) {
	var msg ReconnectMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	if msg.Type != TypeReconnect {
		return nil, errors.New("invalid message type")
	}
	return &msg, nil
}

// ParseAuthResponseMessage parses an auth response message
func ParseAuthResponseMessage(data []byte) (*AuthResponseMessage, error) {
	var msg AuthResponseMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	if msg.Type != TypeAuthResponse {
		return nil, errors.New("invalid message type")
	}
	return &msg, nil
}

// ParseIPPacket extracts source and destination IPs from an IP packet
func ParseIPPacket(packet []byte) (srcIP, dstIP net.IP, err error) {
	if len(packet) < 20 {
		return nil, nil, errors.New("packet too short for IPv4 header")
	}

	// Check IP version (first 4 bits)
	version := packet[0] >> 4
	if version != 4 {
		return nil, nil, errors.New("only IPv4 is supported")
	}

	srcIP = net.IPv4(packet[12], packet[13], packet[14], packet[15])
	dstIP = net.IPv4(packet[16], packet[17], packet[18], packet[19])
	return srcIP, dstIP, nil
}

// IsIPv4Packet checks if the packet is an IPv4 packet
func IsIPv4Packet(packet []byte) bool {
	if len(packet) < 1 {
		return false
	}
	return (packet[0] >> 4) == 4
}
