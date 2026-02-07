package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Server.ListenAddr != "0.0.0.0:443" {
		t.Errorf("expected default listen addr '0.0.0.0:443', got %s", config.Server.ListenAddr)
	}
	if config.VPN.Subnet != "10.100.0.0/24" {
		t.Errorf("expected default subnet '10.100.0.0/24', got %s", config.VPN.Subnet)
	}
	if config.VPN.ServerIP != "10.100.0.1" {
		t.Errorf("expected default server IP '10.100.0.1', got %s", config.VPN.ServerIP)
	}
	if config.VPN.MTU != 1420 {
		t.Errorf("expected default MTU 1420, got %d", config.VPN.MTU)
	}
	if config.VPN.InterfaceName != "tun0" {
		t.Errorf("expected default interface 'tun0', got %s", config.VPN.InterfaceName)
	}
	if config.Logging.Level != "info" {
		t.Errorf("expected default log level 'info', got %s", config.Logging.Level)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Server: ServerConfig{
					ListenAddr: "0.0.0.0:443",
					TLSCert:    "/etc/vpn/server.crt",
					TLSKey:     "/etc/vpn/server.key",
				},
				VPN: VPNConfig{
					Subnet:   "10.100.0.0/24",
					ServerIP: "10.100.0.1",
					MTU:      1420,
				},
				Auth: AuthConfig{
					Tokens: []string{"token1"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing listen addr",
			config: &Config{
				Server: ServerConfig{
					TLSCert: "/etc/vpn/server.crt",
					TLSKey:  "/etc/vpn/server.key",
				},
				VPN: VPNConfig{
					Subnet:   "10.100.0.0/24",
					ServerIP: "10.100.0.1",
				},
				Auth: AuthConfig{
					Tokens: []string{"token1"},
				},
			},
			wantErr: true,
		},
		{
			name: "missing tls cert",
			config: &Config{
				Server: ServerConfig{
					ListenAddr: "0.0.0.0:443",
					TLSKey:     "/etc/vpn/server.key",
				},
				VPN: VPNConfig{
					Subnet:   "10.100.0.0/24",
					ServerIP: "10.100.0.1",
				},
				Auth: AuthConfig{
					Tokens: []string{"token1"},
				},
			},
			wantErr: true,
		},
		{
			name: "missing tls key",
			config: &Config{
				Server: ServerConfig{
					ListenAddr: "0.0.0.0:443",
					TLSCert:    "/etc/vpn/server.crt",
				},
				VPN: VPNConfig{
					Subnet:   "10.100.0.0/24",
					ServerIP: "10.100.0.1",
				},
				Auth: AuthConfig{
					Tokens: []string{"token1"},
				},
			},
			wantErr: true,
		},
		{
			name: "missing subnet",
			config: &Config{
				Server: ServerConfig{
					ListenAddr: "0.0.0.0:443",
					TLSCert:    "/etc/vpn/server.crt",
					TLSKey:     "/etc/vpn/server.key",
				},
				VPN: VPNConfig{
					ServerIP: "10.100.0.1",
				},
				Auth: AuthConfig{
					Tokens: []string{"token1"},
				},
			},
			wantErr: true,
		},
		{
			name: "missing server IP",
			config: &Config{
				Server: ServerConfig{
					ListenAddr: "0.0.0.0:443",
					TLSCert:    "/etc/vpn/server.crt",
					TLSKey:     "/etc/vpn/server.key",
				},
				VPN: VPNConfig{
					Subnet: "10.100.0.0/24",
				},
				Auth: AuthConfig{
					Tokens: []string{"token1"},
				},
			},
			wantErr: true,
		},
		{
			name: "no tokens",
			config: &Config{
				Server: ServerConfig{
					ListenAddr: "0.0.0.0:443",
					TLSCert:    "/etc/vpn/server.crt",
					TLSKey:     "/etc/vpn/server.key",
				},
				VPN: VPNConfig{
					Subnet:   "10.100.0.0/24",
					ServerIP: "10.100.0.1",
				},
				Auth: AuthConfig{
					Tokens: []string{},
				},
			},
			wantErr: true,
		},
		{
			name: "zero mtu gets default",
			config: &Config{
				Server: ServerConfig{
					ListenAddr: "0.0.0.0:443",
					TLSCert:    "/etc/vpn/server.crt",
					TLSKey:     "/etc/vpn/server.key",
				},
				VPN: VPNConfig{
					Subnet:   "10.100.0.0/24",
					ServerIP: "10.100.0.1",
					MTU:      0,
				},
				Auth: AuthConfig{
					Tokens: []string{"token1"},
				},
			},
			wantErr: false,
		},
		{
			name: "empty interface name gets default",
			config: &Config{
				Server: ServerConfig{
					ListenAddr: "0.0.0.0:443",
					TLSCert:    "/etc/vpn/server.crt",
					TLSKey:     "/etc/vpn/server.key",
				},
				VPN: VPNConfig{
					Subnet:        "10.100.0.0/24",
					ServerIP:      "10.100.0.1",
					InterfaceName: "",
				},
				Auth: AuthConfig{
					Tokens: []string{"token1"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfigIsValidToken(t *testing.T) {
	config := &Config{
		Auth: AuthConfig{
			Tokens: []string{"token1", "token2", "token3"},
		},
	}

	// Valid tokens
	if !config.IsValidToken("token1") {
		t.Error("expected token1 to be valid")
	}
	if !config.IsValidToken("token2") {
		t.Error("expected token2 to be valid")
	}
	if !config.IsValidToken("token3") {
		t.Error("expected token3 to be valid")
	}

	// Invalid tokens
	if config.IsValidToken("invalid") {
		t.Error("expected 'invalid' to be invalid")
	}
	if config.IsValidToken("") {
		t.Error("expected empty string to be invalid")
	}
	if config.IsValidToken("Token1") {
		t.Error("expected case-sensitive matching")
	}
}

func TestLoadConfig(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "server.yaml")

	configContent := `
server:
  listen_addr: "0.0.0.0:8443"
  tls_cert: "/etc/vpn/server.crt"
  tls_key: "/etc/vpn/server.key"

vpn:
  subnet: "192.168.100.0/24"
  server_ip: "192.168.100.1"
  mtu: 1400
  interface_name: "vpn0"

auth:
  tokens:
    - "test-token-1"
    - "test-token-2"

logging:
  level: "debug"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if config.Server.ListenAddr != "0.0.0.0:8443" {
		t.Errorf("expected listen addr '0.0.0.0:8443', got %s", config.Server.ListenAddr)
	}
	if config.VPN.Subnet != "192.168.100.0/24" {
		t.Errorf("expected subnet '192.168.100.0/24', got %s", config.VPN.Subnet)
	}
	if config.VPN.MTU != 1400 {
		t.Errorf("expected MTU 1400, got %d", config.VPN.MTU)
	}
	if config.VPN.InterfaceName != "vpn0" {
		t.Errorf("expected interface 'vpn0', got %s", config.VPN.InterfaceName)
	}
	if len(config.Auth.Tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(config.Auth.Tokens))
	}
	if config.Logging.Level != "debug" {
		t.Errorf("expected log level 'debug', got %s", config.Logging.Level)
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	err := os.WriteFile(configPath, []byte("not: valid: yaml: content"), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err = LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadConfigInvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "incomplete.yaml")

	// Missing required fields
	configContent := `
server:
  listen_addr: "0.0.0.0:443"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err = LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for incomplete config")
	}
}

func TestConfigMTUDefault(t *testing.T) {
	config := &Config{
		Server: ServerConfig{
			ListenAddr: "0.0.0.0:443",
			TLSCert:    "/cert",
			TLSKey:     "/key",
		},
		VPN: VPNConfig{
			Subnet:   "10.0.0.0/24",
			ServerIP: "10.0.0.1",
			MTU:      0, // Zero should default to 1420
		},
		Auth: AuthConfig{
			Tokens: []string{"token"},
		},
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if config.VPN.MTU != 1420 {
		t.Errorf("expected MTU 1420, got %d", config.VPN.MTU)
	}
}

func TestConfigInterfaceNameDefault(t *testing.T) {
	config := &Config{
		Server: ServerConfig{
			ListenAddr: "0.0.0.0:443",
			TLSCert:    "/cert",
			TLSKey:     "/key",
		},
		VPN: VPNConfig{
			Subnet:        "10.0.0.0/24",
			ServerIP:      "10.0.0.1",
			InterfaceName: "", // Empty should default to "tun0"
		},
		Auth: AuthConfig{
			Tokens: []string{"token"},
		},
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if config.VPN.InterfaceName != "tun0" {
		t.Errorf("expected interface 'tun0', got %s", config.VPN.InterfaceName)
	}
}
