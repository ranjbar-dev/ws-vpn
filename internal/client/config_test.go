package client

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultClientConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Server.URL != "wss://localhost:443/vpn" {
		t.Errorf("expected default URL 'wss://localhost:443/vpn', got %s", config.Server.URL)
	}
	if config.Server.VerifyTLS != false {
		t.Error("expected default VerifyTLS to be false")
	}
	if config.VPN.InterfaceName != "WS-VPN" {
		t.Errorf("expected default interface 'WS-VPN', got %s", config.VPN.InterfaceName)
	}
	if config.VPN.MTU != 1420 {
		t.Errorf("expected default MTU 1420, got %d", config.VPN.MTU)
	}
	if config.Reconnect.MinBackoff != 1*time.Second {
		t.Errorf("expected default min backoff 1s, got %v", config.Reconnect.MinBackoff)
	}
	if config.Reconnect.MaxBackoff != 60*time.Second {
		t.Errorf("expected default max backoff 60s, got %v", config.Reconnect.MaxBackoff)
	}
	if config.Logging.Level != "info" {
		t.Errorf("expected default log level 'info', got %s", config.Logging.Level)
	}
}

func TestClientConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Server: ServerConfig{
					URL:       "wss://server:443/vpn",
					VerifyTLS: false,
				},
				Auth: AuthConfig{
					Token: "my-token",
				},
				VPN: VPNConfig{
					InterfaceName: "VPN",
					MTU:           1420,
				},
				Reconnect: ReconnectConfig{
					MinBackoff: 1 * time.Second,
					MaxBackoff: 60 * time.Second,
				},
			},
			wantErr: false,
		},
		{
			name: "missing server URL",
			config: &Config{
				Server: ServerConfig{
					URL: "",
				},
				Auth: AuthConfig{
					Token: "my-token",
				},
			},
			wantErr: true,
		},
		{
			name: "missing auth token",
			config: &Config{
				Server: ServerConfig{
					URL: "wss://server:443/vpn",
				},
				Auth: AuthConfig{
					Token: "",
				},
			},
			wantErr: true,
		},
		{
			name: "min backoff greater than max",
			config: &Config{
				Server: ServerConfig{
					URL: "wss://server:443/vpn",
				},
				Auth: AuthConfig{
					Token: "token",
				},
				Reconnect: ReconnectConfig{
					MinBackoff: 60 * time.Second,
					MaxBackoff: 1 * time.Second,
				},
			},
			wantErr: true,
		},
		{
			name: "zero mtu gets default",
			config: &Config{
				Server: ServerConfig{
					URL: "wss://server:443/vpn",
				},
				Auth: AuthConfig{
					Token: "token",
				},
				VPN: VPNConfig{
					MTU: 0,
				},
			},
			wantErr: false,
		},
		{
			name: "empty interface name gets default",
			config: &Config{
				Server: ServerConfig{
					URL: "wss://server:443/vpn",
				},
				Auth: AuthConfig{
					Token: "token",
				},
				VPN: VPNConfig{
					InterfaceName: "",
				},
			},
			wantErr: false,
		},
		{
			name: "zero min backoff gets default",
			config: &Config{
				Server: ServerConfig{
					URL: "wss://server:443/vpn",
				},
				Auth: AuthConfig{
					Token: "token",
				},
				Reconnect: ReconnectConfig{
					MinBackoff: 0,
					MaxBackoff: 60 * time.Second,
				},
			},
			wantErr: false,
		},
		{
			name: "zero max backoff gets default",
			config: &Config{
				Server: ServerConfig{
					URL: "wss://server:443/vpn",
				},
				Auth: AuthConfig{
					Token: "token",
				},
				Reconnect: ReconnectConfig{
					MinBackoff: 1 * time.Second,
					MaxBackoff: 0,
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

func TestLoadClientConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "client.yaml")

	configContent := `
server:
  url: "wss://vpn.example.com:443/vpn"
  verify_tls: true

auth:
  token: "test-auth-token"

vpn:
  interface_name: "MyVPN"
  mtu: 1400

reconnect:
  min_backoff: "2s"
  max_backoff: "120s"

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

	if config.Server.URL != "wss://vpn.example.com:443/vpn" {
		t.Errorf("expected URL 'wss://vpn.example.com:443/vpn', got %s", config.Server.URL)
	}
	if config.Server.VerifyTLS != true {
		t.Error("expected VerifyTLS to be true")
	}
	if config.Auth.Token != "test-auth-token" {
		t.Errorf("expected token 'test-auth-token', got %s", config.Auth.Token)
	}
	if config.VPN.InterfaceName != "MyVPN" {
		t.Errorf("expected interface 'MyVPN', got %s", config.VPN.InterfaceName)
	}
	if config.VPN.MTU != 1400 {
		t.Errorf("expected MTU 1400, got %d", config.VPN.MTU)
	}
	if config.Reconnect.MinBackoff != 2*time.Second {
		t.Errorf("expected min backoff 2s, got %v", config.Reconnect.MinBackoff)
	}
	if config.Reconnect.MaxBackoff != 120*time.Second {
		t.Errorf("expected max backoff 120s, got %v", config.Reconnect.MaxBackoff)
	}
	if config.Logging.Level != "debug" {
		t.Errorf("expected log level 'debug', got %s", config.Logging.Level)
	}
}

func TestLoadClientConfigFileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/client.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadClientConfigInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	err := os.WriteFile(configPath, []byte("invalid: yaml: content:"), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err = LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadClientConfigInvalidDuration(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid-duration.yaml")

	configContent := `
server:
  url: "wss://server:443/vpn"
auth:
  token: "token"
reconnect:
  min_backoff: "invalid"
  max_backoff: "60s"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err = LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestLoadClientConfigMissingToken(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "no-token.yaml")

	configContent := `
server:
  url: "wss://server:443/vpn"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err = LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for missing token")
	}
}

func TestClientConfigDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "minimal.yaml")

	// Minimal config with only required fields
	configContent := `
server:
  url: "wss://server:443/vpn"
auth:
  token: "my-token"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Check defaults were applied
	if config.VPN.InterfaceName != "WS-VPN" {
		t.Errorf("expected default interface 'WS-VPN', got %s", config.VPN.InterfaceName)
	}
	if config.VPN.MTU != 1420 {
		t.Errorf("expected default MTU 1420, got %d", config.VPN.MTU)
	}
	if config.Reconnect.MinBackoff != 1*time.Second {
		t.Errorf("expected default min backoff 1s, got %v", config.Reconnect.MinBackoff)
	}
	if config.Reconnect.MaxBackoff != 60*time.Second {
		t.Errorf("expected default max backoff 60s, got %v", config.Reconnect.MaxBackoff)
	}
}

func TestClientConfigDurationParsing(t *testing.T) {
	tests := []struct {
		min      string
		max      string
		wantMin  time.Duration
		wantMax  time.Duration
		wantErr  bool
	}{
		{"1s", "60s", 1 * time.Second, 60 * time.Second, false},
		{"500ms", "5s", 500 * time.Millisecond, 5 * time.Second, false},
		{"1m", "10m", 1 * time.Minute, 10 * time.Minute, false},
		{"100ms", "1h", 100 * time.Millisecond, 1 * time.Hour, false},
	}

	for _, tt := range tests {
		t.Run(tt.min+"_"+tt.max, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "test.yaml")

			configContent := `
server:
  url: "wss://server:443/vpn"
auth:
  token: "token"
reconnect:
  min_backoff: "` + tt.min + `"
  max_backoff: "` + tt.max + `"
`

			err := os.WriteFile(configPath, []byte(configContent), 0644)
			if err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			config, err := LoadConfig(configPath)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if config.Reconnect.MinBackoff != tt.wantMin {
				t.Errorf("expected min %v, got %v", tt.wantMin, config.Reconnect.MinBackoff)
			}
			if config.Reconnect.MaxBackoff != tt.wantMax {
				t.Errorf("expected max %v, got %v", tt.wantMax, config.Reconnect.MaxBackoff)
			}
		})
	}
}
