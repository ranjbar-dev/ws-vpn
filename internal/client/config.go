package client

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the client configuration
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Auth      AuthConfig      `yaml:"auth"`
	VPN       VPNConfig       `yaml:"vpn"`
	Reconnect ReconnectConfig `yaml:"reconnect"`
	Logging   LoggingConfig   `yaml:"logging"`
}

// ServerConfig holds server connection settings
type ServerConfig struct {
	URL       string `yaml:"url"`
	VerifyTLS bool   `yaml:"verify_tls"`
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	Token string `yaml:"token"`
}

// VPNConfig holds VPN interface settings
type VPNConfig struct {
	InterfaceName string `yaml:"interface_name"`
	MTU           int    `yaml:"mtu"`
}

// ReconnectConfig holds reconnection settings
type ReconnectConfig struct {
	MinBackoff time.Duration `yaml:"min_backoff"`
	MaxBackoff time.Duration `yaml:"max_backoff"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			URL:       "wss://localhost:443/vpn",
			VerifyTLS: false,
		},
		Auth: AuthConfig{
			Token: "",
		},
		VPN: VPNConfig{
			InterfaceName: "WS-VPN",
			MTU:           1420,
		},
		Reconnect: ReconnectConfig{
			MinBackoff: 1 * time.Second,
			MaxBackoff: 60 * time.Second,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultConfig()

	// Custom unmarshaler for duration fields
	type rawConfig struct {
		Server    ServerConfig  `yaml:"server"`
		Auth      AuthConfig    `yaml:"auth"`
		VPN       VPNConfig     `yaml:"vpn"`
		Reconnect struct {
			MinBackoff string `yaml:"min_backoff"`
			MaxBackoff string `yaml:"max_backoff"`
		} `yaml:"reconnect"`
		Logging LoggingConfig `yaml:"logging"`
	}

	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	config.Server = raw.Server
	config.Auth = raw.Auth
	config.VPN = raw.VPN
	config.Logging = raw.Logging

	if raw.Reconnect.MinBackoff != "" {
		d, err := time.ParseDuration(raw.Reconnect.MinBackoff)
		if err != nil {
			return nil, fmt.Errorf("invalid min_backoff: %w", err)
		}
		config.Reconnect.MinBackoff = d
	}

	if raw.Reconnect.MaxBackoff != "" {
		d, err := time.ParseDuration(raw.Reconnect.MaxBackoff)
		if err != nil {
			return nil, fmt.Errorf("invalid max_backoff: %w", err)
		}
		config.Reconnect.MaxBackoff = d
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Server.URL == "" {
		return fmt.Errorf("server URL is required")
	}
	if c.Auth.Token == "" {
		return fmt.Errorf("auth token is required")
	}
	if c.VPN.InterfaceName == "" {
		c.VPN.InterfaceName = "WS-VPN"
	}
	if c.VPN.MTU <= 0 {
		c.VPN.MTU = 1420
	}
	if c.Reconnect.MinBackoff <= 0 {
		c.Reconnect.MinBackoff = 1 * time.Second
	}
	if c.Reconnect.MaxBackoff <= 0 {
		c.Reconnect.MaxBackoff = 60 * time.Second
	}
	if c.Reconnect.MinBackoff > c.Reconnect.MaxBackoff {
		return fmt.Errorf("min_backoff cannot be greater than max_backoff")
	}
	return nil
}
