package server

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the server configuration
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	VPN     VPNConfig     `yaml:"vpn"`
	Auth    AuthConfig    `yaml:"auth"`
	Logging LoggingConfig `yaml:"logging"`
}

// ServerConfig holds server network settings
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	TLSCert    string `yaml:"tls_cert"`
	TLSKey     string `yaml:"tls_key"`
}

// VPNConfig holds VPN network settings
type VPNConfig struct {
	Subnet        string `yaml:"subnet"`
	ServerIP      string `yaml:"server_ip"`
	MTU           int    `yaml:"mtu"`
	InterfaceName string `yaml:"interface_name"`
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	Tokens []string `yaml:"tokens"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddr: "0.0.0.0:443",
			TLSCert:    "/etc/vpn/server.crt",
			TLSKey:     "/etc/vpn/server.key",
		},
		VPN: VPNConfig{
			Subnet:        "10.100.0.0/24",
			ServerIP:      "10.100.0.1",
			MTU:           1420,
			InterfaceName: "tun0",
		},
		Auth: AuthConfig{
			Tokens: []string{},
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
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Server.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if c.Server.TLSCert == "" {
		return fmt.Errorf("tls_cert is required")
	}
	if c.Server.TLSKey == "" {
		return fmt.Errorf("tls_key is required")
	}
	if c.VPN.Subnet == "" {
		return fmt.Errorf("subnet is required")
	}
	if c.VPN.ServerIP == "" {
		return fmt.Errorf("server_ip is required")
	}
	if len(c.Auth.Tokens) == 0 {
		return fmt.Errorf("at least one auth token is required")
	}
	if c.VPN.MTU <= 0 {
		c.VPN.MTU = 1420
	}
	if c.VPN.InterfaceName == "" {
		c.VPN.InterfaceName = "tun0"
	}
	return nil
}

// IsValidToken checks if the given token is valid
func (c *Config) IsValidToken(token string) bool {
	for _, t := range c.Auth.Tokens {
		if t == token {
			return true
		}
	}
	return false
}
