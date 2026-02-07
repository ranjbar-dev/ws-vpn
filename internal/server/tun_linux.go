//go:build linux

package server

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"

	"github.com/songgao/water"
)

// TUNDevice represents a TUN interface on Linux
type TUNDevice struct {
	iface  *water.Interface
	name   string
	ip     net.IP
	subnet *net.IPNet
	mtu    int
	logger *slog.Logger
}

// NewTUNDevice creates and configures a new TUN device
func NewTUNDevice(name string, ip string, cidr string, mtu int, logger *slog.Logger) (*TUNDevice, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = name

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	dev := &TUNDevice{
		iface:  iface,
		name:   iface.Name(),
		ip:     parsedIP,
		subnet: subnet,
		mtu:    mtu,
		logger: logger,
	}

	if err := dev.configure(); err != nil {
		iface.Close()
		return nil, err
	}

	logger.Info("TUN device created", "name", dev.name, "ip", ip, "subnet", cidr, "mtu", mtu)
	return dev, nil
}

// configure sets up the TUN interface with IP and brings it up
func (d *TUNDevice) configure() error {
	// Get the prefix length from the subnet mask
	ones, _ := d.subnet.Mask.Size()
	addr := fmt.Sprintf("%s/%d", d.ip.String(), ones)

	// Set IP address
	cmd := exec.Command("ip", "addr", "add", addr, "dev", d.name)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set IP address: %w: %s", err, string(output))
	}
	d.logger.Debug("set IP address", "addr", addr)

	// Set MTU
	cmd = exec.Command("ip", "link", "set", "dev", d.name, "mtu", fmt.Sprintf("%d", d.mtu))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set MTU: %w: %s", err, string(output))
	}
	d.logger.Debug("set MTU", "mtu", d.mtu)

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", d.name, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w: %s", err, string(output))
	}
	d.logger.Debug("interface brought up")

	return nil
}

// Read reads a packet from the TUN device
func (d *TUNDevice) Read(buf []byte) (int, error) {
	return d.iface.Read(buf)
}

// Write writes a packet to the TUN device
func (d *TUNDevice) Write(buf []byte) (int, error) {
	return d.iface.Write(buf)
}

// Close closes the TUN device
func (d *TUNDevice) Close() error {
	d.logger.Info("closing TUN device", "name", d.name)
	return d.iface.Close()
}

// Name returns the interface name
func (d *TUNDevice) Name() string {
	return d.name
}

// MTU returns the MTU
func (d *TUNDevice) MTU() int {
	return d.mtu
}
