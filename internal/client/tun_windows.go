//go:build windows

package client

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

// TUNDevice represents a TUN interface on Windows using Wintun
type TUNDevice struct {
	device    tun.Device
	name      string
	mtu       int
	logger    *slog.Logger
	subnet    string
	serverIP  string
	assignedIP string
}

// NewTUNDevice creates and configures a new TUN device on Windows
func NewTUNDevice(name string, mtu int, logger *slog.Logger) (*TUNDevice, error) {
	// Create the Wintun adapter
	device, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	realName, err := device.Name()
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("failed to get device name: %w", err)
	}

	dev := &TUNDevice{
		device: device,
		name:   realName,
		mtu:    mtu,
		logger: logger,
	}

	logger.Info("TUN device created", "name", realName, "mtu", mtu)
	return dev, nil
}

// Configure configures the TUN device with the assigned IP and routes
// This implements SPLIT TUNNELING - only VPN subnet traffic goes through VPN
func (d *TUNDevice) Configure(assignedIP, subnet, serverIP string, mtu int) error {
	d.logger.Info("configuring TUN interface (split tunneling mode)",
		"assigned_ip", assignedIP,
		"subnet", subnet,
		"server_ip", serverIP,
		"mtu", mtu,
	)

	d.subnet = subnet
	d.serverIP = serverIP
	d.assignedIP = assignedIP

	// Parse the subnet to get the prefix length
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return fmt.Errorf("failed to parse subnet: %w", err)
	}

	// Set IP address using netsh WITHOUT setting a gateway
	// This prevents adding a default route through the VPN
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", d.name),
		"static",
		assignedIP,
		prefixToMask(prefix.Bits()),
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set IP address: %w: %s", err, string(output))
	}
	d.logger.Debug("set IP address (no gateway)", "ip", assignedIP)

	// Set MTU
	cmd = exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		d.name,
		fmt.Sprintf("mtu=%d", mtu),
		"store=active",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		d.logger.Warn("failed to set MTU (non-fatal)", "error", err, "output", string(output))
	}

	// Delete any existing route for the VPN subnet (cleanup)
	cmd = exec.Command("route", "delete", prefix.Masked().Addr().String())
	cmd.CombinedOutput() // Ignore errors - route may not exist

	// Add route ONLY for the VPN subnet through the VPN interface
	// This ensures only 10.100.0.x traffic goes through VPN
	// All other traffic uses the default route (internet)
	cmd = exec.Command("route", "add",
		prefix.Masked().Addr().String(),
		"mask", prefixToMask(prefix.Bits()),
		serverIP,
		"metric", "1",
	)
	if _, err := cmd.CombinedOutput(); err != nil {
		// Try alternative: route through interface
		d.logger.Debug("primary route add failed, trying interface route", "error", err)
		cmd = exec.Command("route", "add",
			prefix.Masked().Addr().String(),
			"mask", prefixToMask(prefix.Bits()),
			assignedIP,
			"metric", "1",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			d.logger.Warn("failed to add VPN subnet route", "error", err, "output", string(output))
		}
	}

	d.logger.Info("TUN interface configured (split tunneling enabled)",
		"vpn_subnet", subnet,
		"note", "only traffic to VPN subnet will use VPN tunnel",
	)
	return nil
}

// RemoveRoutes removes the VPN routes (cleanup on close)
func (d *TUNDevice) RemoveRoutes() {
	if d.subnet == "" {
		return
	}

	prefix, err := netip.ParsePrefix(d.subnet)
	if err != nil {
		return
	}

	cmd := exec.Command("route", "delete", prefix.Masked().Addr().String())
	cmd.CombinedOutput() // Ignore errors
	d.logger.Debug("removed VPN route", "subnet", d.subnet)
}

// prefixToMask converts a prefix length to a subnet mask string
func prefixToMask(bits int) string {
	mask := uint32(0xFFFFFFFF) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d",
		(mask>>24)&0xFF,
		(mask>>16)&0xFF,
		(mask>>8)&0xFF,
		mask&0xFF,
	)
}

// Read reads a packet from the TUN device
func (d *TUNDevice) Read(buf []byte) (int, error) {
	sizes := make([]int, 1)
	bufs := [][]byte{buf}

	n, err := d.device.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

// Write writes a packet to the TUN device
func (d *TUNDevice) Write(buf []byte) (int, error) {
	bufs := [][]byte{buf}
	n, err := d.device.Write(bufs, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return len(buf), nil
}

// Close closes the TUN device and removes routes
func (d *TUNDevice) Close() error {
	d.logger.Info("closing TUN device", "name", d.name)
	d.RemoveRoutes()
	return d.device.Close()
}

// Name returns the interface name
func (d *TUNDevice) Name() string {
	return d.name
}

// MTU returns the MTU
func (d *TUNDevice) MTU() int {
	return d.mtu
}

// GetInterfaceIndex returns the Windows interface index (for routing)
func (d *TUNDevice) GetInterfaceIndex() (int, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf("(Get-NetAdapter -Name '%s').ifIndex", d.name))
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	var idx int
	_, err = fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &idx)
	return idx, err
}
