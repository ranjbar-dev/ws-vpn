//go:build !windows

package client

import (
	"errors"
	"log/slog"
)

// TUNDevice is a stub for non-Windows platforms
type TUNDevice struct{}

// NewTUNDevice returns an error on non-Windows platforms
func NewTUNDevice(name string, mtu int, logger *slog.Logger) (*TUNDevice, error) {
	return nil, errors.New("TUN device is only supported on Windows; please build with GOOS=windows")
}

func (d *TUNDevice) Configure(assignedIP, subnet, serverIP string, mtu int) error {
	return errors.New("not implemented")
}

func (d *TUNDevice) Read(buf []byte) (int, error) {
	return 0, errors.New("not implemented")
}

func (d *TUNDevice) Write(buf []byte) (int, error) {
	return 0, errors.New("not implemented")
}

func (d *TUNDevice) Close() error {
	return nil
}

func (d *TUNDevice) Name() string {
	return ""
}

func (d *TUNDevice) MTU() int {
	return 0
}

func (d *TUNDevice) RemoveRoutes() {
	// No-op on non-Windows platforms
}

func (d *TUNDevice) GetInterfaceIndex() (int, error) {
	return 0, errors.New("not implemented")
}
