//go:build !linux

package server

import (
	"errors"
	"log/slog"
)

// TUNDevice is a stub for non-Linux platforms
type TUNDevice struct{}

// NewTUNDevice returns an error on non-Linux platforms
func NewTUNDevice(name string, ip string, cidr string, mtu int, logger *slog.Logger) (*TUNDevice, error) {
	return nil, errors.New("TUN device is only supported on Linux; please build with GOOS=linux")
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
