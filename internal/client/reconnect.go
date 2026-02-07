package client

import (
	"context"
	"log/slog"
	"time"
)

// Backoff implements exponential backoff for reconnection
type Backoff struct {
	current time.Duration
	min     time.Duration
	max     time.Duration
	logger  *slog.Logger
}

// NewBackoff creates a new backoff instance
func NewBackoff(min, max time.Duration, logger *slog.Logger) *Backoff {
	return &Backoff{
		current: min,
		min:     min,
		max:     max,
		logger:  logger,
	}
}

// Wait waits for the current backoff duration
// Returns false if the context is cancelled
func (b *Backoff) Wait(ctx context.Context) bool {
	b.logger.Info("waiting before reconnection", "duration", b.current)

	select {
	case <-ctx.Done():
		return false
	case <-time.After(b.current):
		return true
	}
}

// Increase doubles the current backoff up to the maximum
func (b *Backoff) Increase() {
	b.current *= 2
	if b.current > b.max {
		b.current = b.max
	}
}

// Reset resets the backoff to the minimum value
func (b *Backoff) Reset() {
	b.current = b.min
}

// Current returns the current backoff duration
func (b *Backoff) Current() time.Duration {
	return b.current
}

// ReconnectionManager handles the reconnection logic
type ReconnectionManager struct {
	backoff    *Backoff
	attempts   uint64
	lastError  error
	previousIP string
	logger     *slog.Logger
}

// NewReconnectionManager creates a new reconnection manager
func NewReconnectionManager(minBackoff, maxBackoff time.Duration, logger *slog.Logger) *ReconnectionManager {
	return &ReconnectionManager{
		backoff: NewBackoff(minBackoff, maxBackoff, logger),
		logger:  logger,
	}
}

// ShouldReconnect determines if we should attempt to reconnect
func (m *ReconnectionManager) ShouldReconnect(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	default:
		return true
	}
}

// WaitForReconnect waits for the appropriate backoff duration
func (m *ReconnectionManager) WaitForReconnect(ctx context.Context) bool {
	m.attempts++
	m.logger.Info("reconnection attempt",
		"attempt", m.attempts,
		"backoff", m.backoff.Current(),
		"previous_ip", m.previousIP,
	)
	return m.backoff.Wait(ctx)
}

// OnConnectionSuccess handles successful connection
func (m *ReconnectionManager) OnConnectionSuccess(assignedIP string) {
	if m.attempts > 0 {
		m.logger.Info("reconnection successful",
			"attempts", m.attempts,
			"assigned_ip", assignedIP,
		)
	}
	m.backoff.Reset()
	m.attempts = 0
	m.previousIP = assignedIP
	m.lastError = nil
}

// OnConnectionFailure handles connection failure
func (m *ReconnectionManager) OnConnectionFailure(err error) {
	m.lastError = err
	m.backoff.Increase()
	m.logger.Warn("connection failed",
		"error", err,
		"next_backoff", m.backoff.Current(),
	)
}

// GetPreviousIP returns the previously assigned IP for reconnection
func (m *ReconnectionManager) GetPreviousIP() string {
	return m.previousIP
}

// SetPreviousIP sets the previous IP for reconnection attempts
func (m *ReconnectionManager) SetPreviousIP(ip string) {
	m.previousIP = ip
}

// Attempts returns the number of reconnection attempts
func (m *ReconnectionManager) Attempts() uint64 {
	return m.attempts
}

// LastError returns the last connection error
func (m *ReconnectionManager) LastError() error {
	return m.lastError
}
