package client

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"
)

// ============================================================================
// Backoff Tests
// ============================================================================

func TestBackoffInitialValue(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	backoff := NewBackoff(100*time.Millisecond, 1*time.Second, logger)

	if backoff.Current() != 100*time.Millisecond {
		t.Errorf("expected initial backoff 100ms, got %v", backoff.Current())
	}
}

func TestBackoffIncrease(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	backoff := NewBackoff(100*time.Millisecond, 1*time.Second, logger)

	// First increase: 100ms -> 200ms
	backoff.Increase()
	if backoff.Current() != 200*time.Millisecond {
		t.Errorf("expected 200ms, got %v", backoff.Current())
	}

	// Second increase: 200ms -> 400ms
	backoff.Increase()
	if backoff.Current() != 400*time.Millisecond {
		t.Errorf("expected 400ms, got %v", backoff.Current())
	}

	// Third increase: 400ms -> 800ms
	backoff.Increase()
	if backoff.Current() != 800*time.Millisecond {
		t.Errorf("expected 800ms, got %v", backoff.Current())
	}

	// Fourth increase: 800ms -> 1s (capped at max)
	backoff.Increase()
	if backoff.Current() != 1*time.Second {
		t.Errorf("expected 1s (max), got %v", backoff.Current())
	}
}

func TestBackoffMaxCap(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	backoff := NewBackoff(100*time.Millisecond, 1*time.Second, logger)

	// Increase many times
	for i := 0; i < 20; i++ {
		backoff.Increase()
	}

	if backoff.Current() != 1*time.Second {
		t.Errorf("expected max backoff 1s, got %v", backoff.Current())
	}
}

func TestBackoffReset(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	backoff := NewBackoff(100*time.Millisecond, 1*time.Second, logger)

	// Increase several times
	for i := 0; i < 5; i++ {
		backoff.Increase()
	}

	// Reset
	backoff.Reset()

	if backoff.Current() != 100*time.Millisecond {
		t.Errorf("expected backoff reset to 100ms, got %v", backoff.Current())
	}
}

func TestBackoffWait(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	backoff := NewBackoff(50*time.Millisecond, 100*time.Millisecond, logger)

	ctx := context.Background()
	start := time.Now()
	result := backoff.Wait(ctx)
	elapsed := time.Since(start)

	if !result {
		t.Error("expected Wait to return true")
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("expected to wait at least 40ms, only waited %v", elapsed)
	}
}

func TestBackoffWaitCancelled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	backoff := NewBackoff(1*time.Second, 10*time.Second, logger)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	result := backoff.Wait(ctx)
	elapsed := time.Since(start)

	if result {
		t.Error("expected Wait to return false when cancelled")
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("expected early cancellation, waited %v", elapsed)
	}
}

func TestBackoffWaitWithTimeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	backoff := NewBackoff(1*time.Second, 10*time.Second, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	result := backoff.Wait(ctx)
	elapsed := time.Since(start)

	if result {
		t.Error("expected Wait to return false on timeout")
	}
	if elapsed > 150*time.Millisecond {
		t.Errorf("expected timeout around 50ms, waited %v", elapsed)
	}
}

func TestBackoffDifferentMinMax(t *testing.T) {
	tests := []struct {
		min time.Duration
		max time.Duration
	}{
		{1 * time.Millisecond, 10 * time.Millisecond},
		{100 * time.Millisecond, 100 * time.Millisecond}, // min == max
		{1 * time.Second, 60 * time.Second},
		{500 * time.Millisecond, 5 * time.Second},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	for _, tt := range tests {
		backoff := NewBackoff(tt.min, tt.max, logger)

		if backoff.Current() != tt.min {
			t.Errorf("expected initial %v, got %v", tt.min, backoff.Current())
		}

		// Increase until max
		for i := 0; i < 20; i++ {
			backoff.Increase()
		}

		if backoff.Current() != tt.max {
			t.Errorf("expected max %v, got %v", tt.max, backoff.Current())
		}
	}
}

// ============================================================================
// ReconnectionManager Tests
// ============================================================================

func TestReconnectionManagerInitialState(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(100*time.Millisecond, 1*time.Second, logger)

	if manager.GetPreviousIP() != "" {
		t.Error("expected no previous IP initially")
	}
	if manager.Attempts() != 0 {
		t.Errorf("expected 0 attempts initially, got %d", manager.Attempts())
	}
	if manager.LastError() != nil {
		t.Error("expected no last error initially")
	}
}

func TestReconnectionManagerSetPreviousIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(100*time.Millisecond, 1*time.Second, logger)

	manager.SetPreviousIP("10.100.0.5")
	if manager.GetPreviousIP() != "10.100.0.5" {
		t.Errorf("expected previous IP '10.100.0.5', got %s", manager.GetPreviousIP())
	}

	manager.SetPreviousIP("10.100.0.10")
	if manager.GetPreviousIP() != "10.100.0.10" {
		t.Errorf("expected previous IP '10.100.0.10', got %s", manager.GetPreviousIP())
	}
}

func TestReconnectionManagerOnConnectionSuccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(100*time.Millisecond, 1*time.Second, logger)

	// Simulate some failed attempts
	manager.OnConnectionFailure(errors.New("connection refused"))
	manager.OnConnectionFailure(errors.New("timeout"))

	// Then success
	manager.OnConnectionSuccess("10.100.0.10")

	if manager.GetPreviousIP() != "10.100.0.10" {
		t.Errorf("expected previous IP '10.100.0.10', got %s", manager.GetPreviousIP())
	}
	if manager.Attempts() != 0 {
		t.Errorf("expected 0 attempts after success, got %d", manager.Attempts())
	}
	if manager.LastError() != nil {
		t.Error("expected no last error after success")
	}
}

func TestReconnectionManagerOnConnectionFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(100*time.Millisecond, 1*time.Second, logger)

	err := errors.New("connection refused")
	manager.OnConnectionFailure(err)

	if manager.LastError() == nil {
		t.Error("expected last error to be set")
	}
	if manager.LastError().Error() != "connection refused" {
		t.Errorf("expected error message 'connection refused', got %s", manager.LastError().Error())
	}
}

func TestReconnectionManagerShouldReconnect(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(100*time.Millisecond, 1*time.Second, logger)

	ctx := context.Background()
	if !manager.ShouldReconnect(ctx) {
		t.Error("expected ShouldReconnect to return true")
	}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if manager.ShouldReconnect(cancelledCtx) {
		t.Error("expected ShouldReconnect to return false after cancel")
	}
}

func TestReconnectionManagerWaitForReconnect(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(50*time.Millisecond, 200*time.Millisecond, logger)

	ctx := context.Background()

	// First wait
	start := time.Now()
	result := manager.WaitForReconnect(ctx)
	elapsed := time.Since(start)

	if !result {
		t.Error("expected WaitForReconnect to return true")
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("expected wait of at least 40ms, got %v", elapsed)
	}
	if manager.Attempts() != 1 {
		t.Errorf("expected 1 attempt, got %d", manager.Attempts())
	}
}

func TestReconnectionManagerWaitForReconnectCancelled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(1*time.Second, 10*time.Second, logger)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	result := manager.WaitForReconnect(ctx)

	if result {
		t.Error("expected WaitForReconnect to return false when cancelled")
	}
}

func TestReconnectionManagerMultipleFailures(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(10*time.Millisecond, 100*time.Millisecond, logger)

	// Simulate multiple failures
	for i := 0; i < 5; i++ {
		manager.OnConnectionFailure(errors.New("test error"))
	}

	// Backoff should have increased
	// The backoff is managed internally, so we can't directly check it
	// But we can verify that after success, it resets
	manager.OnConnectionSuccess("10.100.0.5")

	if manager.Attempts() != 0 {
		t.Errorf("expected 0 attempts after success, got %d", manager.Attempts())
	}
}

func TestReconnectionManagerPreservesIPAcrossAttempts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(10*time.Millisecond, 100*time.Millisecond, logger)

	// Set initial IP
	manager.SetPreviousIP("10.100.0.5")

	// Simulate failures
	manager.OnConnectionFailure(errors.New("error"))
	manager.OnConnectionFailure(errors.New("error"))

	// Previous IP should still be preserved
	if manager.GetPreviousIP() != "10.100.0.5" {
		t.Errorf("expected previous IP to be preserved, got %s", manager.GetPreviousIP())
	}
}

func TestReconnectionManagerIPUpdatedOnSuccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(10*time.Millisecond, 100*time.Millisecond, logger)

	// Initial success with one IP
	manager.OnConnectionSuccess("10.100.0.5")
	if manager.GetPreviousIP() != "10.100.0.5" {
		t.Errorf("expected IP 10.100.0.5, got %s", manager.GetPreviousIP())
	}

	// Simulate disconnect and reconnect with different IP
	manager.OnConnectionFailure(errors.New("disconnected"))
	manager.OnConnectionSuccess("10.100.0.10")
	if manager.GetPreviousIP() != "10.100.0.10" {
		t.Errorf("expected IP 10.100.0.10, got %s", manager.GetPreviousIP())
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestBackoffZeroValues(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// This tests behavior with zero values - implementation should handle gracefully
	backoff := NewBackoff(0, 0, logger)

	// Should not panic
	backoff.Increase()
	backoff.Reset()
	_ = backoff.Current()
}

func TestReconnectionManagerEmptyIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(10*time.Millisecond, 100*time.Millisecond, logger)

	manager.SetPreviousIP("")
	if manager.GetPreviousIP() != "" {
		t.Error("expected empty previous IP")
	}

	manager.OnConnectionSuccess("")
	if manager.GetPreviousIP() != "" {
		t.Error("expected empty previous IP after success with empty IP")
	}
}

func TestReconnectionManagerNilError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(10*time.Millisecond, 100*time.Millisecond, logger)

	// Should not panic with nil error
	manager.OnConnectionFailure(nil)

	if manager.LastError() != nil {
		t.Error("expected nil last error")
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkBackoffIncrease(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	backoff := NewBackoff(time.Millisecond, time.Second, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backoff.Increase()
		if i%10 == 0 {
			backoff.Reset()
		}
	}
}

func BenchmarkReconnectionManagerOnFailure(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := NewReconnectionManager(time.Millisecond, time.Second, logger)
	err := errors.New("test error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.OnConnectionFailure(err)
	}
}
