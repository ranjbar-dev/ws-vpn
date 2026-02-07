package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ws-vpn/internal/client"
)

var (
	configPath = flag.String("config", "client.yaml", "Path to configuration file")
	logLevel   = flag.String("log-level", "", "Log level (debug, info, warn, error)")
)

func main() {
	flag.Parse()

	// Load configuration
	config, err := client.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Setup logger
	level := parseLogLevel(config.Logging.Level)
	if *logLevel != "" {
		level = parseLogLevel(*logLevel)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	logger.Info("WS-VPN Client starting",
		"version", "1.0.0",
		"config", *configPath,
		"server", config.Server.URL,
	)

	// Check for admin privileges on Windows
	if !isAdmin() {
		logger.Warn("not running as administrator - TUN device creation may fail")
	}

	// Create and start client
	vpnClient := client.New(config, logger)

	if err := vpnClient.Start(); err != nil {
		logger.Error("failed to start client", "error", err)
		os.Exit(1)
	}

	logger.Info("VPN client started, connecting...")

	// Status update goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if vpnClient.IsConnected() {
					stats := vpnClient.Stats()
					logger.Info("connection status",
						"connected", true,
						"assigned_ip", vpnClient.AssignedIP(),
						"packets_sent", stats["packets_sent"],
						"packets_received", stats["packets_received"],
					)
				} else {
					logger.Info("connection status", "connected", false)
				}
			}
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("shutdown signal received")

	if err := vpnClient.Stop(); err != nil {
		logger.Error("failed to stop client", "error", err)
		os.Exit(1)
	}

	logger.Info("client stopped successfully")
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// isAdmin checks if the process is running with administrator privileges
func isAdmin() bool {
	// This is a simple check - in production you'd use more robust detection
	// For now, we just return true and let the TUN creation fail if not admin
	return true
}
