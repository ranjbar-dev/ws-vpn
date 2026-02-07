package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ws-vpn/internal/server"
)

var (
	configPath = flag.String("config", "server.yaml", "Path to configuration file")
	logLevel   = flag.String("log-level", "", "Log level (debug, info, warn, error)")
)

func main() {
	flag.Parse()

	// Load configuration
	config, err := server.LoadConfig(*configPath)
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

	logger.Info("WS-VPN Server starting",
		"version", "1.0.0",
		"config", *configPath,
	)

	// Create and start server
	srv, err := server.New(config, logger)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	if err := srv.Start(); err != nil {
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}

	logger.Info("VPN server is running",
		"listen", config.Server.ListenAddr,
		"subnet", config.VPN.Subnet,
	)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("shutdown signal received")

	if err := srv.Stop(); err != nil {
		logger.Error("failed to stop server", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped successfully")
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
