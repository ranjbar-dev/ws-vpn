//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"github.com/ws-vpn/internal/client"
)

// AppConfig holds the GUI configuration
type AppConfig struct {
	ServerURL     string `json:"server_url"`
	AuthToken     string `json:"auth_token"`
	InterfaceName string `json:"interface_name"`
	MTU           int    `json:"mtu"`
	VerifyTLS     bool   `json:"verify_tls"`
}

// VPNApp represents the main application
type VPNApp struct {
	mainWindow *walk.MainWindow

	// Input fields
	serverURLEdit     *walk.LineEdit
	authTokenEdit     *walk.LineEdit
	interfaceNameEdit *walk.LineEdit
	mtuEdit           *walk.NumberEdit
	verifyTLSCheck    *walk.CheckBox

	// Status
	statusLabel *walk.Label
	connectBtn  *walk.PushButton

	// Logs
	logsEdit *walk.TextEdit

	// VPN client
	vpnClient  *client.Client
	connected  bool
	status     string
	assignedIP string
	mu         sync.RWMutex

	// Logger
	logHandler *GUILogHandler
}

// GUILogHandler writes logs to the GUI
type GUILogHandler struct {
	app      *VPNApp
	mu       sync.Mutex
	logLines []string
	maxLines int
}

func (h *GUILogHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *GUILogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	timestamp := r.Time.Format("15:04:05")
	level := r.Level.String()
	msg := r.Message

	r.Attrs(func(a slog.Attr) bool {
		msg += fmt.Sprintf(" %s=%v", a.Key, a.Value.Any())
		return true
	})

	logLine := fmt.Sprintf("[%s] %s: %s\r\n", timestamp, level, msg)
	h.logLines = append(h.logLines, logLine)

	if len(h.logLines) > h.maxLines {
		h.logLines = h.logLines[len(h.logLines)-h.maxLines:]
	}

	if h.app != nil && h.app.logsEdit != nil && h.app.mainWindow != nil {
		h.app.mainWindow.Synchronize(func() {
			h.app.logsEdit.SetText(h.getAllLogs())
			h.app.logsEdit.SetTextSelection(len(h.app.logsEdit.Text()), len(h.app.logsEdit.Text()))
		})
	}

	return nil
}

func (h *GUILogHandler) getAllLogs() string {
	result := ""
	for _, line := range h.logLines {
		result += line
	}
	return result
}

func (h *GUILogHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *GUILogHandler) WithGroup(name string) slog.Handler      { return h }
func (h *GUILogHandler) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logLines = make([]string, 0)
}

func main() {
	app := &VPNApp{
		status: "Disconnected",
		logHandler: &GUILogHandler{
			logLines: make([]string, 0),
			maxLines: 500,
		},
	}
	app.logHandler.app = app
	app.Run()
}

func (a *VPNApp) Run() {
	err := MainWindow{
		AssignTo: &a.mainWindow,
		Title:    "WS-VPN Client",
		Size:     Size{Width: 500, Height: 600},
		MinSize:  Size{Width: 400, Height: 500},
		Layout:   VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}},
		Children: []Widget{
			// Status Group
			GroupBox{
				Title:  "Connection Status",
				Layout: HBox{},
				Children: []Widget{
					Label{
						AssignTo: &a.statusLabel,
						Text:     "Status: Disconnected",
						Font:     Font{Bold: true, PointSize: 10},
					},
					HSpacer{},
					PushButton{
						AssignTo:  &a.connectBtn,
						Text:      "Connect",
						MinSize:   Size{Width: 100, Height: 30},
						OnClicked: a.onConnectClick,
					},
				},
			},

			// Configuration Group
			GroupBox{
				Title:  "Configuration",
				Layout: Grid{Columns: 2, Spacing: 10},
				Children: []Widget{
					Label{Text: "Server URL:"},
					LineEdit{
						AssignTo: &a.serverURLEdit,
						Text:     "wss://94.101.184.56:443/vpn",
					},

					Label{Text: "Auth Token:"},
					LineEdit{
						AssignTo:     &a.authTokenEdit,
						Text:         "96588sdfasdasf56asdfsdgfafafs9123",
						PasswordMode: true,
					},

					Label{Text: "Interface Name:"},
					LineEdit{
						AssignTo: &a.interfaceNameEdit,
						Text:     "WS-VPN",
					},

					Label{Text: "MTU:"},
					NumberEdit{
						AssignTo: &a.mtuEdit,
						Decimals: 0,
						MinValue: 576,
						MaxValue: 1500,
					},

					Label{Text: ""},
					CheckBox{
						AssignTo: &a.verifyTLSCheck,
						Text:     "Verify TLS Certificate",
						Checked:  false,
					},

					HSpacer{},
					PushButton{
						Text:      "Save Config",
						MinSize:   Size{Width: 100, Height: 25},
						OnClicked: a.saveConfig,
					},
				},
			},

			// Logs Group
			GroupBox{
				Title:  "Logs",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{
						AssignTo: &a.logsEdit,
						ReadOnly: true,
						VScroll:  true,
						MinSize:  Size{Height: 200},
						Font:     Font{Family: "Consolas", PointSize: 9},
					},
					Composite{
						Layout: HBox{},
						Children: []Widget{
							HSpacer{},
							PushButton{
								Text:      "Clear Logs",
								OnClicked: a.clearLogs,
							},
						},
					},
				},
			},
		},
	}.Create()

	if err != nil {
		walk.MsgBox(nil, "Error", fmt.Sprintf("Failed to create window: %v", err), walk.MsgBoxIconError)
		return
	}

	// Set MTU default
	a.mtuEdit.SetValue(1300)

	// Load saved config
	a.loadConfig()

	// Add initial log
	a.addLog("WS-VPN Client started")

	// Update initial status
	a.updateUI()

	a.mainWindow.Run()
}

func (a *VPNApp) addLog(msg string) {
	entry := fmt.Sprintf("[%s] INFO: %s\r\n", time.Now().Format("15:04:05"), msg)
	a.logHandler.mu.Lock()
	a.logHandler.logLines = append(a.logHandler.logLines, entry)
	a.logHandler.mu.Unlock()
	if a.logsEdit != nil {
		a.logsEdit.SetText(a.logHandler.getAllLogs())
	}
}

func (a *VPNApp) clearLogs() {
	a.logHandler.Clear()
	if a.logsEdit != nil {
		a.logsEdit.SetText("")
	}
}

func (a *VPNApp) onConnectClick() {
	a.mu.RLock()
	isConnected := a.connected
	isConnecting := a.status == "Connecting..." || a.status == "Reconnecting..."
	a.mu.RUnlock()

	if isConnected || isConnecting {
		a.disconnect()
	} else {
		a.connect()
	}
}

func (a *VPNApp) connect() {
	serverURL := a.serverURLEdit.Text()
	authToken := a.authTokenEdit.Text()
	interfaceName := a.interfaceNameEdit.Text()
	mtu := int(a.mtuEdit.Value())
	verifyTLS := a.verifyTLSCheck.Checked()

	if serverURL == "" {
		walk.MsgBox(a.mainWindow, "Error", "Server URL is required", walk.MsgBoxIconError)
		return
	}
	if authToken == "" {
		walk.MsgBox(a.mainWindow, "Error", "Auth Token is required", walk.MsgBoxIconError)
		return
	}
	if interfaceName == "" {
		interfaceName = "WS-VPN"
	}
	if mtu <= 0 {
		mtu = 1300
	}

	cfg := &client.Config{
		Server: client.ServerConfig{
			URL:       serverURL,
			VerifyTLS: verifyTLS,
		},
		Auth: client.AuthConfig{
			Token: authToken,
		},
		VPN: client.VPNConfig{
			InterfaceName: interfaceName,
			MTU:           mtu,
		},
		Reconnect: client.ReconnectConfig{
			MinBackoff: 1 * time.Second,
			MaxBackoff: 60 * time.Second,
		},
		Logging: client.LoggingConfig{
			Level: "debug",
		},
	}

	if err := cfg.Validate(); err != nil {
		walk.MsgBox(a.mainWindow, "Error", fmt.Sprintf("Invalid config: %v", err), walk.MsgBoxIconError)
		return
	}

	logger := slog.New(a.logHandler)

	a.mu.Lock()
	if a.vpnClient != nil {
		a.mu.Unlock()
		walk.MsgBox(a.mainWindow, "Error", "Already connected", walk.MsgBoxIconError)
		return
	}
	a.status = "Connecting..."
	a.vpnClient = client.New(cfg, logger)
	a.mu.Unlock()

	a.updateUI()
	a.setInputsEnabled(false)

	logger.Info("Starting VPN connection", "server", serverURL)

	go func() {
		if err := a.vpnClient.Start(); err != nil {
			logger.Error("Failed to start VPN", "error", err)
			a.mu.Lock()
			a.status = "Connection failed"
			a.vpnClient = nil
			a.mu.Unlock()
			a.mainWindow.Synchronize(func() {
				a.updateUI()
				a.setInputsEnabled(true)
			})
			return
		}
		a.monitorConnection(logger)
	}()
}

func (a *VPNApp) monitorConnection(logger *slog.Logger) {
	for {
		a.mu.RLock()
		vpnClient := a.vpnClient
		a.mu.RUnlock()

		if vpnClient == nil {
			a.mu.Lock()
			a.connected = false
			a.status = "Disconnected"
			a.assignedIP = ""
			a.mu.Unlock()
			a.mainWindow.Synchronize(func() {
				a.updateUI()
				a.setInputsEnabled(true)
			})
			return
		}

		if vpnClient.IsConnected() {
			a.mu.Lock()
			a.connected = true
			a.status = "Connected"
			a.assignedIP = vpnClient.AssignedIP()
			a.mu.Unlock()
		} else {
			a.mu.Lock()
			if a.connected {
				a.status = "Reconnecting..."
			}
			a.connected = false
			a.mu.Unlock()
		}

		a.mainWindow.Synchronize(func() {
			a.updateUI()
		})

		time.Sleep(1 * time.Second)
	}
}

func (a *VPNApp) disconnect() {
	a.mu.Lock()
	vpnClient := a.vpnClient
	a.vpnClient = nil
	a.connected = false
	a.status = "Disconnected"
	a.assignedIP = ""
	a.mu.Unlock()

	if vpnClient != nil {
		vpnClient.Stop()
	}

	a.addLog("VPN disconnected")
	a.updateUI()
	a.setInputsEnabled(true)
}

func (a *VPNApp) updateUI() {
	a.mu.RLock()
	status := a.status
	assignedIP := a.assignedIP
	connected := a.connected
	a.mu.RUnlock()

	if connected {
		a.statusLabel.SetText(fmt.Sprintf("Status: Connected (%s)", assignedIP))
		a.statusLabel.SetTextColor(walk.RGB(0, 150, 0))
		a.connectBtn.SetText("Disconnect")
	} else if status == "Connecting..." || status == "Reconnecting..." {
		a.statusLabel.SetText("Status: " + status)
		a.statusLabel.SetTextColor(walk.RGB(200, 150, 0))
		a.connectBtn.SetText("Disconnect")
	} else {
		a.statusLabel.SetText("Status: " + status)
		a.statusLabel.SetTextColor(walk.RGB(200, 0, 0))
		a.connectBtn.SetText("Connect")
	}
}

func (a *VPNApp) setInputsEnabled(enabled bool) {
	a.serverURLEdit.SetEnabled(enabled)
	a.authTokenEdit.SetEnabled(enabled)
	a.interfaceNameEdit.SetEnabled(enabled)
	a.mtuEdit.SetEnabled(enabled)
	a.verifyTLSCheck.SetEnabled(enabled)
}

func (a *VPNApp) getConfigPath() string {
	configDir, _ := os.UserConfigDir()
	if configDir == "" {
		configDir = "."
	}
	appDir := filepath.Join(configDir, "WS-VPN")
	os.MkdirAll(appDir, 0755)
	return filepath.Join(appDir, "config.json")
}

func (a *VPNApp) saveConfig() {
	config := AppConfig{
		ServerURL:     a.serverURLEdit.Text(),
		AuthToken:     a.authTokenEdit.Text(),
		InterfaceName: a.interfaceNameEdit.Text(),
		MTU:           int(a.mtuEdit.Value()),
		VerifyTLS:     a.verifyTLSCheck.Checked(),
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		walk.MsgBox(a.mainWindow, "Error", "Failed to save config", walk.MsgBoxIconError)
		return
	}

	if err := os.WriteFile(a.getConfigPath(), data, 0600); err != nil {
		walk.MsgBox(a.mainWindow, "Error", "Failed to save config file", walk.MsgBoxIconError)
		return
	}

	walk.MsgBox(a.mainWindow, "Success", "Configuration saved!", walk.MsgBoxIconInformation)
}

func (a *VPNApp) loadConfig() {
	data, err := os.ReadFile(a.getConfigPath())
	if err != nil {
		return
	}

	var config AppConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return
	}

	if config.ServerURL != "" {
		a.serverURLEdit.SetText(config.ServerURL)
	}
	if config.AuthToken != "" {
		a.authTokenEdit.SetText(config.AuthToken)
	}
	if config.InterfaceName != "" {
		a.interfaceNameEdit.SetText(config.InterfaceName)
	}
	if config.MTU > 0 {
		a.mtuEdit.SetValue(float64(config.MTU))
	}
	a.verifyTLSCheck.SetChecked(config.VerifyTLS)
}
