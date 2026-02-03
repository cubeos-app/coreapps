package handlers

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/go-chi/chi/v5"
)

// ============================================================================
// VPN Types
// ============================================================================

// VPNStatus represents overall VPN status.
// @Description Overall VPN status
type VPNStatus struct {
	WireGuard []VPNInterface `json:"wireguard"`
	OpenVPN   []VPNInterface `json:"openvpn"`
	Tor       TorStatus      `json:"tor"`
}

// VPNInterface represents a VPN interface.
// @Description VPN interface status
type VPNInterface struct {
	Name      string `json:"name" example:"wg0"`
	Active    bool   `json:"active" example:"true"`
	Type      string `json:"type" example:"wireguard"`
	Endpoint  string `json:"endpoint,omitempty" example:"vpn.example.com:51820"`
	LocalIP   string `json:"local_ip,omitempty" example:"10.0.0.2"`
	PublicKey string `json:"public_key,omitempty"`
}

// TorStatus represents Tor service status.
// @Description Tor service status
type TorStatus struct {
	Running      bool   `json:"running" example:"true"`
	Bootstrapped int    `json:"bootstrapped" example:"100"`
	CircuitReady bool   `json:"circuit_ready" example:"true"`
	SocksPort    int    `json:"socks_port" example:"9050"`
	ControlPort  int    `json:"control_port" example:"9051"`
	ExitIP       string `json:"exit_ip,omitempty" example:"185.220.101.1"`
}

// TorConfig represents Tor configuration.
// @Description Tor configuration settings
type TorConfig struct {
	SocksPort   int               `json:"socks_port" example:"9050"`
	ControlPort int               `json:"control_port" example:"9051"`
	DataDir     string            `json:"data_dir" example:"/var/lib/tor"`
	Settings    map[string]string `json:"settings"`
}

// ============================================================================
// VPN Status Handlers
// ============================================================================

// GetVPNStatus returns overall VPN status.
// @Summary Get VPN status
// @Description Returns status of all VPN connections (WireGuard, OpenVPN, Tor)
// @Tags VPN
// @Accept json
// @Produce json
// @Success 200 {object} VPNStatus
// @Failure 500 {object} ErrorResponse
// @Router /vpn/status [get]
func (h *HALHandler) GetVPNStatus(w http.ResponseWriter, r *http.Request) {
	status := VPNStatus{
		WireGuard: h.getWireGuardInterfaces(),
		OpenVPN:   h.getOpenVPNConnections(),
		Tor:       h.getTorStatus(),
	}

	jsonResponse(w, http.StatusOK, status)
}

// ============================================================================
// WireGuard Handlers
// ============================================================================

// WireGuardUp brings up a WireGuard interface.
// @Summary Bring up WireGuard interface
// @Description Activates a WireGuard VPN interface
// @Tags VPN
// @Accept json
// @Produce json
// @Param name path string true "Interface name" example(wg0)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /vpn/wireguard/up/{name} [post]
func (h *HALHandler) WireGuardUp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	cmd := exec.Command("wg-quick", "up", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to bring up WireGuard: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("WireGuard interface %s is up", name))
}

// WireGuardDown brings down a WireGuard interface.
// @Summary Bring down WireGuard interface
// @Description Deactivates a WireGuard VPN interface
// @Tags VPN
// @Accept json
// @Produce json
// @Param name path string true "Interface name" example(wg0)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /vpn/wireguard/down/{name} [post]
func (h *HALHandler) WireGuardDown(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	cmd := exec.Command("wg-quick", "down", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to bring down WireGuard: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("WireGuard interface %s is down", name))
}

// ============================================================================
// OpenVPN Handlers
// ============================================================================

// OpenVPNUp brings up an OpenVPN connection.
// @Summary Bring up OpenVPN connection
// @Description Starts an OpenVPN connection using systemd service
// @Tags VPN
// @Accept json
// @Produce json
// @Param name path string true "Connection name" example(client)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /vpn/openvpn/up/{name} [post]
func (h *HALHandler) OpenVPNUp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "connection name required")
		return
	}

	serviceName := fmt.Sprintf("openvpn-client@%s", name)
	cmd := exec.Command("systemctl", "start", serviceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to start OpenVPN: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("OpenVPN connection %s started", name))
}

// OpenVPNDown brings down an OpenVPN connection.
// @Summary Bring down OpenVPN connection
// @Description Stops an OpenVPN connection using systemd service
// @Tags VPN
// @Accept json
// @Produce json
// @Param name path string true "Connection name" example(client)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /vpn/openvpn/down/{name} [post]
func (h *HALHandler) OpenVPNDown(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "connection name required")
		return
	}

	serviceName := fmt.Sprintf("openvpn-client@%s", name)
	cmd := exec.Command("systemctl", "stop", serviceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to stop OpenVPN: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("OpenVPN connection %s stopped", name))
}

// ============================================================================
// Tor Handlers
// ============================================================================

// GetTorStatus returns Tor service status.
// @Summary Get Tor status
// @Description Returns Tor service status and circuit information
// @Tags VPN
// @Accept json
// @Produce json
// @Success 200 {object} TorStatus
// @Failure 500 {object} ErrorResponse
// @Router /vpn/tor/status [get]
func (h *HALHandler) GetTorStatus(w http.ResponseWriter, r *http.Request) {
	status := h.getTorStatus()
	jsonResponse(w, http.StatusOK, status)
}

// StartTor starts the Tor service.
// @Summary Start Tor
// @Description Starts the Tor SOCKS proxy service
// @Tags VPN
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /vpn/tor/start [post]
func (h *HALHandler) StartTor(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("systemctl", "start", "tor")
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to start Tor: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "Tor service started")
}

// StopTor stops the Tor service.
// @Summary Stop Tor
// @Description Stops the Tor SOCKS proxy service
// @Tags VPN
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /vpn/tor/stop [post]
func (h *HALHandler) StopTor(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("systemctl", "stop", "tor")
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to stop Tor: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "Tor service stopped")
}

// NewTorCircuit requests a new Tor circuit.
// @Summary Request new Tor circuit
// @Description Requests a new Tor circuit for a new exit IP
// @Tags VPN
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /vpn/tor/newcircuit [post]
func (h *HALHandler) NewTorCircuit(w http.ResponseWriter, r *http.Request) {
	// Send NEWNYM signal to Tor control port
	cmd := exec.Command("bash", "-c", `echo -e 'AUTHENTICATE ""\nSIGNAL NEWNYM\nQUIT' | nc localhost 9051`)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to request new circuit: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "new Tor circuit requested")
}

// GetTorConfig returns Tor configuration.
// @Summary Get Tor configuration
// @Description Returns Tor service configuration settings
// @Tags VPN
// @Accept json
// @Produce json
// @Success 200 {object} TorConfig
// @Failure 500 {object} ErrorResponse
// @Router /vpn/tor/config [get]
func (h *HALHandler) GetTorConfig(w http.ResponseWriter, r *http.Request) {
	config := TorConfig{
		SocksPort:   9050,
		ControlPort: 9051,
		DataDir:     "/var/lib/tor",
		Settings:    make(map[string]string),
	}

	// Read torrc if it exists
	if data, err := os.ReadFile("/etc/tor/torrc"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				config.Settings[parts[0]] = parts[1]
			}
		}
	}

	jsonResponse(w, http.StatusOK, config)
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *HALHandler) getWireGuardInterfaces() []VPNInterface {
	var interfaces []VPNInterface

	cmd := exec.Command("wg", "show", "interfaces")
	output, err := cmd.Output()
	if err != nil {
		return interfaces
	}

	names := strings.Fields(string(output))
	for _, name := range names {
		iface := VPNInterface{
			Name:   name,
			Type:   "wireguard",
			Active: true,
		}

		// Get more details
		cmd := exec.Command("wg", "show", name)
		if details, err := cmd.Output(); err == nil {
			lines := strings.Split(string(details), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "endpoint:") {
					iface.Endpoint = strings.TrimPrefix(line, "endpoint: ")
				}
				if strings.HasPrefix(line, "public key:") {
					iface.PublicKey = strings.TrimPrefix(line, "public key: ")
				}
			}
		}

		// Get local IP
		cmd = exec.Command("ip", "-o", "addr", "show", name)
		if ipOut, err := cmd.Output(); err == nil {
			fields := strings.Fields(string(ipOut))
			for i, f := range fields {
				if f == "inet" && i+1 < len(fields) {
					iface.LocalIP = strings.Split(fields[i+1], "/")[0]
				}
			}
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces
}

func (h *HALHandler) getOpenVPNConnections() []VPNInterface {
	var interfaces []VPNInterface

	// Check for tun interfaces
	entries, _ := os.ReadDir("/sys/class/net")
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "tun") {
			iface := VPNInterface{
				Name:   name,
				Type:   "openvpn",
				Active: true,
			}

			// Get local IP
			cmd := exec.Command("ip", "-o", "addr", "show", name)
			if ipOut, err := cmd.Output(); err == nil {
				fields := strings.Fields(string(ipOut))
				for i, f := range fields {
					if f == "inet" && i+1 < len(fields) {
						iface.LocalIP = strings.Split(fields[i+1], "/")[0]
					}
				}
			}

			interfaces = append(interfaces, iface)
		}
	}

	return interfaces
}

func (h *HALHandler) getTorStatus() TorStatus {
	status := TorStatus{
		SocksPort:   9050,
		ControlPort: 9051,
	}

	// Check if Tor is running
	cmd := exec.Command("systemctl", "is-active", "tor")
	if output, err := cmd.Output(); err == nil {
		status.Running = strings.TrimSpace(string(output)) == "active"
	}

	if !status.Running {
		return status
	}

	// Get bootstrap status from control port
	cmd = exec.Command("bash", "-c", `echo -e 'AUTHENTICATE ""\nGETINFO status/bootstrap-phase\nQUIT' | nc localhost 9051`)
	if output, err := cmd.Output(); err == nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "PROGRESS=100") {
			status.Bootstrapped = 100
			status.CircuitReady = true
		} else {
			// Parse PROGRESS=XX
			if idx := strings.Index(outputStr, "PROGRESS="); idx != -1 {
				progressStr := outputStr[idx+9:]
				if spaceIdx := strings.Index(progressStr, " "); spaceIdx != -1 {
					progressStr = progressStr[:spaceIdx]
				}
				fmt.Sscanf(progressStr, "%d", &status.Bootstrapped)
			}
		}
	}

	// Get exit IP through Tor
	cmd = exec.Command("curl", "-s", "--socks5-hostname", "localhost:9050", "https://check.torproject.org/api/ip")
	if output, err := cmd.Output(); err == nil {
		// Response is JSON: {"IsTor":true,"IP":"x.x.x.x"}
		outputStr := string(output)
		if idx := strings.Index(outputStr, `"IP":"`); idx != -1 {
			ipStart := idx + 6
			if ipEnd := strings.Index(outputStr[ipStart:], `"`); ipEnd != -1 {
				status.ExitIP = outputStr[ipStart : ipStart+ipEnd]
			}
		}
	}

	return status
}
