package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// ListInterfaces returns all network interfaces
// @Summary List network interfaces
// @Description Returns all network interfaces with their status
// @Tags Network
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /network/interfaces [get]
func (h *HALHandler) ListInterfaces(w http.ResponseWriter, r *http.Request) {
	output, err := exec.Command("ip", "-j", "addr").Output()
	if err != nil {
		// Fallback to non-JSON output
		output, err = exec.Command("ip", "addr").Output()
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "failed to get interfaces: "+err.Error())
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"raw": string(output),
		})
		return
	}

	var interfaces []interface{}
	if err := json.Unmarshal(output, &interfaces); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to parse interfaces: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"interfaces": interfaces,
	})
}

// GetInterface returns a specific network interface
// @Summary Get network interface details
// @Description Returns details for a specific network interface
// @Tags Network
// @Produce json
// @Param name path string true "Interface name"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/interface/{name} [get]
func (h *HALHandler) GetInterface(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	output, err := exec.Command("ip", "-j", "addr", "show", name).Output()
	if err != nil {
		errorResponse(w, http.StatusNotFound, "interface not found: "+name)
		return
	}

	var iface []interface{}
	if err := json.Unmarshal(output, &iface); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to parse interface: "+err.Error())
		return
	}

	if len(iface) > 0 {
		jsonResponse(w, http.StatusOK, iface[0])
	} else {
		jsonResponse(w, http.StatusOK, map[string]interface{}{})
	}
}

// GetInterfaceTraffic returns traffic statistics for a specific interface
// @Summary Get interface traffic statistics
// @Description Returns TX/RX bytes for a specific interface from sysfs
// @Tags Network
// @Produce json
// @Param name path string true "Interface name"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /network/interface/{name}/traffic [get]
func (h *HALHandler) GetInterfaceTraffic(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	// Read from /sys/class/net/{iface}/statistics/
	basePath := fmt.Sprintf("/sys/class/net/%s/statistics", name)

	// Check if interface exists
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		errorResponse(w, http.StatusNotFound, fmt.Sprintf("interface not found: %s", name))
		return
	}

	rxBytes, _ := readFileString(basePath + "/rx_bytes")
	txBytes, _ := readFileString(basePath + "/tx_bytes")
	rxPackets, _ := readFileString(basePath + "/rx_packets")
	txPackets, _ := readFileString(basePath + "/tx_packets")
	rxErrors, _ := readFileString(basePath + "/rx_errors")
	txErrors, _ := readFileString(basePath + "/tx_errors")
	rxDropped, _ := readFileString(basePath + "/rx_dropped")
	txDropped, _ := readFileString(basePath + "/tx_dropped")

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"interface":  name,
		"rx_bytes":   rxBytes,
		"tx_bytes":   txBytes,
		"rx_packets": rxPackets,
		"tx_packets": txPackets,
		"rx_errors":  rxErrors,
		"tx_errors":  txErrors,
		"rx_dropped": rxDropped,
		"tx_dropped": txDropped,
	})
}

// GetTrafficStats returns network traffic statistics for all interfaces
// @Summary Get network traffic statistics
// @Description Returns TX/RX bytes for all interfaces from /proc/net/dev
// @Tags Network
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /network/traffic [get]
func (h *HALHandler) GetTrafficStats(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to read /proc/net/dev: %v", err))
		return
	}

	interfaces := make(map[string]map[string]int64)
	lines := strings.Split(string(data), "\n")

	for _, line := range lines[2:] { // Skip header lines
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		iface := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])

		if len(fields) >= 12 {
			rxBytes, _ := strconv.ParseInt(fields[0], 10, 64)
			rxPackets, _ := strconv.ParseInt(fields[1], 10, 64)
			rxErrors, _ := strconv.ParseInt(fields[2], 10, 64)
			rxDropped, _ := strconv.ParseInt(fields[3], 10, 64)
			txBytes, _ := strconv.ParseInt(fields[8], 10, 64)
			txPackets, _ := strconv.ParseInt(fields[9], 10, 64)
			txErrors, _ := strconv.ParseInt(fields[10], 10, 64)
			txDropped, _ := strconv.ParseInt(fields[11], 10, 64)

			interfaces[iface] = map[string]int64{
				"rx_bytes":   rxBytes,
				"rx_packets": rxPackets,
				"rx_errors":  rxErrors,
				"rx_dropped": rxDropped,
				"tx_bytes":   txBytes,
				"tx_packets": txPackets,
				"tx_errors":  txErrors,
				"tx_dropped": txDropped,
			}
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"interfaces": interfaces,
		"source":     "/proc/net/dev",
	})
}

// BringInterfaceUp brings an interface up
// @Summary Bring interface up
// @Description Brings a network interface up using ip link set
// @Tags Network
// @Produce json
// @Param name path string true "Interface name"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/interface/{name}/up [post]
func (h *HALHandler) BringInterfaceUp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	output, err := exec.Command("ip", "link", "set", name, "up").CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to bring up %s: %v - %s", name, err, string(output)))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"interface": name,
		"state":     "up",
	})
}

// BringInterfaceDown brings an interface down
// @Summary Bring interface down
// @Description Brings a network interface down using ip link set
// @Tags Network
// @Produce json
// @Param name path string true "Interface name"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/interface/{name}/down [post]
func (h *HALHandler) BringInterfaceDown(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	output, err := exec.Command("ip", "link", "set", name, "down").CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to bring down %s: %v - %s", name, err, string(output)))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"interface": name,
		"state":     "down",
	})
}

// GetNetworkStatus returns overall network status
// @Summary Get network status
// @Description Returns overall network connectivity status including default route and internet check
// @Tags Network
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /network/status [get]
func (h *HALHandler) GetNetworkStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"connected": false,
		"mode":      "unknown",
	}

	// Check default route
	output, err := exec.Command("ip", "route", "show", "default").Output()
	if err == nil && len(output) > 0 {
		status["connected"] = true
		status["default_route"] = strings.TrimSpace(string(output))
	}

	// Check internet connectivity
	_, err = exec.Command("ping", "-c", "1", "-W", "2", "8.8.8.8").Output()
	status["internet"] = err == nil

	// Determine mode based on interfaces
	if _, err := os.Stat("/sys/class/net/eth0"); err == nil {
		carrier, _ := os.ReadFile("/sys/class/net/eth0/carrier")
		if strings.TrimSpace(string(carrier)) == "1" {
			status["mode"] = "ethernet"
		}
	}

	jsonResponse(w, http.StatusOK, status)
}

// ScanWiFi scans for WiFi networks
// @Summary Scan WiFi networks
// @Description Scans for available WiFi networks on specified interface using iw
// @Tags Network
// @Produce json
// @Param iface path string true "WiFi interface name"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /network/wifi/scan/{iface} [get]
func (h *HALHandler) ScanWiFi(w http.ResponseWriter, r *http.Request) {
	iface := chi.URLParam(r, "iface")
	if iface == "" {
		iface = "wlan0"
	}

	output, err := exec.Command("iw", iface, "scan").Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("scan failed: %v", err))
		return
	}

	networks := parseWifiScan(string(output))

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"interface": iface,
		"networks":  networks,
		"count":     len(networks),
	})
}

// parseWifiScan parses iw scan output
func parseWifiScan(output string) []map[string]interface{} {
	var networks []map[string]interface{}
	var current map[string]interface{}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "BSS ") {
			if current != nil {
				networks = append(networks, current)
			}
			current = make(map[string]interface{})
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				bssid := strings.TrimSuffix(parts[1], "(on")
				current["bssid"] = bssid
			}
		} else if current != nil {
			if strings.HasPrefix(line, "SSID:") {
				current["ssid"] = strings.TrimPrefix(line, "SSID: ")
			} else if strings.HasPrefix(line, "signal:") {
				current["signal"] = strings.TrimPrefix(line, "signal: ")
			} else if strings.HasPrefix(line, "freq:") {
				current["frequency"] = strings.TrimPrefix(line, "freq: ")
			}
		}
	}

	if current != nil {
		networks = append(networks, current)
	}

	return networks
}

// ConnectWiFi connects to a WiFi network
// @Summary Connect to WiFi
// @Description Connects to a WiFi network using wpa_supplicant
// @Tags Network
// @Accept json
// @Produce json
// @Param request body object true "WiFi connection request" example({"ssid":"MyNetwork","password":"secret","interface":"wlan0"})
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/wifi/connect [post]
func (h *HALHandler) ConnectWiFi(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SSID      string `json:"ssid"`
		Password  string `json:"password"`
		Interface string `json:"interface"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SSID == "" {
		errorResponse(w, http.StatusBadRequest, "ssid required")
		return
	}

	if req.Interface == "" {
		req.Interface = "wlan0"
	}

	// Use wpa_cli to connect
	output, err := exec.Command("wpa_cli", "-i", req.Interface, "add_network").Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to add network: %v", err))
		return
	}

	networkID := strings.TrimSpace(string(output))

	// Set SSID
	_, err = exec.Command("wpa_cli", "-i", req.Interface, "set_network", networkID, "ssid", fmt.Sprintf("\"%s\"", req.SSID)).Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to set ssid: %v", err))
		return
	}

	// Set password
	if req.Password != "" {
		_, err = exec.Command("wpa_cli", "-i", req.Interface, "set_network", networkID, "psk", fmt.Sprintf("\"%s\"", req.Password)).Output()
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to set password: %v", err))
			return
		}
	} else {
		_, err = exec.Command("wpa_cli", "-i", req.Interface, "set_network", networkID, "key_mgmt", "NONE").Output()
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to set key_mgmt: %v", err))
			return
		}
	}

	// Enable network
	_, err = exec.Command("wpa_cli", "-i", req.Interface, "enable_network", networkID).Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to enable network: %v", err))
		return
	}

	// Save config
	exec.Command("wpa_cli", "-i", req.Interface, "save_config").Run()

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"ssid":       req.SSID,
		"interface":  req.Interface,
		"network_id": networkID,
	})
}

// DisconnectWiFi disconnects from current WiFi
// @Summary Disconnect WiFi
// @Description Disconnects from current WiFi network using wpa_cli
// @Tags Network
// @Produce json
// @Param iface path string true "WiFi interface name"
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/wifi/disconnect/{iface} [post]
func (h *HALHandler) DisconnectWiFi(w http.ResponseWriter, r *http.Request) {
	iface := chi.URLParam(r, "iface")
	if iface == "" {
		iface = "wlan0"
	}

	_, err := exec.Command("wpa_cli", "-i", iface, "disconnect").Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("disconnect failed: %v", err))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"interface": iface,
	})
}

// GetAPStatus returns access point status
// @Summary Get AP status
// @Description Returns access point status from hostapd_cli
// @Tags Network
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /network/ap/status [get]
func (h *HALHandler) GetAPStatus(w http.ResponseWriter, r *http.Request) {
	output, err := exec.Command("hostapd_cli", "status").Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get AP status: %v", err))
		return
	}

	status := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			status[parts[0]] = parts[1]
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status": status,
	})
}

// GetAPClients returns connected AP clients
// @Summary Get AP clients
// @Description Returns list of clients connected to the access point using hostapd_cli
// @Tags Network
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /network/ap/clients [get]
func (h *HALHandler) GetAPClients(w http.ResponseWriter, r *http.Request) {
	output, err := exec.Command("hostapd_cli", "all_sta").Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get AP clients: %v", err))
		return
	}

	var clients []map[string]string
	var current map[string]string

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// MAC address line starts a new client
		if len(line) == 17 && strings.Count(line, ":") == 5 {
			if current != nil {
				clients = append(clients, current)
			}
			current = map[string]string{"mac": line}
		} else if current != nil {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				current[parts[0]] = parts[1]
			}
		}
	}
	if current != nil {
		clients = append(clients, current)
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"clients": clients,
		"count":   len(clients),
	})
}

// DisconnectAPClient disconnects a client from the AP
// @Summary Disconnect AP client
// @Description Disconnects a client from the access point by MAC address using hostapd_cli
// @Tags Network
// @Accept json
// @Produce json
// @Param request body object true "Disconnect request" example({"mac":"AA:BB:CC:DD:EE:FF"})
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/ap/disconnect [post]
func (h *HALHandler) DisconnectAPClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MAC string `json:"mac"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.MAC == "" {
		errorResponse(w, http.StatusBadRequest, "mac address required")
		return
	}

	output, err := exec.Command("hostapd_cli", "disassociate", req.MAC).CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to disconnect client: %v - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("client %s disconnected", req.MAC))
}

// BlockAPClient blocks a client from the AP
// @Summary Block AP client
// @Description Blocks a client from connecting to the access point using hostapd_cli deny_acl
// @Tags Network
// @Accept json
// @Produce json
// @Param request body object true "Block request" example({"mac":"AA:BB:CC:DD:EE:FF"})
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/ap/block [post]
func (h *HALHandler) BlockAPClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MAC string `json:"mac"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.MAC == "" {
		errorResponse(w, http.StatusBadRequest, "mac address required")
		return
	}

	// First disconnect, then deny
	exec.Command("hostapd_cli", "disassociate", req.MAC).Run()

	output, err := exec.Command("hostapd_cli", "deny_acl", "ADD_MAC", req.MAC).CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to block client: %v - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("client %s blocked", req.MAC))
}
