package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// getDefaultInternetCheckIP returns the IP used for internet connectivity checks.
func getDefaultInternetCheckIP() string {
	if ip := os.Getenv("HAL_INTERNET_CHECK_IP"); ip != "" {
		return ip
	}
	return "8.8.8.8"
}

// getDefaultWiFiInterface returns the default WiFi interface name.
func getDefaultWiFiInterface() string {
	if iface := os.Getenv("HAL_DEFAULT_WIFI_INTERFACE"); iface != "" {
		return iface
	}
	return "wlan0"
}

// ListInterfaces returns all network interfaces
// @Summary List network interfaces
// @Description Returns all network interfaces with their status
// @Tags Network
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /network/interfaces [get]
func (h *HALHandler) ListInterfaces(w http.ResponseWriter, r *http.Request) {
	output, err := execWithTimeout(r.Context(), "ip", "-j", "addr")
	if err != nil {
		// Fallback to non-JSON output
		output, err = execWithTimeout(r.Context(), "ip", "addr")
		if err != nil {
			log.Printf("ListInterfaces: %v", err)
			errorResponse(w, http.StatusInternalServerError, "failed to get interfaces")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"raw": output,
		})
		return
	}

	var interfaces []interface{}
	if err := json.Unmarshal([]byte(output), &interfaces); err != nil {
		log.Printf("ListInterfaces: parse error: %v", err)
		errorResponse(w, http.StatusInternalServerError, "failed to parse interfaces")
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
	if err := validateInterfaceName(name); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	output, err := execWithTimeout(r.Context(), "ip", "-j", "addr", "show", name)
	if err != nil {
		errorResponse(w, http.StatusNotFound, "interface not found")
		return
	}

	var iface []interface{}
	if err := json.Unmarshal([]byte(output), &iface); err != nil {
		log.Printf("GetInterface(%s): parse error: %v", name, err)
		errorResponse(w, http.StatusInternalServerError, "failed to parse interface")
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
	if err := validateInterfaceName(name); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// validateInterfaceName() blocks path traversal characters (no / or ..)
	basePath := fmt.Sprintf("/sys/class/net/%s/statistics", name)

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		errorResponse(w, http.StatusNotFound, "interface not found")
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
		log.Printf("GetTrafficStats: %v", err)
		errorResponse(w, http.StatusInternalServerError, "failed to read network statistics")
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
	if err := validateInterfaceName(name); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	_, err := execWithTimeout(r.Context(), "ip", "link", "set", name, "up")
	if err != nil {
		log.Printf("BringInterfaceUp(%s): %v", name, err)
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("bring interface up", err))
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
	if err := validateInterfaceName(name); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	_, err := execWithTimeout(r.Context(), "ip", "link", "set", name, "down")
	if err != nil {
		log.Printf("BringInterfaceDown(%s): %v", name, err)
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("bring interface down", err))
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
	output, err := execWithTimeout(r.Context(), "ip", "route", "show", "default")
	if err == nil && len(output) > 0 {
		status["connected"] = true
		status["default_route"] = strings.TrimSpace(output)
	}

	// Check internet connectivity
	checkIP := getDefaultInternetCheckIP()
	_, err = execWithTimeout(r.Context(), "ping", "-c", "1", "-W", "2", checkIP)
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
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/wifi/scan/{iface} [get]
func (h *HALHandler) ScanWiFi(w http.ResponseWriter, r *http.Request) {
	iface := chi.URLParam(r, "iface")
	if iface == "" {
		iface = getDefaultWiFiInterface()
	}
	if err := validateInterfaceName(iface); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	output, err := execWithTimeout(r.Context(), "iw", iface, "scan")
	if err != nil {
		log.Printf("ScanWiFi(%s): %v", iface, err)
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("WiFi scan", err))
		return
	}

	networks := parseWifiScan(output)

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
	r = limitBody(r, 1<<20) // 1MB

	var req struct {
		SSID      string `json:"ssid"`
		Password  string `json:"password"`
		Interface string `json:"interface"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate SSID
	if err := validateSSID(req.SSID); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate password if provided
	if req.Password != "" {
		if err := validateWiFiPassword(req.Password); err != nil {
			errorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if req.Interface == "" {
		req.Interface = getDefaultWiFiInterface()
	}
	if err := validateInterfaceName(req.Interface); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Use wpa_cli to connect
	output, err := execWithTimeout(r.Context(), "wpa_cli", "-i", req.Interface, "add_network")
	if err != nil {
		log.Printf("ConnectWiFi: add_network: %v", err)
		errorResponse(w, http.StatusInternalServerError, "failed to add network")
		return
	}

	networkID := strings.TrimSpace(output)

	// Set SSID
	_, err = execWithTimeout(r.Context(), "wpa_cli", "-i", req.Interface, "set_network", networkID, "ssid", fmt.Sprintf("\"%s\"", req.SSID))
	if err != nil {
		log.Printf("ConnectWiFi: set_network ssid: %v", err)
		errorResponse(w, http.StatusInternalServerError, "failed to set SSID")
		return
	}

	// Set password
	if req.Password != "" {
		_, err = execWithTimeout(r.Context(), "wpa_cli", "-i", req.Interface, "set_network", networkID, "psk", fmt.Sprintf("\"%s\"", req.Password))
		if err != nil {
			log.Printf("ConnectWiFi: set_network psk: %v", err)
			errorResponse(w, http.StatusInternalServerError, "failed to set password")
			return
		}
	} else {
		_, err = execWithTimeout(r.Context(), "wpa_cli", "-i", req.Interface, "set_network", networkID, "key_mgmt", "NONE")
		if err != nil {
			log.Printf("ConnectWiFi: set_network key_mgmt: %v", err)
			errorResponse(w, http.StatusInternalServerError, "failed to set key management")
			return
		}
	}

	// Enable network
	_, err = execWithTimeout(r.Context(), "wpa_cli", "-i", req.Interface, "enable_network", networkID)
	if err != nil {
		log.Printf("ConnectWiFi: enable_network: %v", err)
		errorResponse(w, http.StatusInternalServerError, "failed to enable network")
		return
	}

	// Save config (best effort)
	_, _ = execWithTimeout(r.Context(), "wpa_cli", "-i", req.Interface, "save_config")

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
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/wifi/disconnect/{iface} [post]
func (h *HALHandler) DisconnectWiFi(w http.ResponseWriter, r *http.Request) {
	iface := chi.URLParam(r, "iface")
	if iface == "" {
		iface = getDefaultWiFiInterface()
	}
	if err := validateInterfaceName(iface); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	_, err := execWithTimeout(r.Context(), "wpa_cli", "-i", iface, "disconnect")
	if err != nil {
		log.Printf("DisconnectWiFi(%s): %v", iface, err)
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("WiFi disconnect", err))
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
	output, err := execWithTimeout(r.Context(), "hostapd_cli", "status")
	if err != nil {
		log.Printf("GetAPStatus: %v", err)
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("get AP status", err))
		return
	}

	status := make(map[string]string)
	lines := strings.Split(output, "\n")
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
	output, err := execWithTimeout(r.Context(), "hostapd_cli", "all_sta")
	if err != nil {
		log.Printf("GetAPClients: %v", err)
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("get AP clients", err))
		return
	}

	var clients []map[string]string
	var current map[string]string

	lines := strings.Split(output, "\n")
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
	r = limitBody(r, 1<<20) // 1MB

	var req struct {
		MAC string `json:"mac"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := validateMACAddress(req.MAC); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	_, err := execWithTimeout(r.Context(), "hostapd_cli", "disassociate", req.MAC)
	if err != nil {
		log.Printf("DisconnectAPClient(%s): %v", req.MAC, err)
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("disconnect AP client", err))
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
	r = limitBody(r, 1<<20) // 1MB

	var req struct {
		MAC string `json:"mac"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := validateMACAddress(req.MAC); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// First disconnect, then deny
	_, _ = execWithTimeout(r.Context(), "hostapd_cli", "disassociate", req.MAC)

	_, err := execWithTimeout(r.Context(), "hostapd_cli", "deny_acl", "ADD_MAC", req.MAC)
	if err != nil {
		log.Printf("BlockAPClient(%s): %v", req.MAC, err)
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("block AP client", err))
		return
	}

	successResponse(w, fmt.Sprintf("client %s blocked", req.MAC))
}

// UnblockAPClient removes a MAC address from the AP blocklist
// @Summary Unblock AP client
// @Description Removes a MAC address from the access point deny list using hostapd_cli
// @Tags Network
// @Produce json
// @Param mac path string true "MAC address to unblock"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/ap/unblock/{mac} [post]
func (h *HALHandler) UnblockAPClient(w http.ResponseWriter, r *http.Request) {
	mac := chi.URLParam(r, "mac")
	if err := validateMACAddress(mac); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	_, err := execWithTimeout(r.Context(), "hostapd_cli", "deny_acl", "DEL_MAC", mac)
	if err != nil {
		log.Printf("UnblockAPClient(%s): %v", mac, err)
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("unblock AP client", err))
		return
	}

	successResponse(w, fmt.Sprintf("client %s unblocked", mac))
}

// APBlocklistResponse represents the list of blocked MAC addresses
type APBlocklistResponse struct {
	MACs []string `json:"macs"`
}

// GetAPBlocklist returns the list of blocked MAC addresses from hostapd deny ACL
// @Summary Get AP blocklist
// @Description Returns the list of MAC addresses blocked from the access point
// @Tags Network
// @Produce json
// @Success 200 {object} APBlocklistResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/ap/blocklist [get]
func (h *HALHandler) GetAPBlocklist(w http.ResponseWriter, r *http.Request) {
	output, err := execWithTimeout(r.Context(), "hostapd_cli", "deny_acl", "SHOW")
	if err != nil {
		// If hostapd isn't running, return empty list (not an error)
		jsonResponse(w, http.StatusOK, APBlocklistResponse{MACs: []string{}})
		return
	}

	macs := []string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		mac := strings.TrimSpace(line)
		if mac != "" && validateMACAddress(mac) == nil {
			macs = append(macs, strings.ToUpper(mac))
		}
	}

	jsonResponse(w, http.StatusOK, APBlocklistResponse{MACs: macs})
}

// RequestDHCP requests a DHCP lease on an interface
// @Summary Request DHCP lease
// @Description Requests a DHCP lease on the specified network interface using dhclient
// @Tags Network
// @Accept json
// @Produce json
// @Param request body object true "DHCP request" example({"interface":"eth0"})
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/dhcp/request [post]
func (h *HALHandler) RequestDHCP(w http.ResponseWriter, r *http.Request) {
	r = limitBody(r, 1<<20)

	var req struct {
		Interface string `json:"interface"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Interface == "" {
		errorResponse(w, http.StatusBadRequest, "interface is required")
		return
	}
	if err := validateInterfaceName(req.Interface); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Release existing lease first (best effort)
	_, _ = execWithTimeout(r.Context(), "dhclient", "-r", req.Interface)

	// Request new lease
	_, err := execWithTimeout(r.Context(), "dhclient", req.Interface)
	if err != nil {
		log.Printf("RequestDHCP(%s): %v", req.Interface, err)
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("DHCP request", err))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"interface": req.Interface,
		"message":   "DHCP lease requested",
	})
}

// SetStaticIP sets a static IP address on an interface
// @Summary Set static IP
// @Description Sets a static IP address on the specified network interface using ip addr
// @Tags Network
// @Accept json
// @Produce json
// @Param request body object true "Static IP config" example({"interface":"eth0","ip":"10.42.24.100/24","gateway":"10.42.24.1"})
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/ip/static [post]
func (h *HALHandler) SetStaticIP(w http.ResponseWriter, r *http.Request) {
	r = limitBody(r, 1<<20)

	var req struct {
		Interface string `json:"interface"`
		IP        string `json:"ip"`
		Gateway   string `json:"gateway"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Interface == "" || req.IP == "" {
		errorResponse(w, http.StatusBadRequest, "interface and ip are required")
		return
	}
	if err := validateInterfaceName(req.Interface); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateCIDROrIP(req.IP); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid IP: "+err.Error())
		return
	}
	if req.Gateway != "" {
		if err := validateCIDROrIP(req.Gateway); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid gateway: "+err.Error())
			return
		}
	}

	// Flush existing addresses on interface
	_, _ = execWithTimeout(r.Context(), "ip", "addr", "flush", "dev", req.Interface)

	// Add static IP
	_, err := execWithTimeout(r.Context(), "ip", "addr", "add", req.IP, "dev", req.Interface)
	if err != nil {
		log.Printf("SetStaticIP(%s, %s): addr add: %v", req.Interface, req.IP, err)
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("set static IP", err))
		return
	}

	// Set default gateway if provided
	if req.Gateway != "" {
		// Remove existing default route via this interface (best effort)
		_, _ = execWithTimeout(r.Context(), "ip", "route", "del", "default", "dev", req.Interface)

		_, err := execWithTimeout(r.Context(), "ip", "route", "add", "default", "via", req.Gateway, "dev", req.Interface)
		if err != nil {
			log.Printf("SetStaticIP(%s): route add default via %s: %v", req.Interface, req.Gateway, err)
			// Don't fail — IP is already set, just warn about gateway
			jsonResponse(w, http.StatusOK, map[string]interface{}{
				"success":   true,
				"interface": req.Interface,
				"ip":        req.IP,
				"warning":   "IP set but gateway route failed",
			})
			return
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"interface": req.Interface,
		"ip":        req.IP,
		"gateway":   req.Gateway,
		"message":   "static IP configured",
	})
}
