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

// parseWifiScan parses iw scan output into structured data
func parseWifiScan(output string) []map[string]interface{} {
	var networks []map[string]interface{}
	var current map[string]interface{}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "BSS ") {
			if current != nil {
				networks = append(networks, current)
			}
			current = make(map[string]interface{})
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				bssid := strings.TrimSuffix(parts[1], "(on")
				current["bssid"] = bssid
			}
			current["security"] = "Open"
		} else if current != nil {
			if strings.HasPrefix(trimmed, "SSID:") {
				current["ssid"] = strings.TrimSpace(strings.TrimPrefix(trimmed, "SSID:"))
			} else if strings.HasPrefix(trimmed, "signal:") {
				sigStr := strings.TrimPrefix(trimmed, "signal: ")
				sigStr = strings.TrimSuffix(sigStr, " dBm")
				sigStr = strings.TrimSpace(sigStr)
				if v, err := strconv.ParseFloat(sigStr, 64); err == nil {
					current["signal"] = int(v)
				}
			} else if strings.HasPrefix(trimmed, "freq:") {
				freqStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "freq:"))
				if v, err := strconv.Atoi(freqStr); err == nil {
					current["frequency"] = v
					// Derive channel from frequency
					current["channel"] = freqToChannel(v)
				}
			} else if strings.Contains(trimmed, "WPA") || strings.Contains(trimmed, "RSN") {
				if strings.Contains(trimmed, "RSN") {
					current["security"] = "WPA2"
				} else if strings.Contains(trimmed, "WPA") {
					// Don't downgrade from WPA2
					if current["security"] != "WPA2" {
						current["security"] = "WPA"
					}
				}
			} else if strings.Contains(trimmed, "WEP") {
				if current["security"] == "Open" {
					current["security"] = "WEP"
				}
			}
		}
	}

	if current != nil {
		networks = append(networks, current)
	}

	return networks
}

// freqToChannel converts WiFi frequency in MHz to channel number
func freqToChannel(freq int) int {
	switch {
	case freq >= 2412 && freq <= 2484:
		if freq == 2484 {
			return 14
		}
		return (freq - 2407) / 5
	case freq >= 5170 && freq <= 5825:
		return (freq - 5000) / 5
	case freq >= 5955 && freq <= 7115:
		return (freq - 5950) / 5
	default:
		return 0
	}
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
// @Description Returns structured access point status from hostapd_cli with hostapd.conf fallback
// @Tags Network
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /network/ap/status [get]
func (h *HALHandler) GetAPStatus(w http.ResponseWriter, r *http.Request) {
	result := map[string]interface{}{
		"active":    false,
		"ssid":      "",
		"channel":   0,
		"interface": "wlan0",
		"frequency": 0,
		"bssid":     "",
		"clients":   0,
	}

	// Try hostapd_cli status first
	output, err := execWithTimeout(r.Context(), "hostapd_cli", "status")
	if err == nil {
		raw := parseKeyValue(output)
		// hostapd_cli uses keys like ssid[0], bssid[0] — normalize them
		if v, ok := raw["state"]; ok {
			result["active"] = (v == "ENABLED" || v == "COUNTRY_UPDATE" || v == "HT_SCAN" || v == "DFS")
			result["state"] = v
		}
		if v, ok := raw["ssid[0]"]; ok {
			result["ssid"] = v
		} else if v, ok := raw["ssid"]; ok {
			result["ssid"] = v
		}
		if v, ok := raw["channel"]; ok {
			if ch, err := strconv.Atoi(v); err == nil {
				result["channel"] = ch
			}
		}
		if v, ok := raw["freq"]; ok {
			if freq, err := strconv.Atoi(v); err == nil {
				result["frequency"] = freq
			}
		}
		if v, ok := raw["bssid[0]"]; ok {
			result["bssid"] = v
		} else if v, ok := raw["bssid"]; ok {
			result["bssid"] = v
		}
		if v, ok := raw["num_sta[0]"]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				result["clients"] = n
			}
		}
		// Detect interface from "Selected interface" line
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "Selected interface") {
				// "Selected interface 'wlan0'"
				parts := strings.SplitN(line, "'", 3)
				if len(parts) >= 2 {
					result["interface"] = parts[1]
				}
			}
		}
	} else {
		log.Printf("GetAPStatus: hostapd_cli failed: %v, falling back to config file", err)
	}

	// If ssid is still empty, fall back to hostapd.conf
	if result["ssid"] == "" {
		result["ssid"], result["channel"], result["interface"] = parseHostapdConf()
	}

	// Check if hostapd service is active (overrides hostapd_cli state if needed)
	if !result["active"].(bool) {
		svcOutput, err := execWithTimeout(r.Context(), "systemctl", "is-active", "hostapd")
		if err == nil && strings.TrimSpace(svcOutput) == "active" {
			result["active"] = true
		}
	}

	jsonResponse(w, http.StatusOK, result)
}

// parseKeyValue parses key=value output (used by hostapd_cli, wpa_cli, etc.)
func parseKeyValue(output string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

// parseHostapdConf reads SSID, channel, and interface from hostapd.conf as fallback
func parseHostapdConf() (ssid string, channel int, iface string) {
	ssid = "CubeOS"
	iface = "wlan0"

	confPaths := []string{
		"/etc/hostapd/hostapd.conf",
		"/etc/hostapd.conf",
	}

	for _, path := range confPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			switch key {
			case "ssid":
				ssid = val
			case "channel":
				if ch, err := strconv.Atoi(val); err == nil {
					channel = ch
				}
			case "interface":
				iface = val
			}
		}
		break // Use first found config
	}
	return
}

// GetAPClients returns connected AP clients
// @Summary Get AP clients
// @Description Returns list of clients connected to the access point, enriched with DHCP lease data
// @Tags Network
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /network/ap/clients [get]
func (h *HALHandler) GetAPClients(w http.ResponseWriter, r *http.Request) {
	// Load DHCP leases for IP/hostname enrichment
	leases := loadDHCPLeases()

	var clients []map[string]interface{}

	// Try hostapd_cli all_sta first
	output, err := execWithTimeout(r.Context(), "hostapd_cli", "all_sta")
	if err == nil {
		var currentMAC string
		var current map[string]interface{}

		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// MAC address line starts a new client (17 chars, 5 colons)
			if len(line) == 17 && strings.Count(line, ":") == 5 {
				if current != nil {
					clients = append(clients, current)
				}
				currentMAC = strings.ToUpper(line)
				current = map[string]interface{}{
					"mac_address": currentMAC,
					"ip_address":  "",
					"hostname":    "",
				}
				// Enrich from DHCP leases
				if lease, ok := leases[strings.ToLower(line)]; ok {
					current["ip_address"] = lease.ip
					current["hostname"] = lease.hostname
				}
			} else if current != nil {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					val := strings.TrimSpace(parts[1])
					switch key {
					case "connected_time":
						if v, err := strconv.ParseInt(val, 10, 64); err == nil {
							current["connected_time"] = v
						}
					case "signal":
						// hostapd reports signal in dBm, may have trailing text
						sig := strings.Fields(val)
						if len(sig) > 0 {
							if v, err := strconv.Atoi(sig[0]); err == nil {
								current["signal"] = v
							}
						}
					case "rx_bytes":
						if v, err := strconv.ParseInt(val, 10, 64); err == nil {
							current["rx_bytes"] = v
						}
					case "tx_bytes":
						if v, err := strconv.ParseInt(val, 10, 64); err == nil {
							current["tx_bytes"] = v
						}
					}
				}
			}
		}
		if current != nil {
			clients = append(clients, current)
		}
	} else {
		log.Printf("GetAPClients: hostapd_cli failed: %v, falling back to DHCP leases", err)
		// Fall back: report DHCP clients on the AP subnet as connected
		for _, lease := range leases {
			if strings.HasPrefix(lease.ip, "10.42.24.") && lease.ip != "10.42.24.1" {
				clients = append(clients, map[string]interface{}{
					"mac_address": strings.ToUpper(lease.mac),
					"ip_address":  lease.ip,
					"hostname":    lease.hostname,
					"source":      "dhcp_lease",
				})
			}
		}
	}

	if clients == nil {
		clients = []map[string]interface{}{}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"clients": clients,
		"count":   len(clients),
	})
}

// dhcpLease holds parsed DHCP lease data
type dhcpLease struct {
	mac      string
	ip       string
	hostname string
	expiry   string
}

// loadDHCPLeases reads DHCP lease files and returns a map keyed by lowercase MAC
func loadDHCPLeases() map[string]dhcpLease {
	leases := make(map[string]dhcpLease)

	leasePaths := []string{
		"/var/lib/misc/dnsmasq.leases",
		"/tmp/dnsmasq.leases",
		"/etc/pihole/dhcp.leases",
		"/var/lib/dhcp/dhcpd.leases",
		// Pi-hole in Docker paths
		"/cubeos/coreapps/pihole/appdata/etc-dnsmasq.d/dhcp.leases",
		"/cubeos/coreapps/pihole/appdata/etc-pihole/dhcp.leases",
	}

	for _, path := range leasePaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// dnsmasq lease format: <expiry> <mac> <ip> <hostname> <client-id>
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				mac := strings.ToLower(fields[1])
				leases[mac] = dhcpLease{
					mac:      mac,
					ip:       fields[2],
					hostname: fields[3],
					expiry:   fields[0],
				}
			}
		}
		if len(leases) > 0 {
			break // Use first file that has data
		}
	}

	return leases
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
