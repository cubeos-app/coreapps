package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// ============================================================================
// Network Interface Types
// ============================================================================

// NetworkInterface represents a network interface.
// @Description Network interface information
type NetworkInterface struct {
	Name          string   `json:"name" example:"eth0"`
	IsUp          bool     `json:"is_up" example:"true"`
	MACAddress    string   `json:"mac_address" example:"dc:a6:32:12:34:56"`
	IPv4Addresses []string `json:"ipv4_addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
	MTU           int      `json:"mtu" example:"1500"`
	IsWireless    bool     `json:"is_wireless" example:"false"`
}

// InterfacesResponse represents the response for listing interfaces.
// @Description List of network interfaces
type InterfacesResponse struct {
	Interfaces []NetworkInterface `json:"interfaces"`
}

// TrafficStats represents interface traffic statistics.
// @Description Network interface traffic statistics
type TrafficStats struct {
	Interface string           `json:"interface" example:"eth0"`
	Stats     map[string]int64 `json:"stats"`
}

// ============================================================================
// WiFi Types
// ============================================================================

// WiFiNetwork represents a WiFi network from scan.
// @Description WiFi network information
type WiFiNetwork struct {
	SSID      string `json:"ssid" example:"MyNetwork"`
	BSSID     string `json:"bssid" example:"00:11:22:33:44:55"`
	Signal    int    `json:"signal" example:"-45"`
	Channel   int    `json:"channel" example:"6"`
	Security  string `json:"security" example:"WPA2"`
	Frequency int    `json:"frequency,omitempty" example:"2437"`
}

// WiFiScanResponse represents WiFi scan results.
// @Description WiFi scan results
type WiFiScanResponse struct {
	Interface string        `json:"interface" example:"wlan0"`
	Networks  []WiFiNetwork `json:"networks"`
	Count     int           `json:"count" example:"5"`
}

// WiFiConnectRequest represents WiFi connection request.
// @Description WiFi connection parameters
type WiFiConnectRequest struct {
	Interface string `json:"interface" example:"wlan0"`
	SSID      string `json:"ssid" example:"MyNetwork"`
	Password  string `json:"password" example:"secret123"`
}

// ============================================================================
// Access Point Types
// ============================================================================

// APClient represents a connected AP client.
// @Description Connected Access Point client
type APClient struct {
	MAC        string `json:"mac" example:"dc:a6:32:12:34:56"`
	IP         string `json:"ip,omitempty" example:"10.42.24.100"`
	Hostname   string `json:"hostname,omitempty" example:"iPhone"`
	Signal     int    `json:"signal,omitempty" example:"-45"`
	RxBytes    int64  `json:"rx_bytes,omitempty"`
	TxBytes    int64  `json:"tx_bytes,omitempty"`
	Connected  string `json:"connected,omitempty" example:"2h 15m"`
	Authorized bool   `json:"authorized" example:"true"`
}

// APClientsResponse represents AP clients list.
// @Description List of connected AP clients
type APClientsResponse struct {
	Clients []APClient `json:"clients"`
	Count   int        `json:"count" example:"3"`
}

// APStatusResponse represents AP status.
// @Description Access Point status
type APStatusResponse struct {
	Enabled   bool   `json:"enabled" example:"true"`
	SSID      string `json:"ssid" example:"CubeOS"`
	Channel   int    `json:"channel" example:"6"`
	Interface string `json:"interface" example:"wlan0"`
	Clients   int    `json:"clients" example:"3"`
}

// APDisconnectRequest represents AP client disconnect request.
// @Description AP client disconnect parameters
type APDisconnectRequest struct {
	MAC string `json:"mac" example:"dc:a6:32:12:34:56"`
}

// ============================================================================
// Network Interface Handlers
// ============================================================================

// ListInterfaces returns all network interfaces.
// @Summary List network interfaces
// @Description Returns all network interfaces with their configuration
// @Tags Network
// @Accept json
// @Produce json
// @Success 200 {object} InterfacesResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/interfaces [get]
func (h *HALHandler) ListInterfaces(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list interfaces: "+err.Error())
		return
	}

	var interfaces []NetworkInterface
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}
		iface := h.getInterfaceInfo(name)
		interfaces = append(interfaces, iface)
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"interfaces": interfaces,
	})
}

// GetInterface returns info about a specific interface.
// @Summary Get interface details
// @Description Returns detailed information about a specific network interface
// @Tags Network
// @Accept json
// @Produce json
// @Param name path string true "Interface name" example(eth0)
// @Success 200 {object} NetworkInterface
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /network/interface/{name} [get]
func (h *HALHandler) GetInterface(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	if _, err := os.Stat(filepath.Join("/sys/class/net", name)); os.IsNotExist(err) {
		errorResponse(w, http.StatusNotFound, "interface not found: "+name)
		return
	}

	iface := h.getInterfaceInfo(name)
	jsonResponse(w, http.StatusOK, iface)
}

// GetInterfaceTraffic returns traffic stats for an interface.
// @Summary Get interface traffic statistics
// @Description Returns RX/TX bytes, packets, errors, and dropped counts
// @Tags Network
// @Accept json
// @Produce json
// @Param name path string true "Interface name" example(eth0)
// @Success 200 {object} TrafficStats
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /network/interface/{name}/traffic [get]
func (h *HALHandler) GetInterfaceTraffic(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	basePath := filepath.Join("/sys/class/net", name)
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		errorResponse(w, http.StatusNotFound, "interface not found: "+name)
		return
	}

	statsPath := filepath.Join(basePath, "statistics")
	stats := map[string]int64{}

	files := []string{"rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"}
	for _, f := range files {
		if data, err := os.ReadFile(filepath.Join(statsPath, f)); err == nil {
			if val, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
				stats[f] = val
			}
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"interface": name,
		"stats":     stats,
	})
}

// BringInterfaceUp brings a network interface up.
// @Summary Bring interface up
// @Description Enables a network interface
// @Tags Network
// @Accept json
// @Produce json
// @Param name path string true "Interface name" example(eth0)
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

	cmd := exec.Command("ip", "link", "set", name, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to bring up interface: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("interface %s brought up", name))
}

// BringInterfaceDown brings a network interface down.
// @Summary Bring interface down
// @Description Disables a network interface
// @Tags Network
// @Accept json
// @Produce json
// @Param name path string true "Interface name" example(eth0)
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

	cmd := exec.Command("ip", "link", "set", name, "down")
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to bring down interface: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("interface %s brought down", name))
}

// GetNetworkStatus returns overall network status.
// @Summary Get network status
// @Description Returns status of all network interfaces
// @Tags Network
// @Accept json
// @Produce json
// @Success 200 {object} InterfacesResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/status [get]
func (h *HALHandler) GetNetworkStatus(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to read interfaces: "+err.Error())
		return
	}

	var interfaces []NetworkInterface
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}
		iface := h.getInterfaceInfo(name)
		interfaces = append(interfaces, iface)
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"interfaces": interfaces,
	})
}

// ============================================================================
// WiFi Handlers
// ============================================================================

// ScanWiFi scans for WiFi networks.
// @Summary Scan WiFi networks
// @Description Scans for available WiFi networks on an interface
// @Tags WiFi
// @Accept json
// @Produce json
// @Param iface path string true "Interface name" example(wlan0)
// @Success 200 {object} WiFiScanResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/wifi/scan/{iface} [get]
func (h *HALHandler) ScanWiFi(w http.ResponseWriter, r *http.Request) {
	iface := chi.URLParam(r, "iface")
	if iface == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	cmd := exec.Command("iwlist", iface, "scan")
	output, err := cmd.Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "scan failed: "+err.Error())
		return
	}

	networks := parseIwlistOutput(string(output))
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"interface": iface,
		"networks":  networks,
		"count":     len(networks),
	})
}

// ConnectWiFi connects to a WiFi network.
// @Summary Connect to WiFi
// @Description Connects to a WiFi network using NetworkManager
// @Tags WiFi
// @Accept json
// @Produce json
// @Param request body WiFiConnectRequest true "Connection parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/wifi/connect [post]
func (h *HALHandler) ConnectWiFi(w http.ResponseWriter, r *http.Request) {
	var req WiFiConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Interface == "" || req.SSID == "" {
		errorResponse(w, http.StatusBadRequest, "interface and ssid required")
		return
	}

	cmd := exec.Command("nmcli", "device", "wifi", "connect", req.SSID, "password", req.Password, "ifname", req.Interface)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("connection failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("connected to %s", req.SSID))
}

// DisconnectWiFi disconnects from WiFi.
// @Summary Disconnect WiFi
// @Description Disconnects from current WiFi network
// @Tags WiFi
// @Accept json
// @Produce json
// @Param iface path string true "Interface name" example(wlan0)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/wifi/disconnect/{iface} [post]
func (h *HALHandler) DisconnectWiFi(w http.ResponseWriter, r *http.Request) {
	iface := chi.URLParam(r, "iface")
	if iface == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	cmd := exec.Command("nmcli", "device", "disconnect", iface)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("disconnect failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("disconnected %s", iface))
}

// ============================================================================
// Access Point Handlers
// ============================================================================

// GetAPStatus returns AP status.
// @Summary Get AP status
// @Description Returns Access Point status from hostapd
// @Tags AccessPoint
// @Accept json
// @Produce json
// @Success 200 {object} APStatusResponse
// @Failure 404 {object} ErrorResponse "hostapd not running"
// @Failure 503 {object} ErrorResponse "hostapd not configured"
// @Router /network/ap/status [get]
func (h *HALHandler) GetAPStatus(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("hostapd_cli", "-i", "wlan0", "status")
	output, err := cmd.Output()
	if err != nil {
		errorResponse(w, http.StatusNotFound, "hostapd not running or not configured")
		return
	}

	status := APStatusResponse{
		Enabled:   true,
		Interface: "wlan0",
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch key {
			case "ssid":
				status.SSID = value
			case "channel":
				status.Channel, _ = strconv.Atoi(value)
			case "num_sta":
				status.Clients, _ = strconv.Atoi(value)
			}
		}
	}

	jsonResponse(w, http.StatusOK, status)
}

// GetAPClients lists connected AP clients.
// @Summary List AP clients
// @Description Returns list of clients connected to the Access Point
// @Tags AccessPoint
// @Accept json
// @Produce json
// @Success 200 {object} APClientsResponse
// @Failure 404 {object} ErrorResponse "hostapd not running"
// @Failure 503 {object} ErrorResponse "hostapd not configured"
// @Router /network/ap/clients [get]
func (h *HALHandler) GetAPClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.getHostapdClients()
	if err != nil {
		errorResponse(w, http.StatusNotFound, "failed to get AP clients: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"clients": clients,
		"count":   len(clients),
	})
}

// DisconnectAPClient disconnects a client from AP.
// @Summary Disconnect AP client
// @Description Disconnects a specific client from the Access Point
// @Tags AccessPoint
// @Accept json
// @Produce json
// @Param request body APDisconnectRequest true "Client MAC address"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/ap/disconnect [post]
func (h *HALHandler) DisconnectAPClient(w http.ResponseWriter, r *http.Request) {
	var req APDisconnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.MAC == "" {
		errorResponse(w, http.StatusBadRequest, "mac address required")
		return
	}

	cmd := exec.Command("hostapd_cli", "-i", "wlan0", "deauthenticate", req.MAC)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("disconnect failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("disconnected client %s", req.MAC))
}

// BlockAPClient blocks a client from AP.
// @Summary Block AP client
// @Description Blocks a client from connecting to the Access Point
// @Tags AccessPoint
// @Accept json
// @Produce json
// @Param request body APDisconnectRequest true "Client MAC address"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /network/ap/block [post]
func (h *HALHandler) BlockAPClient(w http.ResponseWriter, r *http.Request) {
	var req APDisconnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.MAC == "" {
		errorResponse(w, http.StatusBadRequest, "mac address required")
		return
	}

	cmd := exec.Command("hostapd_cli", "-i", "wlan0", "deny_acl", "ADD_MAC", req.MAC)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("block failed: %s - %s", err, string(output)))
		return
	}

	exec.Command("hostapd_cli", "-i", "wlan0", "deauthenticate", req.MAC).Run()

	successResponse(w, fmt.Sprintf("blocked client %s", req.MAC))
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *HALHandler) getInterfaceInfo(name string) NetworkInterface {
	iface := NetworkInterface{Name: name}
	basePath := filepath.Join("/sys/class/net", name)

	// Check if up
	if data, err := os.ReadFile(filepath.Join(basePath, "operstate")); err == nil {
		state := strings.TrimSpace(string(data))
		iface.IsUp = state == "up" || state == "unknown"
	}

	// Get MAC address
	if data, err := os.ReadFile(filepath.Join(basePath, "address")); err == nil {
		iface.MACAddress = strings.TrimSpace(string(data))
	}

	// Get MTU
	if data, err := os.ReadFile(filepath.Join(basePath, "mtu")); err == nil {
		iface.MTU, _ = strconv.Atoi(strings.TrimSpace(string(data)))
	}

	// Check if wireless
	_, err := os.Stat(filepath.Join(basePath, "wireless"))
	iface.IsWireless = err == nil

	// Get IP addresses
	cmd := exec.Command("ip", "-o", "addr", "show", name)
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "inet ") {
				fields := strings.Fields(line)
				for i, f := range fields {
					if f == "inet" && i+1 < len(fields) {
						ip := strings.Split(fields[i+1], "/")[0]
						iface.IPv4Addresses = append(iface.IPv4Addresses, ip)
					}
				}
			}
			if strings.Contains(line, "inet6 ") {
				fields := strings.Fields(line)
				for i, f := range fields {
					if f == "inet6" && i+1 < len(fields) {
						ip := strings.Split(fields[i+1], "/")[0]
						iface.IPv6Addresses = append(iface.IPv6Addresses, ip)
					}
				}
			}
		}
	}

	return iface
}

func parseIwlistOutput(output string) []WiFiNetwork {
	var networks []WiFiNetwork
	var current *WiFiNetwork

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Cell ") {
			if current != nil {
				networks = append(networks, *current)
			}
			current = &WiFiNetwork{}
			if idx := strings.Index(line, "Address: "); idx != -1 {
				current.BSSID = strings.TrimSpace(line[idx+9:])
			}
		}

		if current == nil {
			continue
		}

		if strings.HasPrefix(line, "ESSID:") {
			ssid := strings.TrimPrefix(line, "ESSID:")
			ssid = strings.Trim(ssid, "\"")
			current.SSID = ssid
		}

		if strings.HasPrefix(line, "Channel:") {
			ch := strings.TrimPrefix(line, "Channel:")
			current.Channel, _ = strconv.Atoi(ch)
		}

		if strings.Contains(line, "Signal level=") {
			if idx := strings.Index(line, "Signal level="); idx != -1 {
				sigStr := line[idx+13:]
				if spaceIdx := strings.Index(sigStr, " "); spaceIdx != -1 {
					sigStr = sigStr[:spaceIdx]
				}
				current.Signal, _ = strconv.Atoi(sigStr)
			}
		}

		if strings.Contains(line, "Encryption key:") {
			if strings.Contains(line, "on") {
				current.Security = "WPA/WPA2"
			} else {
				current.Security = "Open"
			}
		}
	}

	if current != nil {
		networks = append(networks, *current)
	}

	return networks
}

func (h *HALHandler) getHostapdClients() ([]APClient, error) {
	cmd := exec.Command("hostapd_cli", "-i", "wlan0", "all_sta")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var clients []APClient
	var current *APClient

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if len(line) == 17 && strings.Count(line, ":") == 5 {
			if current != nil {
				clients = append(clients, *current)
			}
			current = &APClient{MAC: line, Authorized: true}
			continue
		}

		if current == nil {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch key {
			case "rx_bytes":
				current.RxBytes, _ = strconv.ParseInt(value, 10, 64)
			case "tx_bytes":
				current.TxBytes, _ = strconv.ParseInt(value, 10, 64)
			case "signal":
				current.Signal, _ = strconv.Atoi(value)
			}
		}
	}

	if current != nil {
		clients = append(clients, *current)
	}

	// Get IP/hostname from DHCP leases
	if leases, err := os.ReadFile("/var/lib/misc/dnsmasq.leases"); err == nil {
		leaseLines := strings.Split(string(leases), "\n")
		for _, lease := range leaseLines {
			fields := strings.Fields(lease)
			if len(fields) >= 4 {
				mac := strings.ToLower(fields[1])
				for i := range clients {
					if strings.ToLower(clients[i].MAC) == mac {
						clients[i].IP = fields[2]
						clients[i].Hostname = fields[3]
					}
				}
			}
		}
	}

	return clients, nil
}
