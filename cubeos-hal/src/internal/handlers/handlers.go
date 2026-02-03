package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/go-chi/chi/v5"
)

// HALHandler handles all HAL endpoints
type HALHandler struct{}

// NewHALHandler creates a new HAL handler
func NewHALHandler() *HALHandler {
	return &HALHandler{}
}

// Response helpers
func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func errorResponse(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]interface{}{
		"error": message,
		"code":  status,
	})
}

func successResponse(w http.ResponseWriter, message string) {
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": message,
	})
}

// ============================================================================
// Network Interface Operations
// ============================================================================

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name          string   `json:"name"`
	IsUp          bool     `json:"is_up"`
	MACAddress    string   `json:"mac_address"`
	IPv4Addresses []string `json:"ipv4_addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
	MTU           int      `json:"mtu"`
	IsWireless    bool     `json:"is_wireless"`
}

// ListInterfaces returns all network interfaces
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

// GetInterface returns info about a specific interface
func (h *HALHandler) GetInterface(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	// Check interface exists
	if _, err := os.Stat(filepath.Join("/sys/class/net", name)); os.IsNotExist(err) {
		errorResponse(w, http.StatusNotFound, "interface not found: "+name)
		return
	}

	iface := h.getInterfaceInfo(name)
	jsonResponse(w, http.StatusOK, iface)
}

// GetInterfaceTraffic returns traffic stats for an interface
func (h *HALHandler) GetInterfaceTraffic(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	// Check interface exists
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

func (h *HALHandler) getInterfaceInfo(name string) NetworkInterface {
	iface := NetworkInterface{Name: name}
	basePath := filepath.Join("/sys/class/net", name)

	// Check if up
	if data, err := os.ReadFile(filepath.Join(basePath, "operstate")); err == nil {
		state := strings.TrimSpace(string(data))
		iface.IsUp = state == "up" || state == "unknown"
	}

	// MAC address
	if data, err := os.ReadFile(filepath.Join(basePath, "address")); err == nil {
		iface.MACAddress = strings.TrimSpace(string(data))
	}

	// MTU
	if data, err := os.ReadFile(filepath.Join(basePath, "mtu")); err == nil {
		if mtu, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			iface.MTU = mtu
		}
	}

	// Is wireless
	_, err := os.Stat(filepath.Join(basePath, "wireless"))
	iface.IsWireless = err == nil

	// Get IP addresses from ip command
	cmd := exec.Command("ip", "-4", "addr", "show", name)
	if output, err := cmd.Output(); err == nil {
		re := regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)`)
		for _, match := range re.FindAllStringSubmatch(string(output), -1) {
			iface.IPv4Addresses = append(iface.IPv4Addresses, match[1])
		}
	}

	cmd = exec.Command("ip", "-6", "addr", "show", name)
	if output, err := cmd.Output(); err == nil {
		re := regexp.MustCompile(`inet6 ([a-f0-9:]+)`)
		for _, match := range re.FindAllStringSubmatch(string(output), -1) {
			iface.IPv6Addresses = append(iface.IPv6Addresses, match[1])
		}
	}

	return iface
}

// BringInterfaceUp brings a network interface up
func (h *HALHandler) BringInterfaceUp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	cmd := exec.Command("ip", "link", "set", name, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to bring up %s: %s - %s", name, err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("interface %s is now up", name))
}

// BringInterfaceDown brings a network interface down
func (h *HALHandler) BringInterfaceDown(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	cmd := exec.Command("ip", "link", "set", name, "down")
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to bring down %s: %s - %s", name, err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("interface %s is now down", name))
}

// ============================================================================
// WiFi Operations
// ============================================================================

// WiFiNetwork represents a scanned WiFi network
type WiFiNetwork struct {
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid"`
	Signal    int    `json:"signal"`
	Frequency int    `json:"frequency"`
	Security  string `json:"security"`
	Channel   int    `json:"channel"`
}

// ScanWiFi scans for WiFi networks on the specified interface
func (h *HALHandler) ScanWiFi(w http.ResponseWriter, r *http.Request) {
	iface := chi.URLParam(r, "iface")
	if iface == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	// Ensure interface is up
	exec.Command("ip", "link", "set", iface, "up").Run()
	time.Sleep(500 * time.Millisecond)

	// Run scan
	cmd := exec.Command("iw", iface, "scan")
	output, err := cmd.Output()
	if err != nil {
		// Device might be busy, retry once
		time.Sleep(2 * time.Second)
		cmd = exec.Command("iw", iface, "scan")
		output, err = cmd.Output()
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "scan failed: "+err.Error())
			return
		}
	}

	networks := parseIWScan(string(output))
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"networks":  networks,
		"interface": iface,
	})
}

func parseIWScan(output string) []WiFiNetwork {
	var networks []WiFiNetwork
	var current *WiFiNetwork

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "BSS ") {
			if current != nil && current.SSID != "" {
				networks = append(networks, *current)
			}
			current = &WiFiNetwork{}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				current.BSSID = strings.TrimSuffix(parts[1], "(on")
			}
		}

		if current == nil {
			continue
		}

		if strings.HasPrefix(line, "SSID:") {
			current.SSID = strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
		} else if strings.HasPrefix(line, "signal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				signal, _ := strconv.ParseFloat(parts[1], 64)
				current.Signal = int(signal)
			}
		} else if strings.HasPrefix(line, "freq:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				freq, _ := strconv.Atoi(parts[1])
				current.Frequency = freq
				// Calculate channel from frequency
				if freq >= 2412 && freq <= 2484 {
					current.Channel = (freq - 2407) / 5
				} else if freq >= 5180 && freq <= 5825 {
					current.Channel = (freq - 5000) / 5
				}
			}
		} else if strings.Contains(line, "WPA") || strings.Contains(line, "RSN") {
			if current.Security == "" {
				current.Security = "WPA2"
			}
			if strings.Contains(line, "WPA:") {
				current.Security = "WPA"
			}
			if strings.Contains(line, "RSN:") {
				current.Security = "WPA2"
			}
		} else if strings.Contains(line, "Privacy") {
			if current.Security == "" {
				current.Security = "WEP"
			}
		}
	}

	// Don't forget the last one
	if current != nil && current.SSID != "" {
		networks = append(networks, *current)
	}

	// Set security to "Open" for networks without encryption
	for i := range networks {
		if networks[i].Security == "" {
			networks[i].Security = "Open"
		}
	}

	return networks
}

// ConnectWiFi connects to a WiFi network
func (h *HALHandler) ConnectWiFi(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Interface string `json:"interface"`
		SSID      string `json:"ssid"`
		Password  string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Interface == "" || req.SSID == "" {
		errorResponse(w, http.StatusBadRequest, "interface and ssid required")
		return
	}

	// Create wpa_supplicant config
	configPath := "/tmp/wpa_supplicant_" + req.Interface + ".conf"
	config := fmt.Sprintf(`ctrl_interface=/var/run/wpa_supplicant
update_config=1

network={
    ssid="%s"
    psk="%s"
    key_mgmt=WPA-PSK
}
`, req.SSID, req.Password)

	if req.Password == "" {
		config = fmt.Sprintf(`ctrl_interface=/var/run/wpa_supplicant
update_config=1

network={
    ssid="%s"
    key_mgmt=NONE
}
`, req.SSID)
	}

	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to write config: "+err.Error())
		return
	}

	// Kill any existing wpa_supplicant for this interface
	exec.Command("pkill", "-f", "wpa_supplicant.*"+req.Interface).Run()
	time.Sleep(500 * time.Millisecond)

	// Start wpa_supplicant
	cmd := exec.Command("wpa_supplicant", "-B", "-i", req.Interface, "-c", configPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("wpa_supplicant failed: %s - %s", err, string(output)))
		return
	}

	// Request DHCP
	time.Sleep(2 * time.Second)
	cmd = exec.Command("dhclient", "-v", req.Interface)
	cmd.Run() // Don't fail if dhclient fails

	successResponse(w, fmt.Sprintf("connecting to %s on %s", req.SSID, req.Interface))
}

// DisconnectWiFi disconnects from WiFi
func (h *HALHandler) DisconnectWiFi(w http.ResponseWriter, r *http.Request) {
	iface := chi.URLParam(r, "iface")
	if iface == "" {
		errorResponse(w, http.StatusBadRequest, "interface name required")
		return
	}

	// Kill wpa_supplicant for this interface
	exec.Command("pkill", "-f", "wpa_supplicant.*"+iface).Run()
	exec.Command("dhclient", "-r", iface).Run()
	exec.Command("ip", "addr", "flush", "dev", iface).Run()

	successResponse(w, fmt.Sprintf("disconnected from WiFi on %s", iface))
}

// GetNetworkStatus returns comprehensive network status for dashboard
func (h *HALHandler) GetNetworkStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"interfaces":       []NetworkInterface{},
		"internet":         false,
		"internet_latency": 0,
		"ap":               h.getAPStatus(),
		"nat":              h.getNATStatus(),
		"firewall":         h.getFirewallStatus(),
	}

	// Get interfaces
	entries, _ := os.ReadDir("/sys/class/net")
	var interfaces []NetworkInterface
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" {
			continue
		}
		interfaces = append(interfaces, h.getInterfaceInfo(name))
	}
	status["interfaces"] = interfaces

	// Check internet connectivity with latency
	start := time.Now()
	cmd := exec.Command("ping", "-c", "1", "-W", "2", "8.8.8.8")
	if cmd.Run() == nil {
		status["internet"] = true
		status["internet_latency"] = time.Since(start).Milliseconds()
	}

	jsonResponse(w, http.StatusOK, status)
}

// getAPStatus returns Access Point status
func (h *HALHandler) getAPStatus() map[string]interface{} {
	status := map[string]interface{}{
		"active":    false,
		"ssid":      "",
		"channel":   0,
		"frequency": "",
		"clients":   0,
	}

	// Method 1: Check if wlan0 is in AP mode via iw
	cmd := exec.Command("iw", "dev", "wlan0", "info")
	if output, err := cmd.Output(); err == nil {
		if strings.Contains(string(output), "type AP") {
			status["active"] = true
		}
	}

	// Method 2: Check hostapd socket exists (fallback)
	if !status["active"].(bool) {
		if _, err := os.Stat("/var/run/hostapd/wlan0"); err == nil {
			status["active"] = true
		}
	}

	// Method 3: Check systemctl via command (fallback)
	if !status["active"].(bool) {
		cmd = exec.Command("systemctl", "is-active", "hostapd")
		if output, err := cmd.Output(); err == nil {
			if strings.TrimSpace(string(output)) == "active" {
				status["active"] = true
			}
		}
	}

	// Read hostapd config for SSID/channel
	configPaths := []string{
		"/etc/hostapd/hostapd.conf",
		"/etc/hostapd.conf",
	}

	for _, configPath := range configPaths {
		if data, err := os.ReadFile(configPath); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "ssid=") {
					status["ssid"] = strings.TrimPrefix(line, "ssid=")
				} else if strings.HasPrefix(line, "channel=") {
					if ch, err := strconv.Atoi(strings.TrimPrefix(line, "channel=")); err == nil {
						status["channel"] = ch
						if ch <= 14 {
							status["frequency"] = "2.4GHz"
						} else {
							status["frequency"] = "5GHz"
						}
					}
				}
			}
			break
		}
	}

	// Count connected clients
	cmd = exec.Command("hostapd_cli", "all_sta")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		clientCount := 0
		for _, line := range lines {
			if isMACAddress(strings.TrimSpace(line)) {
				clientCount++
			}
		}
		status["clients"] = clientCount
	}

	return status
}

// getNATStatus returns NAT/Internet sharing status
func (h *HALHandler) getNATStatus() map[string]interface{} {
	status := map[string]interface{}{
		"enabled":          false,
		"ip_forward":       false,
		"masquerade":       false,
		"source_interface": "",
		"dest_interface":   "",
	}

	// Check IP forwarding
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		status["ip_forward"] = strings.TrimSpace(string(data)) == "1"
	}

	// Check for MASQUERADE rule
	cmd := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v")
	if output, err := cmd.Output(); err == nil {
		if strings.Contains(string(output), "MASQUERADE") {
			status["masquerade"] = true
			status["enabled"] = status["ip_forward"].(bool)
		}
	}

	return status
}

// getFirewallStatus returns firewall status
func (h *HALHandler) getFirewallStatus() map[string]interface{} {
	status := map[string]interface{}{
		"active":      false,
		"ip_forward":  false,
		"rules_count": 0,
	}

	// Check IP forwarding
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		ipForward := strings.TrimSpace(string(data)) == "1"
		status["ip_forward"] = ipForward
		status["active"] = ipForward
	}

	// Count iptables rules
	cmd := exec.Command("iptables", "-L", "-n")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		ruleCount := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "Chain") && !strings.HasPrefix(line, "target") {
				ruleCount++
			}
		}
		status["rules_count"] = ruleCount
		if ruleCount > 0 {
			status["active"] = true
		}
	}

	return status
}

// ============================================================================
// System Throttling/Temperature
// ============================================================================

// GetThrottleStatus returns Pi CPU/GPU throttling status
func (h *HALHandler) GetThrottleStatus(w http.ResponseWriter, r *http.Request) {
	// Use nsenter to run vcgencmd on host (requires pid:host in container)
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-n", "-i", "/usr/bin/vcgencmd", "get_throttled")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try reading from sysfs (some Pi kernels expose this)
		if data, err := os.ReadFile("/sys/devices/platform/soc/soc:firmware/get_throttled"); err == nil {
			output = data
		} else {
			errorResponse(w, http.StatusInternalServerError, "vcgencmd failed (try running on host): "+err.Error())
			return
		}
	}

	// Parse "throttled=0x0" format
	str := strings.TrimSpace(string(output))
	parts := strings.Split(str, "=")
	if len(parts) != 2 {
		// Maybe just the hex value
		parts = []string{"throttled", str}
	}

	val, _ := strconv.ParseInt(strings.TrimPrefix(parts[1], "0x"), 16, 64)

	status := map[string]interface{}{
		"raw":                       parts[1],
		"under_voltage":             val&0x1 != 0,
		"freq_capped":               val&0x2 != 0,
		"throttled":                 val&0x4 != 0,
		"soft_temp_limit":           val&0x8 != 0,
		"under_voltage_occurred":    val&0x10000 != 0,
		"freq_capped_occurred":      val&0x20000 != 0,
		"throttled_occurred":        val&0x40000 != 0,
		"soft_temp_limit_occurred":  val&0x80000 != 0,
	}

	jsonResponse(w, http.StatusOK, status)
}

// GetCPUTemp returns CPU temperature
func (h *HALHandler) GetCPUTemp(w http.ResponseWriter, r *http.Request) {
	// Try nsenter + vcgencmd first (Pi specific, requires pid:host)
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-n", "-i", "/usr/bin/vcgencmd", "measure_temp")
	if output, err := cmd.Output(); err == nil {
		// Parse "temp=45.0'C" format
		str := strings.TrimSpace(string(output))
		str = strings.TrimPrefix(str, "temp=")
		str = strings.TrimSuffix(str, "'C")
		if temp, err := strconv.ParseFloat(str, 64); err == nil {
			jsonResponse(w, http.StatusOK, map[string]interface{}{
				"temperature": temp,
				"unit":        "celsius",
				"source":      "vcgencmd",
			})
			return
		}
	}

	// Fallback to thermal zone
	if data, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
		if milliC, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
			jsonResponse(w, http.StatusOK, map[string]interface{}{
				"temperature": float64(milliC) / 1000.0,
				"unit":        "celsius",
				"source":      "thermal_zone",
			})
			return
		}
	}

	errorResponse(w, http.StatusInternalServerError, "unable to read CPU temperature")
}

// GetEEPROMInfo returns Pi bootloader EEPROM information
func (h *HALHandler) GetEEPROMInfo(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-n", "-i", "/usr/bin/vcgencmd", "bootloader_version")
	output, err := cmd.Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to read EEPROM: "+err.Error())
		return
	}

	info := map[string]interface{}{
		"raw": strings.TrimSpace(string(output)),
	}

	// Parse the output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// First line is date: "2024/09/23 14:02:56"
		if strings.Contains(line, "/") && strings.Contains(line, ":") && !strings.Contains(line, "=") {
			info["date"] = line
			continue
		}

		// Parse key=value or "key value" pairs
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				info[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "version ") {
			info["version"] = strings.TrimPrefix(line, "version ")
		} else if strings.HasPrefix(line, "timestamp ") {
			if ts, err := strconv.ParseInt(strings.TrimPrefix(line, "timestamp "), 10, 64); err == nil {
				info["timestamp"] = ts
				info["timestamp_formatted"] = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
		} else if strings.HasPrefix(line, "update-time ") {
			if ts, err := strconv.ParseInt(strings.TrimPrefix(line, "update-time "), 10, 64); err == nil {
				info["update_time"] = ts
				info["update_time_formatted"] = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
		} else if strings.HasPrefix(line, "capabilities ") {
			info["capabilities"] = strings.TrimPrefix(line, "capabilities ")
		}
	}

	jsonResponse(w, http.StatusOK, info)
}

// GetBootConfig returns Pi boot configuration
func (h *HALHandler) GetBootConfig(w http.ResponseWriter, r *http.Request) {
	result := map[string]interface{}{
		"config":   map[string]interface{}{},
		"overlays": []string{},
	}

	// Get active config from vcgencmd
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-n", "-i", "/usr/bin/vcgencmd", "get_config", "int")
	if output, err := cmd.Output(); err == nil {
		config := map[string]interface{}{}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				valStr := strings.TrimSpace(parts[1])
				// Try to parse as int
				if val, err := strconv.ParseInt(valStr, 0, 64); err == nil {
					config[key] = val
				} else {
					config[key] = valStr
				}
			}
		}
		result["config"] = config
	}

	// Read config.txt for overlays and comments
	configPaths := []string{
		"/boot/firmware/config.txt",
		"/boot/config.txt",
	}

	for _, path := range configPaths {
		if data, err := os.ReadFile(path); err == nil {
			result["config_file"] = path

			// Extract dtoverlay entries
			var overlays []string
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "dtoverlay=") {
					overlay := strings.TrimPrefix(line, "dtoverlay=")
					overlays = append(overlays, overlay)
				}
			}
			result["overlays"] = overlays
			break
		}
	}

	// Get some key hardware info
	hwInfo := map[string]interface{}{}

	// Total RAM
	cmd = exec.Command("nsenter", "-t", "1", "-m", "-u", "-n", "-i", "/usr/bin/vcgencmd", "get_config", "total_mem")
	if output, err := cmd.Output(); err == nil {
		if parts := strings.Split(strings.TrimSpace(string(output)), "="); len(parts) == 2 {
			if mem, err := strconv.Atoi(parts[1]); err == nil {
				hwInfo["total_mem_mb"] = mem
			}
		}
	}

	// ARM frequency
	cmd = exec.Command("nsenter", "-t", "1", "-m", "-u", "-n", "-i", "/usr/bin/vcgencmd", "get_config", "arm_freq")
	if output, err := cmd.Output(); err == nil {
		if parts := strings.Split(strings.TrimSpace(string(output)), "="); len(parts) == 2 {
			if freq, err := strconv.Atoi(parts[1]); err == nil {
				hwInfo["arm_freq_mhz"] = freq
			}
		}
	}

	// GPU memory
	cmd = exec.Command("nsenter", "-t", "1", "-m", "-u", "-n", "-i", "/usr/bin/vcgencmd", "get_mem", "gpu")
	if output, err := cmd.Output(); err == nil {
		str := strings.TrimSpace(string(output))
		str = strings.TrimPrefix(str, "gpu=")
		str = strings.TrimSuffix(str, "M")
		if mem, err := strconv.Atoi(str); err == nil {
			hwInfo["gpu_mem_mb"] = mem
		}
	}

	result["hardware"] = hwInfo

	jsonResponse(w, http.StatusOK, result)
}

// ============================================================================
// AP Client Operations
// ============================================================================

// APClient represents a connected AP client
type APClient struct {
	MACAddress    string `json:"mac_address"`
	IPAddress     string `json:"ip_address,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	ConnectedTime int    `json:"connected_time,omitempty"` // seconds
	Signal        int    `json:"signal,omitempty"`         // dBm
	TxBytes       int64  `json:"tx_bytes,omitempty"`
	RxBytes       int64  `json:"rx_bytes,omitempty"`
}

// GetAPClients returns connected Access Point clients
func (h *HALHandler) GetAPClients(w http.ResponseWriter, r *http.Request) {
	var clients []APClient

	// Try hostapd_cli first (most accurate for WiFi clients)
	cmd := exec.Command("hostapd_cli", "all_sta")
	output, err := cmd.Output()
	if err == nil {
		clients = parseHostapdClients(string(output))
	}

	// If hostapd_cli failed or returned no clients, try with specific interface
	if len(clients) == 0 {
		// Try common AP interface
		cmd = exec.Command("hostapd_cli", "-i", "wlan0", "all_sta")
		output, err = cmd.Output()
		if err == nil {
			clients = parseHostapdClients(string(output))
		}
	}

	// Enrich with DHCP lease information for IP addresses and hostnames
	leases := parseDHCPLeases()
	for i := range clients {
		mac := strings.ToLower(clients[i].MACAddress)
		if lease, ok := leases[mac]; ok {
			clients[i].IPAddress = lease.IP
			clients[i].Hostname = lease.Hostname
		}
	}

	// If still no clients from hostapd, fall back to ARP + DHCP leases
	if len(clients) == 0 {
		clients = getClientsFromARP(leases)
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"clients": clients,
		"count":   len(clients),
	})
}

// DisconnectAPClient disconnects a client from the AP
func (h *HALHandler) DisconnectAPClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MAC string `json:"mac"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.MAC == "" || !isMACAddress(req.MAC) {
		errorResponse(w, http.StatusBadRequest, "valid MAC address required")
		return
	}

	// Disassociate client (gentle disconnect)
	cmd := exec.Command("hostapd_cli", "disassociate", req.MAC)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to disconnect: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("client %s disconnected", req.MAC))
}

// BlockAPClient blocks a client from the AP (deauth + deny list)
func (h *HALHandler) BlockAPClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MAC string `json:"mac"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.MAC == "" || !isMACAddress(req.MAC) {
		errorResponse(w, http.StatusBadRequest, "valid MAC address required")
		return
	}

	// Deauthenticate client (forceful)
	cmd := exec.Command("hostapd_cli", "deauthenticate", req.MAC)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to block: %s - %s", err, string(output)))
		return
	}

	// TODO: Add to deny list in hostapd.conf for persistence
	// For now, just deauth (they can reconnect until hostapd restarts with deny list)

	successResponse(w, fmt.Sprintf("client %s blocked", req.MAC))
}

// parseHostapdClients parses hostapd_cli all_sta output
func parseHostapdClients(output string) []APClient {
	var clients []APClient
	var current *APClient

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// New station starts with MAC address
		if isMACAddress(line) {
			if current != nil {
				clients = append(clients, *current)
			}
			current = &APClient{
				MACAddress: strings.ToLower(line),
			}
			continue
		}

		if current == nil {
			continue
		}

		// Parse key=value pairs
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "connected_time":
				if v, err := strconv.Atoi(value); err == nil {
					current.ConnectedTime = v
				}
			case "signal":
				if v, err := strconv.Atoi(value); err == nil {
					current.Signal = v
				}
			case "tx_bytes":
				if v, err := strconv.ParseInt(value, 10, 64); err == nil {
					current.TxBytes = v
				}
			case "rx_bytes":
				if v, err := strconv.ParseInt(value, 10, 64); err == nil {
					current.RxBytes = v
				}
			}
		}
	}

	// Don't forget the last client
	if current != nil {
		clients = append(clients, *current)
	}

	return clients
}

// isMACAddress checks if a string is a MAC address
func isMACAddress(s string) bool {
	// MAC format: xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
	s = strings.ToLower(s)
	macRegex := regexp.MustCompile(`^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$`)
	return macRegex.MatchString(s)
}

// DHCPLease represents a DHCP lease entry
type DHCPLease struct {
	MAC      string
	IP       string
	Hostname string
	Expires  string
}

// parseDHCPLeases reads DHCP leases from Pi-hole or dnsmasq
func parseDHCPLeases() map[string]DHCPLease {
	leases := make(map[string]DHCPLease)

	// Try Pi-hole DHCP leases first
	leasePaths := []string{
	 	"/cubeos/coreapps/pihole/appdata/etc-pihole/dhcp.leases", // CubeOS Pi-hole v6
		"/etc/pihole/dhcp.leases",
		"/var/lib/misc/dnsmasq.leases",
		"/var/lib/dhcp/dhcpd.leases",
	}

	for _, path := range leasePaths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)

			// dnsmasq format: timestamp mac ip hostname clientid
			if len(fields) >= 4 {
				mac := strings.ToLower(fields[1])
				leases[mac] = DHCPLease{
					MAC:      mac,
					IP:       fields[2],
					Hostname: fields[3],
					Expires:  fields[0],
				}
			}
		}
		break // Use first successful file
	}

	return leases
}

// getClientsFromARP gets clients from ARP table (fallback)
func getClientsFromARP(leases map[string]DHCPLease) []APClient {
	var clients []APClient

	// Read ARP table
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return clients
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false // Skip header
			continue
		}

		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		ip := fields[0]
		mac := strings.ToLower(fields[3])

		// Skip incomplete entries and localhost
		if mac == "00:00:00:00:00:00" || ip == "10.42.24.1" {
			continue
		}

		// Filter to only CubeOS subnet
		if !strings.HasPrefix(ip, "10.42.24.") {
			continue
		}

		client := APClient{
			MACAddress: mac,
			IPAddress:  ip,
		}

		// Add hostname from DHCP leases if available
		if lease, ok := leases[mac]; ok {
			client.Hostname = lease.Hostname
		}

		clients = append(clients, client)
	}

	return clients
}

// ============================================================================
// Firewall Operations
// ============================================================================

// GetFirewallRules returns current iptables rules
func (h *HALHandler) GetFirewallRules(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("iptables", "-L", "-n", "-v")
	output, err := cmd.Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get rules: "+err.Error())
		return
	}

	natCmd := exec.Command("iptables", "-t", "nat", "-L", "-n", "-v")
	natOutput, _ := natCmd.Output()

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"filter": string(output),
		"nat":    string(natOutput),
	})
}

// EnableNAT enables NAT forwarding
func (h *HALHandler) EnableNAT(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SourceInterface string `json:"source_interface"` // e.g., wlan0 (AP)
		DestInterface   string `json:"dest_interface"`   // e.g., eth0 or wlan1
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SourceInterface == "" || req.DestInterface == "" {
		errorResponse(w, http.StatusBadRequest, "source_interface and dest_interface required")
		return
	}

	// Enable IP forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to enable IP forwarding: "+err.Error())
		return
	}

	// Clear existing NAT rules for this interface
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", req.DestInterface, "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-D", "FORWARD", "-i", req.SourceInterface, "-o", req.DestInterface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD", "-i", req.DestInterface, "-o", req.SourceInterface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()

	// Add NAT rules
	cmds := [][]string{
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-o", req.DestInterface, "-j", "MASQUERADE"},
		{"iptables", "-A", "FORWARD", "-i", req.SourceInterface, "-o", req.DestInterface, "-j", "ACCEPT"},
		{"iptables", "-A", "FORWARD", "-i", req.DestInterface, "-o", req.SourceInterface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}

	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("iptables failed: %s - %s", err, string(output)))
			return
		}
	}

	successResponse(w, fmt.Sprintf("NAT enabled: %s -> %s", req.SourceInterface, req.DestInterface))
}

// DisableNAT disables NAT forwarding
func (h *HALHandler) DisableNAT(w http.ResponseWriter, r *http.Request) {
	// Flush NAT table
	exec.Command("iptables", "-t", "nat", "-F").Run()
	exec.Command("iptables", "-F", "FORWARD").Run()

	// Disable IP forwarding
	os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644)

	successResponse(w, "NAT disabled")
}

// AddFirewallRule adds a firewall rule
func (h *HALHandler) AddFirewallRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Table string   `json:"table"` // filter, nat, mangle
		Chain string   `json:"chain"` // INPUT, OUTPUT, FORWARD, etc.
		Args  []string `json:"args"`  // Additional iptables arguments
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	args := []string{}
	if req.Table != "" && req.Table != "filter" {
		args = append(args, "-t", req.Table)
	}
	args = append(args, "-A", req.Chain)
	args = append(args, req.Args...)

	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("iptables failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "rule added")
}

// DeleteFirewallRule deletes a firewall rule
func (h *HALHandler) DeleteFirewallRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Table string   `json:"table"`
		Chain string   `json:"chain"`
		Args  []string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	args := []string{}
	if req.Table != "" && req.Table != "filter" {
		args = append(args, "-t", req.Table)
	}
	args = append(args, "-D", req.Chain)
	args = append(args, req.Args...)

	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("iptables failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "rule deleted")
}

// EnableIPForward enables IP forwarding
func (h *HALHandler) EnableIPForward(w http.ResponseWriter, r *http.Request) {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to enable IP forwarding: "+err.Error())
		return
	}
	successResponse(w, "IP forwarding enabled")
}

// DisableIPForward disables IP forwarding
func (h *HALHandler) DisableIPForward(w http.ResponseWriter, r *http.Request) {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to disable IP forwarding: "+err.Error())
		return
	}
	successResponse(w, "IP forwarding disabled")
}

// ============================================================================
// VPN Operations
// ============================================================================

// GetVPNStatus returns VPN connection status
func (h *HALHandler) GetVPNStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"wireguard": map[string]interface{}{
			"active":     false,
			"interfaces": []string{},
		},
		"openvpn": map[string]interface{}{
			"active": false,
		},
	}

	// Check WireGuard
	cmd := exec.Command("wg", "show", "interfaces")
	if output, err := cmd.Output(); err == nil {
		interfaces := strings.Fields(string(output))
		if len(interfaces) > 0 {
			status["wireguard"] = map[string]interface{}{
				"active":     true,
				"interfaces": interfaces,
			}
		}
	}

	// Check OpenVPN
	cmd = exec.Command("pgrep", "-x", "openvpn")
	if cmd.Run() == nil {
		status["openvpn"] = map[string]interface{}{
			"active": true,
		}
	}

	jsonResponse(w, http.StatusOK, status)
}

// WireGuardUp brings up a WireGuard interface
func (h *HALHandler) WireGuardUp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "config name required")
		return
	}

	cmd := exec.Command("wg-quick", "up", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("wg-quick up failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("WireGuard %s is up", name))
}

// WireGuardDown brings down a WireGuard interface
func (h *HALHandler) WireGuardDown(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "config name required")
		return
	}

	cmd := exec.Command("wg-quick", "down", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("wg-quick down failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("WireGuard %s is down", name))
}

// OpenVPNUp starts OpenVPN with a config
func (h *HALHandler) OpenVPNUp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "config name required")
		return
	}

	configPath := filepath.Join("/cubeos/config/vpn/openvpn", name+".ovpn")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = filepath.Join("/cubeos/config/vpn/openvpn", name+".conf")
	}

	cmd := exec.Command("openvpn", "--daemon", "--config", configPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("openvpn failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("OpenVPN %s started", name))
}

// OpenVPNDown stops OpenVPN
func (h *HALHandler) OpenVPNDown(w http.ResponseWriter, r *http.Request) {
	exec.Command("pkill", "-x", "openvpn").Run()
	successResponse(w, "OpenVPN stopped")
}

// ============================================================================
// USB Operations
// ============================================================================

// USBDevice represents a USB device
type USBDevice struct {
	Bus       string `json:"bus"`
	Device    string `json:"device"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Mounted   bool   `json:"mounted"`
	MountPath string `json:"mount_path,omitempty"`
}

// ListUSBDevices lists USB storage devices
func (h *HALHandler) ListUSBDevices(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,VENDOR,MODEL")
	output, err := cmd.Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "lsblk failed: "+err.Error())
		return
	}

	var result map[string]interface{}
	json.Unmarshal(output, &result)

	jsonResponse(w, http.StatusOK, result)
}

// MountUSB mounts a USB device
func (h *HALHandler) MountUSB(w http.ResponseWriter, r *http.Request) {
	device := chi.URLParam(r, "device")
	if device == "" {
		errorResponse(w, http.StatusBadRequest, "device name required")
		return
	}

	mountPath := filepath.Join("/cubeos/mounts/usb", device)
	os.MkdirAll(mountPath, 0755)

	devicePath := "/dev/" + device
	cmd := exec.Command("mount", devicePath, mountPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("mount failed: %s - %s", err, string(output)))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"device":     device,
		"mount_path": mountPath,
	})
}

// UnmountUSB unmounts a USB device
func (h *HALHandler) UnmountUSB(w http.ResponseWriter, r *http.Request) {
	device := chi.URLParam(r, "device")
	if device == "" {
		errorResponse(w, http.StatusBadRequest, "device name required")
		return
	}

	mountPath := filepath.Join("/cubeos/mounts/usb", device)
	cmd := exec.Command("umount", mountPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("umount failed: %s - %s", err, string(output)))
		return
	}

	os.Remove(mountPath)
	successResponse(w, fmt.Sprintf("unmounted %s", device))
}

// ============================================================================
// Bluetooth Operations (stubs for future)
// ============================================================================

func (h *HALHandler) GetBluetoothStatus(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"available": false,
		"message":   "Bluetooth support not yet implemented",
	})
}

func (h *HALHandler) ListBluetoothDevices(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"devices": []interface{}{},
	})
}

func (h *HALHandler) ScanBluetooth(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, http.StatusNotImplemented, "Bluetooth scanning not yet implemented")
}

func (h *HALHandler) PairBluetooth(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, http.StatusNotImplemented, "Bluetooth pairing not yet implemented")
}

// ============================================================================
// System Operations
// ============================================================================

// Reboot reboots the system
func (h *HALHandler) Reboot(w http.ResponseWriter, r *http.Request) {
	successResponse(w, "rebooting in 2 seconds...")
	go func() {
		time.Sleep(2 * time.Second)
		exec.Command("reboot").Run()
	}()
}

// Shutdown shuts down the system
func (h *HALHandler) Shutdown(w http.ResponseWriter, r *http.Request) {
	successResponse(w, "shutting down in 2 seconds...")
	go func() {
		time.Sleep(2 * time.Second)
		exec.Command("shutdown", "-h", "now").Run()
	}()
}

// RestartService restarts a systemd service
func (h *HALHandler) RestartService(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "service name required")
		return
	}

	// Whitelist allowed services
	allowed := map[string]bool{
		"hostapd":          true,
		"dnsmasq":          true,
		"wpa_supplicant":   true,
		"NetworkManager":   true,
		"docker":           true,
		"cubeos-watchdog":  true,
		"systemd-resolved": true,
		"systemd-networkd": true,
		"ssh":              true,
		"sshd":             true,
	}

	if !allowed[name] {
		errorResponse(w, http.StatusForbidden, "service not in whitelist: "+name)
		return
	}

	// Use D-Bus to communicate with host systemd
	ctx := context.Background()
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "dbus connection failed: "+err.Error())
		return
	}
	defer conn.Close()

	unitName := name + ".service"
	ch := make(chan string)
	_, err = conn.RestartUnitContext(ctx, unitName, "replace", ch)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to restart %s: %s", name, err))
		return
	}
	<-ch // Wait for job completion

	successResponse(w, fmt.Sprintf("service %s restarted", name))
}

// StartService starts a systemd service
func (h *HALHandler) StartService(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "service name required")
		return
	}

	// Use D-Bus to communicate with host systemd
	ctx := context.Background()
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "dbus connection failed: "+err.Error())
		return
	}
	defer conn.Close()

	unitName := name + ".service"
	ch := make(chan string)
	_, err = conn.StartUnitContext(ctx, unitName, "replace", ch)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to start %s: %s", name, err))
		return
	}
	<-ch // Wait for job completion

	successResponse(w, fmt.Sprintf("service %s started", name))
}

// StopService stops a systemd service
func (h *HALHandler) StopService(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "service name required")
		return
	}

	// Use D-Bus to communicate with host systemd
	ctx := context.Background()
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "dbus connection failed: "+err.Error())
		return
	}
	defer conn.Close()

	unitName := name + ".service"
	ch := make(chan string)
	_, err = conn.StopUnitContext(ctx, unitName, "replace", ch)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to stop %s: %s", name, err))
		return
	}
	<-ch // Wait for job completion

	successResponse(w, fmt.Sprintf("service %s stopped", name))
}

// ServiceStatus gets the status of a systemd service
func (h *HALHandler) ServiceStatus(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "service name required")
		return
	}

	ctx := context.Background()
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"name":    name,
			"active":  false,
			"enabled": false,
		})
		return
	}
	defer conn.Close()

	unitName := name + ".service"
	result := map[string]interface{}{
		"name":    name,
		"active":  false,
		"enabled": false,
	}

	// Get ActiveState property
	prop, err := conn.GetUnitPropertyContext(ctx, unitName, "ActiveState")
	if err == nil {
		if activeState, ok := prop.Value.Value().(string); ok {
			result["active"] = activeState == "active"
		}
	}

	// Get UnitFileState property for enabled status
	prop, err = conn.GetUnitPropertyContext(ctx, unitName, "UnitFileState")
	if err == nil {
		if enabledState, ok := prop.Value.Value().(string); ok {
			result["enabled"] = enabledState == "enabled"
		}
	}

	jsonResponse(w, http.StatusOK, result)
}

// ============================================================================
// Mount Operations
// ============================================================================

// MountRequest represents a mount request
type MountRequest struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	RemotePath string `json:"remote_path"`
	LocalPath  string `json:"local_path"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Options    string `json:"options,omitempty"`
}

// MountSMB handles SMB/CIFS mount requests
func (h *HALHandler) MountSMB(w http.ResponseWriter, r *http.Request) {
	var req MountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate
	if req.RemotePath == "" || req.LocalPath == "" {
		errorResponse(w, http.StatusBadRequest, "remote_path and local_path are required")
		return
	}

	// Ensure local path exists
	if err := os.MkdirAll(req.LocalPath, 0755); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create mount point: %v", err))
		return
	}

	// Build mount command
	mountOpts := []string{"vers=3.0"}

	if req.Username != "" && req.Password != "" {
		// Create temporary credentials file
		credsFile := filepath.Join("/tmp", fmt.Sprintf(".mount_creds_%d", os.Getpid()))
		content := fmt.Sprintf("username=%s\npassword=%s\n", req.Username, req.Password)
		if err := os.WriteFile(credsFile, []byte(content), 0600); err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create credentials: %v", err))
			return
		}
		defer os.Remove(credsFile)
		mountOpts = append(mountOpts, fmt.Sprintf("credentials=%s", credsFile))
	} else {
		mountOpts = append(mountOpts, "guest")
	}

	if req.Options != "" {
		mountOpts = append(mountOpts, req.Options)
	}

	// Execute mount
	args := []string{"-t", "cifs", "-o", strings.Join(mountOpts, ","), req.RemotePath, req.LocalPath}
	cmd := exec.Command("mount", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Mount failed: %s: %v", string(output), err))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"mount_path": req.LocalPath,
		"message":    "SMB share mounted successfully",
	})
}

// MountNFS handles NFS mount requests
func (h *HALHandler) MountNFS(w http.ResponseWriter, r *http.Request) {
	var req MountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate
	if req.RemotePath == "" || req.LocalPath == "" {
		errorResponse(w, http.StatusBadRequest, "remote_path and local_path are required")
		return
	}

	// Ensure local path exists
	if err := os.MkdirAll(req.LocalPath, 0755); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create mount point: %v", err))
		return
	}

	// Build mount options
	mountOpts := []string{"rw", "soft", "intr"}
	if req.Options != "" {
		mountOpts = append(mountOpts, req.Options)
	}

	// Execute mount
	args := []string{"-t", "nfs", "-o", strings.Join(mountOpts, ","), req.RemotePath, req.LocalPath}
	cmd := exec.Command("mount", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Mount failed: %s: %v", string(output), err))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"mount_path": req.LocalPath,
		"message":    "NFS share mounted successfully",
	})
}

// UnmountPath handles unmount requests
func (h *HALHandler) UnmountPath(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Path == "" {
		errorResponse(w, http.StatusBadRequest, "path is required")
		return
	}

	// Try normal unmount first
	cmd := exec.Command("umount", req.Path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try lazy unmount
		cmd = exec.Command("umount", "-l", req.Path)
		output, err = cmd.CombinedOutput()
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Unmount failed: %s: %v", string(output), err))
			return
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Unmounted successfully",
	})
}

// TestMountConnection tests connectivity to a remote share
func (h *HALHandler) TestMountConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type       string `json:"type"`
		RemotePath string `json:"remote_path"`
		Username   string `json:"username"`
		Password   string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	switch req.Type {
	case "smb":
		// Use smbclient to test - extract server from //server/share
		parts := strings.Split(strings.TrimPrefix(req.RemotePath, "//"), "/")
		if len(parts) < 1 {
			errorResponse(w, http.StatusBadRequest, "Invalid SMB path")
			return
		}
		server := parts[0]

		var args []string
		if req.Username != "" {
			args = []string{"-L", server, "-U", fmt.Sprintf("%s%%%s", req.Username, req.Password)}
		} else {
			args = []string{"-L", server, "-N"}
		}

		cmd := exec.Command("smbclient", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			errorResponse(w, http.StatusBadRequest, fmt.Sprintf("SMB connection test failed: %s", string(output)))
			return
		}

	case "nfs":
		// Use showmount to test
		parts := strings.SplitN(req.RemotePath, ":", 2)
		if len(parts) != 2 {
			errorResponse(w, http.StatusBadRequest, "Invalid NFS path format (expected server:/path)")
			return
		}
		server := parts[0]

		cmd := exec.Command("showmount", "-e", server)
		output, err := cmd.CombinedOutput()
		if err != nil {
			errorResponse(w, http.StatusBadRequest, fmt.Sprintf("NFS connection test failed: %s", string(output)))
			return
		}

	default:
		errorResponse(w, http.StatusBadRequest, "Invalid mount type (use 'smb' or 'nfs')")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Connection test successful",
	})
}

// ListMounts returns all active mounts
func (h *HALHandler) ListMounts(w http.ResponseWriter, r *http.Request) {
	var mounts []map[string]interface{}

	file, err := os.Open("/proc/mounts")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to read mounts")
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		device := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]
		options := fields[3]

		// Filter to only show relevant mounts (cifs, nfs, ext4 on /cubeos)
		if fsType == "cifs" || fsType == "nfs" || fsType == "nfs4" ||
			(strings.HasPrefix(mountPoint, "/cubeos") && fsType == "ext4") {
			mounts = append(mounts, map[string]interface{}{
				"device":      device,
				"mount_point": mountPoint,
				"fs_type":     fsType,
				"options":     options,
			})
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"mounts": mounts,
	})
}

// CheckMounted checks if a path is mounted
func (h *HALHandler) CheckMounted(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		errorResponse(w, http.StatusBadRequest, "path query parameter is required")
		return
	}

	mounted := false
	file, err := os.Open("/proc/mounts")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && fields[1] == path {
				mounted = true
				break
			}
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"mounted": mounted,
		"path":    path,
	})
}
