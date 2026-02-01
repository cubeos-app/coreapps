package handlers

import (
	"bufio"
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

// GetNetworkStatus returns overall network status
func (h *HALHandler) GetNetworkStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"interfaces": []NetworkInterface{},
		"internet":   false,
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

	// Check internet connectivity
	cmd := exec.Command("ping", "-c", "1", "-W", "2", "8.8.8.8")
	if cmd.Run() == nil {
		status["internet"] = true
	}

	jsonResponse(w, http.StatusOK, status)
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
		"hostapd":            true,
		"dnsmasq":            true,
		"wpa_supplicant":     true,
		"NetworkManager":     true,
		"docker":             true,
		"cubeos-watchdog":    true,
		"systemd-resolved":   true,
		"systemd-networkd":   true,
		"ssh":                true,
		"sshd":               true,
	}

	if !allowed[name] {
		errorResponse(w, http.StatusForbidden, "service not in whitelist: "+name)
		return
	}

	cmd := exec.Command("systemctl", "restart", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to restart %s: %s - %s", name, err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("service %s restarted", name))
}

// StartService starts a systemd service
func (h *HALHandler) StartService(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "service name required")
		return
	}

	cmd := exec.Command("systemctl", "start", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to start %s: %s - %s", name, err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("service %s started", name))
}

// StopService stops a systemd service
func (h *HALHandler) StopService(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "service name required")
		return
	}

	cmd := exec.Command("systemctl", "stop", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to stop %s: %s - %s", name, err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("service %s stopped", name))
}

// ServiceStatus gets the status of a systemd service
func (h *HALHandler) ServiceStatus(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		errorResponse(w, http.StatusBadRequest, "service name required")
		return
	}

	cmd := exec.Command("systemctl", "is-active", name)
	output, _ := cmd.Output()
	active := strings.TrimSpace(string(output)) == "active"

	cmd = exec.Command("systemctl", "is-enabled", name)
	output, _ = cmd.Output()
	enabled := strings.TrimSpace(string(output)) == "enabled"

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"name":    name,
		"active":  active,
		"enabled": enabled,
	})
}
