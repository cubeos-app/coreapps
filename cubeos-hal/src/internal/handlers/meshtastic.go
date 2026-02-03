package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ============================================================================
// Meshtastic Types
// ============================================================================

// MeshtasticDevice represents a Meshtastic device.
// @Description Meshtastic LoRa device information
type MeshtasticDevice struct {
	Port      string `json:"port" example:"/dev/ttyUSB0"`
	Name      string `json:"name" example:"Meshtastic"`
	NodeID    string `json:"node_id,omitempty" example:"!abcd1234"`
	LongName  string `json:"long_name,omitempty" example:"CubeOS Node"`
	ShortName string `json:"short_name,omitempty" example:"CUBE"`
	HWModel   string `json:"hw_model,omitempty" example:"TBEAM"`
	Firmware  string `json:"firmware,omitempty" example:"2.0.0"`
	Connected bool   `json:"connected" example:"true"`
}

// MeshtasticStatus represents Meshtastic status.
// @Description Meshtastic network status
type MeshtasticStatus struct {
	Available  bool              `json:"available" example:"true"`
	Connected  bool              `json:"connected" example:"true"`
	Device     *MeshtasticDevice `json:"device,omitempty"`
	NodeCount  int               `json:"node_count" example:"5"`
	ChannelURL string            `json:"channel_url,omitempty"`
}

// MeshtasticNode represents a node in the mesh.
// @Description Meshtastic mesh network node
type MeshtasticNode struct {
	NodeID       string  `json:"node_id" example:"!abcd1234"`
	LongName     string  `json:"long_name" example:"Remote Node"`
	ShortName    string  `json:"short_name" example:"REM"`
	HWModel      string  `json:"hw_model,omitempty" example:"TBEAM"`
	SNR          float64 `json:"snr,omitempty" example:"10.5"`
	LastHeard    string  `json:"last_heard,omitempty" example:"2026-02-03T16:30:00Z"`
	Hops         int     `json:"hops,omitempty" example:"1"`
	BatteryLevel int     `json:"battery_level,omitempty" example:"85"`
	Latitude     float64 `json:"latitude,omitempty" example:"52.3676"`
	Longitude    float64 `json:"longitude,omitempty" example:"4.9041"`
	Altitude     float64 `json:"altitude,omitempty" example:"10.0"`
}

// MeshtasticPosition represents local position.
// @Description Meshtastic local position
type MeshtasticPosition struct {
	Latitude  float64 `json:"latitude" example:"52.3676"`
	Longitude float64 `json:"longitude" example:"4.9041"`
	Altitude  float64 `json:"altitude,omitempty" example:"10.0"`
	Timestamp string  `json:"timestamp" example:"2026-02-03T16:30:00Z"`
	Valid     bool    `json:"valid" example:"true"`
}

// MeshtasticMessage represents a message to send.
// @Description Meshtastic message parameters
type MeshtasticMessage struct {
	Text        string `json:"text" example:"Hello mesh!"`
	Destination string `json:"destination,omitempty" example:"!abcd1234"`
	Channel     int    `json:"channel,omitempty" example:"0"`
}

// ============================================================================
// Meshtastic Handlers
// ============================================================================

// GetMeshtasticDevices lists Meshtastic devices.
// @Summary List Meshtastic devices
// @Description Returns list of connected Meshtastic LoRa devices
// @Tags Meshtastic
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /meshtastic/devices [get]
func (h *HALHandler) GetMeshtasticDevices(w http.ResponseWriter, r *http.Request) {
	devices := h.scanMeshtasticDevices()
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"count":   len(devices),
		"devices": devices,
	})
}

// GetMeshtasticStatus returns Meshtastic status.
// @Summary Get Meshtastic status
// @Description Returns Meshtastic network and device status
// @Tags Meshtastic
// @Accept json
// @Produce json
// @Param port query string false "Serial port" default(/dev/ttyUSB0)
// @Success 200 {object} MeshtasticStatus
// @Failure 500 {object} ErrorResponse
// @Router /meshtastic/status [get]
func (h *HALHandler) GetMeshtasticStatus(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	if port == "" {
		port = "/dev/ttyUSB0"
	}

	status := MeshtasticStatus{
		Available: false,
	}

	// Check if meshtastic CLI is available
	if _, err := exec.LookPath("meshtastic"); err != nil {
		jsonResponse(w, http.StatusOK, status)
		return
	}

	// Check if port exists
	if _, err := os.Stat(port); err != nil {
		jsonResponse(w, http.StatusOK, status)
		return
	}

	status.Available = true

	// Get device info
	output, err := exec.Command("meshtastic", "--port", port, "--info").Output()
	if err == nil {
		status.Connected = true
		device := h.parseMeshtasticInfo(string(output), port)
		status.Device = &device
	}

	// Get node count
	nodesOutput, err := exec.Command("meshtastic", "--port", port, "--nodes").Output()
	if err == nil {
		nodes := h.parseMeshtasticNodes(string(nodesOutput))
		status.NodeCount = len(nodes)
	}

	jsonResponse(w, http.StatusOK, status)
}

// GetMeshtasticNodes returns mesh nodes.
// @Summary Get mesh nodes
// @Description Returns list of nodes in the Meshtastic mesh network
// @Tags Meshtastic
// @Accept json
// @Produce json
// @Param port query string false "Serial port" default(/dev/ttyUSB0)
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /meshtastic/nodes [get]
func (h *HALHandler) GetMeshtasticNodes(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	if port == "" {
		port = "/dev/ttyUSB0"
	}

	output, err := exec.Command("meshtastic", "--port", port, "--nodes").Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get nodes: "+err.Error())
		return
	}

	nodes := h.parseMeshtasticNodes(string(output))
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"count": len(nodes),
		"nodes": nodes,
	})
}

// GetMeshtasticPosition returns local position.
// @Summary Get Meshtastic position
// @Description Returns the local Meshtastic node's GPS position
// @Tags Meshtastic
// @Accept json
// @Produce json
// @Param port query string false "Serial port" default(/dev/ttyUSB0)
// @Success 200 {object} MeshtasticPosition
// @Failure 500 {object} ErrorResponse
// @Router /meshtastic/position [get]
func (h *HALHandler) GetMeshtasticPosition(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	if port == "" {
		port = "/dev/ttyUSB0"
	}

	position := MeshtasticPosition{
		Valid: false,
	}

	output, err := exec.Command("meshtastic", "--port", port, "--info").Output()
	if err != nil {
		jsonResponse(w, http.StatusOK, position)
		return
	}

	// Parse position from info output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "latitude:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "latitude:"))
			position.Latitude, _ = strconv.ParseFloat(val, 64)
		}
		if strings.HasPrefix(line, "longitude:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "longitude:"))
			position.Longitude, _ = strconv.ParseFloat(val, 64)
		}
		if strings.HasPrefix(line, "altitude:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "altitude:"))
			position.Altitude, _ = strconv.ParseFloat(val, 64)
		}
	}

	if position.Latitude != 0 || position.Longitude != 0 {
		position.Valid = true
	}

	jsonResponse(w, http.StatusOK, position)
}

// SendMeshtasticMessage sends a message via Meshtastic.
// @Summary Send Meshtastic message
// @Description Sends a text message via the Meshtastic mesh network
// @Tags Meshtastic
// @Accept json
// @Produce json
// @Param port query string false "Serial port" default(/dev/ttyUSB0)
// @Param request body MeshtasticMessage true "Message parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /meshtastic/send [post]
func (h *HALHandler) SendMeshtasticMessage(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	if port == "" {
		port = "/dev/ttyUSB0"
	}

	var req MeshtasticMessage
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Text == "" {
		errorResponse(w, http.StatusBadRequest, "text required")
		return
	}

	args := []string{"--port", port, "--sendtext", req.Text}

	if req.Destination != "" {
		args = append(args, "--dest", req.Destination)
	}

	if req.Channel > 0 {
		args = append(args, "--ch-index", strconv.Itoa(req.Channel))
	}

	cmd := exec.Command("meshtastic", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("send failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "message sent via Meshtastic")
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *HALHandler) scanMeshtasticDevices() []MeshtasticDevice {
	var devices []MeshtasticDevice

	// Check common serial ports
	ports := []string{
		"/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2",
		"/dev/ttyACM0", "/dev/ttyACM1",
	}

	for _, port := range ports {
		if _, err := os.Stat(port); err == nil {
			// Try to identify as Meshtastic device
			device := MeshtasticDevice{
				Port: port,
				Name: "Meshtastic Device",
			}

			// Try to get device info
			output, err := exec.Command("meshtastic", "--port", port, "--info").Output()
			if err == nil {
				device.Connected = true
				info := h.parseMeshtasticInfo(string(output), port)
				device.NodeID = info.NodeID
				device.LongName = info.LongName
				device.ShortName = info.ShortName
				device.HWModel = info.HWModel
				device.Firmware = info.Firmware
				devices = append(devices, device)
			}
		}
	}

	return devices
}

func (h *HALHandler) parseMeshtasticInfo(output string, port string) MeshtasticDevice {
	device := MeshtasticDevice{
		Port:      port,
		Connected: true,
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Owner:") {
			device.LongName = strings.TrimSpace(strings.TrimPrefix(line, "Owner:"))
		}
		if strings.HasPrefix(line, "My info:") {
			// Extract node ID from "My info: { 'num': 123, 'user': {...} }"
			if idx := strings.Index(line, "'num':"); idx != -1 {
				numStr := line[idx+6:]
				if endIdx := strings.Index(numStr, ","); endIdx != -1 {
					numStr = strings.TrimSpace(numStr[:endIdx])
					if num, err := strconv.Atoi(numStr); err == nil {
						device.NodeID = fmt.Sprintf("!%08x", num)
					}
				}
			}
		}
		if strings.HasPrefix(line, "Hardware model:") {
			device.HWModel = strings.TrimSpace(strings.TrimPrefix(line, "Hardware model:"))
		}
		if strings.HasPrefix(line, "Firmware version:") {
			device.Firmware = strings.TrimSpace(strings.TrimPrefix(line, "Firmware version:"))
		}
	}

	return device
}

func (h *HALHandler) parseMeshtasticNodes(output string) []MeshtasticNode {
	var nodes []MeshtasticNode

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip header and empty lines
		if line == "" || strings.HasPrefix(line, "╔") || strings.HasPrefix(line, "║") ||
			strings.HasPrefix(line, "╚") || strings.Contains(line, "User") {
			continue
		}

		// Parse table row (format varies by meshtastic CLI version)
		if strings.Contains(line, "!") {
			node := MeshtasticNode{}

			// Try to extract node ID (starts with !)
			if idx := strings.Index(line, "!"); idx != -1 {
				nodeIDEnd := strings.Index(line[idx:], " ")
				if nodeIDEnd == -1 {
					node.NodeID = line[idx:]
				} else {
					node.NodeID = line[idx : idx+nodeIDEnd]
				}
			}

			nodes = append(nodes, node)
		}
	}

	return nodes
}

// SetMeshtasticChannel sets the Meshtastic channel.
func (h *HALHandler) SetMeshtasticChannel(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, http.StatusNotImplemented, "Meshtastic channel configuration not yet implemented")
}
