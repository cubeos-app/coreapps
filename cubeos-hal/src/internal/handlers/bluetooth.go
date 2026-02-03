package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"github.com/go-chi/chi/v5"
)

// ============================================================================
// Bluetooth Types
// ============================================================================

// BluetoothDevice represents a Bluetooth device.
// @Description Bluetooth device information
type BluetoothDevice struct {
	Address   string `json:"address" example:"DC:A6:32:12:34:56"`
	Name      string `json:"name" example:"My Phone"`
	Paired    bool   `json:"paired" example:"true"`
	Connected bool   `json:"connected" example:"false"`
	Trusted   bool   `json:"trusted" example:"true"`
	Class     string `json:"class,omitempty" example:"Phone"`
	RSSI      int    `json:"rssi,omitempty" example:"-50"`
}

// BluetoothDevicesResponse represents Bluetooth devices list.
// @Description List of Bluetooth devices
type BluetoothDevicesResponse struct {
	Paired    []BluetoothDevice `json:"paired"`
	Available []BluetoothDevice `json:"available,omitempty"`
}

// BluetoothStatus represents Bluetooth adapter status.
// @Description Bluetooth adapter status
type BluetoothStatus struct {
	Available    bool   `json:"available" example:"true"`
	Powered      bool   `json:"powered" example:"true"`
	Discoverable bool   `json:"discoverable" example:"false"`
	Pairable     bool   `json:"pairable" example:"true"`
	Name         string `json:"name" example:"CubeOS"`
	Address      string `json:"address" example:"DC:A6:32:AA:BB:CC"`
	Alias        string `json:"alias,omitempty" example:"CubeOS"`
}

// BluetoothConnectRequest represents a Bluetooth connect request.
// @Description Bluetooth connect parameters
type BluetoothConnectRequest struct {
	Address string `json:"address" example:"DC:A6:32:12:34:56"`
}

// ============================================================================
// Bluetooth Adapter Handlers
// ============================================================================

// GetBluetoothStatus returns Bluetooth adapter status.
// @Summary Get Bluetooth status
// @Description Returns Bluetooth adapter status
// @Tags Bluetooth
// @Accept json
// @Produce json
// @Success 200 {object} BluetoothStatus
// @Failure 404 {object} ErrorResponse "Bluetooth not available"
// @Failure 500 {object} ErrorResponse
// @Router /bluetooth/status [get]
func (h *HALHandler) GetBluetoothStatus(w http.ResponseWriter, r *http.Request) {
	status := BluetoothStatus{
		Available: false,
	}

	// Check if bluetoothctl is available
	cmd := exec.Command("bluetoothctl", "show")
	output, err := cmd.Output()
	if err != nil {
		errorResponse(w, http.StatusNotFound, "Bluetooth not available")
		return
	}

	status.Available = true

	// Parse output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Controller ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				status.Address = parts[1]
			}
		}

		if strings.HasPrefix(line, "Name:") {
			status.Name = strings.TrimPrefix(line, "Name: ")
		}

		if strings.HasPrefix(line, "Alias:") {
			status.Alias = strings.TrimPrefix(line, "Alias: ")
		}

		if strings.HasPrefix(line, "Powered:") {
			status.Powered = strings.Contains(line, "yes")
		}

		if strings.HasPrefix(line, "Discoverable:") {
			status.Discoverable = strings.Contains(line, "yes")
		}

		if strings.HasPrefix(line, "Pairable:") {
			status.Pairable = strings.Contains(line, "yes")
		}
	}

	jsonResponse(w, http.StatusOK, status)
}

// PowerOnBluetooth powers on Bluetooth.
// @Summary Power on Bluetooth
// @Description Powers on the Bluetooth adapter
// @Tags Bluetooth
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /bluetooth/power/on [post]
func (h *HALHandler) PowerOnBluetooth(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("bluetoothctl", "power", "on")
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to power on: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "Bluetooth powered on")
}

// PowerOffBluetooth powers off Bluetooth.
// @Summary Power off Bluetooth
// @Description Powers off the Bluetooth adapter
// @Tags Bluetooth
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /bluetooth/power/off [post]
func (h *HALHandler) PowerOffBluetooth(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("bluetoothctl", "power", "off")
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to power off: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "Bluetooth powered off")
}

// ============================================================================
// Bluetooth Device Handlers
// ============================================================================

// GetBluetoothDevices lists Bluetooth devices.
// @Summary List Bluetooth devices
// @Description Returns list of paired and available Bluetooth devices
// @Tags Bluetooth
// @Accept json
// @Produce json
// @Success 200 {object} BluetoothDevicesResponse
// @Failure 500 {object} ErrorResponse
// @Router /bluetooth/devices [get]
func (h *HALHandler) GetBluetoothDevices(w http.ResponseWriter, r *http.Request) {
	response := BluetoothDevicesResponse{
		Paired:    h.getPairedBluetoothDevices(),
		Available: []BluetoothDevice{},
	}

	jsonResponse(w, http.StatusOK, response)
}

// ScanBluetoothDevices scans for Bluetooth devices.
// @Summary Scan Bluetooth devices
// @Description Scans for available Bluetooth devices (async)
// @Tags Bluetooth
// @Accept json
// @Produce json
// @Param duration query int false "Scan duration in seconds" default(10)
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /bluetooth/scan [post]
func (h *HALHandler) ScanBluetoothDevices(w http.ResponseWriter, r *http.Request) {
	// Start scanning
	cmd := exec.Command("bluetoothctl", "scan", "on")
	if err := cmd.Start(); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to start scan: "+err.Error())
		return
	}

	successResponse(w, "Bluetooth scan started (run GET /bluetooth/devices to see results)")
}

// PairBluetoothDevice pairs with a Bluetooth device.
// @Summary Pair Bluetooth device
// @Description Initiates pairing with a Bluetooth device
// @Tags Bluetooth
// @Accept json
// @Produce json
// @Param request body BluetoothConnectRequest true "Device address"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /bluetooth/pair [post]
func (h *HALHandler) PairBluetoothDevice(w http.ResponseWriter, r *http.Request) {
	var req BluetoothConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Address == "" {
		errorResponse(w, http.StatusBadRequest, "address required")
		return
	}

	cmd := exec.Command("bluetoothctl", "pair", req.Address)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("pairing failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("pairing initiated with %s", req.Address))
}

// ConnectBluetoothDevice connects to a Bluetooth device.
// @Summary Connect Bluetooth device
// @Description Connects to a paired Bluetooth device
// @Tags Bluetooth
// @Accept json
// @Produce json
// @Param address path string true "Device address" example(DC:A6:32:12:34:56)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /bluetooth/connect/{address} [post]
func (h *HALHandler) ConnectBluetoothDevice(w http.ResponseWriter, r *http.Request) {
	address := chi.URLParam(r, "address")
	if address == "" {
		errorResponse(w, http.StatusBadRequest, "address required")
		return
	}

	cmd := exec.Command("bluetoothctl", "connect", address)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("connect failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("connected to %s", address))
}

// DisconnectBluetoothDevice disconnects from a Bluetooth device.
// @Summary Disconnect Bluetooth device
// @Description Disconnects from a connected Bluetooth device
// @Tags Bluetooth
// @Accept json
// @Produce json
// @Param address path string true "Device address" example(DC:A6:32:12:34:56)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /bluetooth/disconnect/{address} [post]
func (h *HALHandler) DisconnectBluetoothDevice(w http.ResponseWriter, r *http.Request) {
	address := chi.URLParam(r, "address")
	if address == "" {
		errorResponse(w, http.StatusBadRequest, "address required")
		return
	}

	cmd := exec.Command("bluetoothctl", "disconnect", address)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("disconnect failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("disconnected from %s", address))
}

// RemoveBluetoothDevice removes a paired Bluetooth device.
// @Summary Remove Bluetooth device
// @Description Removes a paired Bluetooth device
// @Tags Bluetooth
// @Accept json
// @Produce json
// @Param address path string true "Device address" example(DC:A6:32:12:34:56)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /bluetooth/remove/{address} [delete]
func (h *HALHandler) RemoveBluetoothDevice(w http.ResponseWriter, r *http.Request) {
	address := chi.URLParam(r, "address")
	if address == "" {
		errorResponse(w, http.StatusBadRequest, "address required")
		return
	}

	cmd := exec.Command("bluetoothctl", "remove", address)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("remove failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("removed %s", address))
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *HALHandler) getPairedBluetoothDevices() []BluetoothDevice {
	var devices []BluetoothDevice

	cmd := exec.Command("bluetoothctl", "devices", "Paired")
	output, err := cmd.Output()
	if err != nil {
		return devices
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse: "Device DC:A6:32:12:34:56 My Phone"
		if strings.HasPrefix(line, "Device ") {
			parts := strings.SplitN(line[7:], " ", 2)
			if len(parts) >= 1 {
				device := BluetoothDevice{
					Address: parts[0],
					Paired:  true,
				}
				if len(parts) >= 2 {
					device.Name = parts[1]
				}

				// Check if connected
				infoCmd := exec.Command("bluetoothctl", "info", device.Address)
				if infoOutput, err := infoCmd.Output(); err == nil {
					device.Connected = strings.Contains(string(infoOutput), "Connected: yes")
					device.Trusted = strings.Contains(string(infoOutput), "Trusted: yes")
				}

				devices = append(devices, device)
			}
		}
	}

	return devices
}
