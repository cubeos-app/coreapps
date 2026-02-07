package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/go-chi/chi/v5"
)

// powerActionInProgress guards against double-invocation of reboot/shutdown.
var powerActionInProgress atomic.Bool

// ============================================================================
// System Types
// ============================================================================

// TemperatureResponse represents CPU temperature.
// @Description CPU temperature reading
type TemperatureResponse struct {
	Temperature float64 `json:"temperature" example:"56.5"`
	Unit        string  `json:"unit" example:"celsius"`
	Source      string  `json:"source" example:"sysfs"`
}

// ThrottleStatus represents throttling status.
// @Description CPU throttling status flags
type ThrottleStatus struct {
	UnderVoltageOccurred         bool   `json:"under_voltage_occurred" example:"false"`
	ArmFrequencyCappedOccurred   bool   `json:"arm_frequency_capped_occurred" example:"false"`
	CurrentlyThrottled           bool   `json:"currently_throttled" example:"false"`
	SoftTemperatureLimitOccurred bool   `json:"soft_temperature_limit_occurred" example:"false"`
	UnderVoltageNow              bool   `json:"under_voltage_now" example:"false"`
	ArmFrequencyCappedNow        bool   `json:"arm_frequency_capped_now" example:"false"`
	ThrottledNow                 bool   `json:"throttled_now" example:"false"`
	SoftTemperatureLimitNow      bool   `json:"soft_temperature_limit_now" example:"false"`
	RawHex                       string `json:"raw_hex" example:"0x0"`
	Source                       string `json:"source,omitempty" example:"sysfs"`
}

// EEPROMInfo represents Raspberry Pi EEPROM information.
// @Description Raspberry Pi EEPROM/firmware information
type EEPROMInfo struct {
	Version    string `json:"version" example:"2024-01-15"`
	Bootloader string `json:"bootloader,omitempty"`
	VL805      string `json:"vl805,omitempty"`
	Model      string `json:"model,omitempty" example:"Raspberry Pi 5 Model B Rev 1.0"`
	Serial     string `json:"serial,omitempty" example:"10000000abcd1234"`
	Revision   string `json:"revision,omitempty"`
}

// BootConfig represents boot configuration.
// @Description Boot configuration from config.txt
type BootConfig struct {
	Config map[string]string `json:"config"`
	Raw    string            `json:"raw,omitempty"`
}

// ServiceStatus represents a systemd service status.
// @Description Systemd service status
type ServiceStatus struct {
	Name        string `json:"name" example:"cubeos-hal"`
	Active      bool   `json:"active" example:"true"`
	Running     bool   `json:"running" example:"true"`
	Enabled     bool   `json:"enabled" example:"true"`
	Description string `json:"description,omitempty"`
	LoadState   string `json:"load_state" example:"loaded"`
	ActiveState string `json:"active_state" example:"active"`
	SubState    string `json:"sub_state" example:"running"`
	MainPID     int    `json:"main_pid,omitempty" example:"1234"`
}

// ============================================================================
// System Control Handlers
// ============================================================================

// Reboot reboots the system.
// @Summary Reboot system
// @Description Initiates a system reboot
// @Tags System
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /system/reboot [post]
func (h *HALHandler) Reboot(w http.ResponseWriter, r *http.Request) {
	if !powerActionInProgress.CompareAndSwap(false, true) {
		errorResponse(w, http.StatusConflict, "power action already in progress")
		return
	}
	successResponse(w, "system rebooting...")
	go func() {
		time.Sleep(1 * time.Second)
		if _, err := execWithTimeout(context.Background(), "systemctl", "reboot"); err != nil {
			log.Printf("reboot command failed: %v", err)
			powerActionInProgress.Store(false) // Reset on failure so retry is possible
		}
	}()
}

// Shutdown shuts down the system.
// @Summary Shutdown system
// @Description Initiates a system shutdown
// @Tags System
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /system/shutdown [post]
func (h *HALHandler) Shutdown(w http.ResponseWriter, r *http.Request) {
	if !powerActionInProgress.CompareAndSwap(false, true) {
		errorResponse(w, http.StatusConflict, "power action already in progress")
		return
	}
	successResponse(w, "system shutting down...")
	go func() {
		time.Sleep(1 * time.Second)
		if _, err := execWithTimeout(context.Background(), "systemctl", "poweroff"); err != nil {
			log.Printf("shutdown command failed: %v", err)
			powerActionInProgress.Store(false)
		}
	}()
}

// ============================================================================
// System Information Handlers
// ============================================================================

// GetCPUTemp returns CPU temperature.
// @Summary Get CPU temperature
// @Description Returns current CPU temperature from sysfs thermal zone
// @Tags System
// @Accept json
// @Produce json
// @Success 200 {object} TemperatureResponse
// @Failure 500 {object} ErrorResponse
// @Router /system/temperature [get]
func (h *HALHandler) GetCPUTemp(w http.ResponseWriter, r *http.Request) {
	// Read from sysfs thermal zone (works in containers without vcgencmd)
	// Returns millidegrees, e.g., 57850 = 57.85°C
	thermalPaths := []string{
		"/sys/class/thermal/thermal_zone0/temp",
		"/sys/devices/virtual/thermal/thermal_zone0/temp",
	}

	var temp float64
	var source string
	var found bool

	for _, path := range thermalPaths {
		data, err := os.ReadFile(path)
		if err == nil {
			milliTemp, parseErr := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
			if parseErr == nil {
				temp = float64(milliTemp) / 1000.0
				source = "sysfs"
				found = true
				break
			}
		}
	}

	if !found {
		errorResponse(w, http.StatusInternalServerError, "failed to read temperature from sysfs")
		return
	}

	jsonResponse(w, http.StatusOK, TemperatureResponse{
		Temperature: temp,
		Unit:        "celsius",
		Source:      source,
	})
}

// GetThrottleStatus returns throttling status.
// @Summary Get throttle status
// @Description Returns CPU throttling status flags from sysfs
// @Tags System
// @Accept json
// @Produce json
// @Success 200 {object} ThrottleStatus
// @Failure 500 {object} ErrorResponse
// @Router /system/throttle [get]
func (h *HALHandler) GetThrottleStatus(w http.ResponseWriter, r *http.Request) {
	// Try sysfs first (Raspberry Pi kernel exposes this)
	throttlePaths := []string{
		"/sys/devices/platform/soc/soc:firmware/get_throttled",
		"/sys/class/hwmon/hwmon0/throttled",
	}

	var hexVal string
	var source string
	var found bool

	for _, path := range throttlePaths {
		data, err := os.ReadFile(path)
		if err == nil {
			hexVal = strings.TrimSpace(string(data))
			source = "sysfs"
			found = true
			break
		}
	}

	// If sysfs not available, return zeros (no throttling detected)
	if !found {
		// Return empty throttle status rather than error
		// This allows the endpoint to work in containers/VMs
		status := ThrottleStatus{
			RawHex: "0x0",
			Source: "unavailable",
		}
		jsonResponse(w, http.StatusOK, status)
		return
	}

	// Parse hex value (may be "0x0" or just "0")
	hexVal = strings.TrimPrefix(hexVal, "0x")
	val, err := strconv.ParseInt(hexVal, 16, 64)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to parse throttle status")
		return
	}

	status := ThrottleStatus{
		UnderVoltageOccurred:         val&(1<<16) != 0,
		ArmFrequencyCappedOccurred:   val&(1<<17) != 0,
		CurrentlyThrottled:           val&(1<<18) != 0,
		SoftTemperatureLimitOccurred: val&(1<<19) != 0,
		UnderVoltageNow:              val&(1<<0) != 0,
		ArmFrequencyCappedNow:        val&(1<<1) != 0,
		ThrottledNow:                 val&(1<<2) != 0,
		SoftTemperatureLimitNow:      val&(1<<3) != 0,
		RawHex:                       "0x" + hexVal,
		Source:                       source,
	}

	jsonResponse(w, http.StatusOK, status)
}

// GetEEPROMInfo returns Raspberry Pi EEPROM/firmware information.
// @Summary Get EEPROM info
// @Description Returns Raspberry Pi EEPROM/firmware version and hardware info
// @Tags System
// @Accept json
// @Produce json
// @Success 200 {object} EEPROMInfo
// @Failure 500 {object} ErrorResponse
// @Router /system/eeprom [get]
func (h *HALHandler) GetEEPROMInfo(w http.ResponseWriter, r *http.Request) {
	info := EEPROMInfo{}

	// Try to get bootloader version from /proc/device-tree (works without vcgencmd)
	if data, err := os.ReadFile("/proc/device-tree/system/linux,revision"); err == nil {
		info.Revision = fmt.Sprintf("%x", data)
	}

	// Get model info from /proc/cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Model") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					info.Model = strings.TrimSpace(parts[1])
				}
			}
			if strings.HasPrefix(line, "Serial") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					info.Serial = strings.TrimSpace(parts[1])
				}
			}
			if strings.HasPrefix(line, "Revision") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					info.Revision = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	// Try to get bootloader info from /proc/device-tree
	if data, err := os.ReadFile("/proc/device-tree/chosen/bootloader/version"); err == nil {
		info.Version = strings.TrimSpace(strings.TrimRight(string(data), "\x00"))
	}

	jsonResponse(w, http.StatusOK, info)
}

// GetBootConfig returns boot configuration.
// @Summary Get boot configuration
// @Description Returns boot configuration from config.txt
// @Tags System
// @Accept json
// @Produce json
// @Success 200 {object} BootConfig
// @Failure 500 {object} ErrorResponse
// @Router /system/bootconfig [get]
func (h *HALHandler) GetBootConfig(w http.ResponseWriter, r *http.Request) {
	config := BootConfig{
		Config: make(map[string]string),
	}

	// Try common config.txt locations
	configPaths := []string{
		"/boot/firmware/config.txt",
		"/boot/config.txt",
	}

	for _, path := range configPaths {
		if data, err := os.ReadFile(path); err == nil {
			config.Raw = string(data)
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					config.Config[parts[0]] = parts[1]
				}
			}
			break
		}
	}

	jsonResponse(w, http.StatusOK, config)
}

// ============================================================================
// Service Management Handlers
// ============================================================================

// ServiceStatus returns the status of a systemd service.
// @Summary Get service status
// @Description Returns the status of a systemd service
// @Tags System
// @Accept json
// @Produce json
// @Param name path string true "Service name" example(cubeos-hal)
// @Success 200 {object} ServiceStatus
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /system/service/{name}/status [get]
func (h *HALHandler) ServiceStatus(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := validateServiceName(name); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Ensure .service suffix
	if !strings.HasSuffix(name, ".service") {
		name = name + ".service"
	}

	ctx := context.Background()
	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		log.Printf("ServiceStatus: dbus connection failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "failed to connect to system manager")
		return
	}
	defer conn.Close()

	status := ServiceStatus{Name: name}

	// Get unit properties
	props, err := conn.GetUnitPropertiesContext(ctx, name)
	if err != nil {
		log.Printf("ServiceStatus: GetUnitProperties failed for %s: %v", name, err)
		errorResponse(w, http.StatusInternalServerError, "failed to get service status")
		return
	}

	if v, ok := props["ActiveState"].(string); ok {
		status.ActiveState = v
		status.Active = v == "active"
	}
	if v, ok := props["SubState"].(string); ok {
		status.SubState = v
		status.Running = v == "running"
	}
	if v, ok := props["LoadState"].(string); ok {
		status.LoadState = v
	}
	if v, ok := props["Description"].(string); ok {
		status.Description = v
	}
	if v, ok := props["MainPID"].(uint32); ok {
		status.MainPID = int(v)
	}

	// Check if enabled using systemctl
	if enabledOutput, err := execWithTimeout(r.Context(), "systemctl", "is-enabled", name); err == nil {
		status.Enabled = strings.TrimSpace(enabledOutput) == "enabled"
	}

	jsonResponse(w, http.StatusOK, status)
}

// RestartService restarts a systemd service.
// @Summary Restart service
// @Description Restarts a systemd service
// @Tags System
// @Accept json
// @Produce json
// @Param name path string true "Service name" example(cubeos-hal)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /system/service/{name}/restart [post]
func (h *HALHandler) RestartService(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := validateServiceName(name); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	if !strings.HasSuffix(name, ".service") {
		name = name + ".service"
	}

	ctx := context.Background()
	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		log.Printf("RestartService: dbus connection failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "failed to connect to system manager")
		return
	}
	defer conn.Close()

	resultChan := make(chan string, 1)
	_, err = conn.RestartUnitContext(ctx, name, "replace", resultChan)
	if err != nil {
		log.Printf("RestartService: RestartUnit failed for %s: %v", name, err)
		errorResponse(w, http.StatusInternalServerError, "failed to restart service")
		return
	}

	result := <-resultChan
	if result != "done" {
		errorResponse(w, http.StatusInternalServerError, "service restart failed")
		return
	}

	successResponse(w, fmt.Sprintf("service %s restarted", name))
}

// StartService starts a systemd service.
// @Summary Start service
// @Description Starts a systemd service
// @Tags System
// @Accept json
// @Produce json
// @Param name path string true "Service name" example(cubeos-hal)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /system/service/{name}/start [post]
func (h *HALHandler) StartService(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := validateServiceName(name); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	if !strings.HasSuffix(name, ".service") {
		name = name + ".service"
	}

	ctx := context.Background()
	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		log.Printf("StartService: dbus connection failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "failed to connect to system manager")
		return
	}
	defer conn.Close()

	resultChan := make(chan string, 1)
	_, err = conn.StartUnitContext(ctx, name, "replace", resultChan)
	if err != nil {
		log.Printf("StartService: StartUnit failed for %s: %v", name, err)
		errorResponse(w, http.StatusInternalServerError, "failed to start service")
		return
	}

	result := <-resultChan
	if result != "done" {
		errorResponse(w, http.StatusInternalServerError, "service start failed")
		return
	}

	successResponse(w, fmt.Sprintf("service %s started", name))
}

// StopService stops a systemd service.
// @Summary Stop service
// @Description Stops a systemd service
// @Tags System
// @Accept json
// @Produce json
// @Param name path string true "Service name" example(cubeos-hal)
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /system/service/{name}/stop [post]
func (h *HALHandler) StopService(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := validateServiceName(name); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	if !strings.HasSuffix(name, ".service") {
		name = name + ".service"
	}

	ctx := context.Background()
	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		log.Printf("StopService: dbus connection failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "failed to connect to system manager")
		return
	}
	defer conn.Close()

	resultChan := make(chan string, 1)
	_, err = conn.StopUnitContext(ctx, name, "replace", resultChan)
	if err != nil {
		log.Printf("StopService: StopUnit failed for %s: %v", name, err)
		errorResponse(w, http.StatusInternalServerError, "failed to stop service")
		return
	}

	result := <-resultChan
	if result != "done" {
		errorResponse(w, http.StatusInternalServerError, "service stop failed")
		return
	}

	successResponse(w, fmt.Sprintf("service %s stopped", name))
}
