package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// Constants - Geekworm X1202 / MAX17040
// ============================================================================

const (
	DefaultI2CBus      = 1
	MAX17040Address    = 0x36
	MAX17040RegVCELL   = 0x02
	MAX17040RegSOC     = 0x04
	MAX17040RegMODE    = 0x06
	MAX17040RegVERSION = 0x08

	GPIOPowerLoss  = 6  // Input: HIGH = AC present, LOW = power lost
	GPIOChargeCtrl = 16 // Output: LOW = charging, HIGH = not charging

	LowBatteryThreshold      = 15.0
	CriticalBatteryThreshold = 5.0
)

// ============================================================================
// Power Types
// ============================================================================

// BatteryStatus represents current battery state.
// @Description Battery status information from X1202 UPS
type BatteryStatus struct {
	Available           bool    `json:"available" example:"true"`
	Voltage             float64 `json:"voltage" example:"4.12"`
	VoltageRaw          uint16  `json:"voltage_raw,omitempty"`
	Percentage          float64 `json:"percentage" example:"85.5"`
	PercentageEstimated float64 `json:"percentage_estimated,omitempty" example:"87.0"`
	PercentageRaw       uint16  `json:"percentage_raw,omitempty"`
	IsCharging          bool    `json:"is_charging" example:"true"`
	ChargingEnabled     bool    `json:"charging_enabled" example:"true"`
	ACPresent           bool    `json:"ac_present" example:"true"`
	IsLow               bool    `json:"is_low" example:"false"`
	IsCritical          bool    `json:"is_critical" example:"false"`
	LastUpdated         string  `json:"last_updated"`
}

// UPSInfo contains UPS hardware information.
// @Description UPS hardware detection information
type UPSInfo struct {
	Model       string `json:"model" example:"Geekworm X1202"`
	Detected    bool   `json:"detected" example:"true"`
	I2CAddress  string `json:"i2c_address" example:"0x36"`
	I2CBus      int    `json:"i2c_bus" example:"1"`
	FuelGauge   string `json:"fuel_gauge" example:"MAX17040"`
	GPIOChip    string `json:"gpio_chip" example:"gpiochip4"`
	PiVersion   int    `json:"pi_version" example:"5"`
	ChipVersion uint16 `json:"chip_version,omitempty"`
}

// PowerStatus combines all power-related information.
// @Description Complete power status including UPS, battery, uptime, RTC, and watchdog
type PowerStatus struct {
	UPS         UPSInfo       `json:"ups"`
	Battery     BatteryStatus `json:"battery"`
	Uptime      UptimeInfo    `json:"uptime"`
	RTC         RTCStatus     `json:"rtc"`
	Watchdog    WatchdogInfo  `json:"watchdog"`
	LastUpdated string        `json:"last_updated"`
}

// UptimeInfo contains system uptime information.
// @Description System uptime information
type UptimeInfo struct {
	Seconds     float64   `json:"seconds" example:"593949.26"`
	Formatted   string    `json:"formatted" example:"6d 21h 5m 49s"`
	BootTime    string    `json:"boot_time" example:"2026-01-27T19:00:00Z"`
	LoadAverage []float64 `json:"load_average"`
}

// RTCStatus contains RTC information.
// @Description Real-Time Clock status
type RTCStatus struct {
	Available    bool   `json:"available" example:"true"`
	Time         string `json:"time" example:"2026-02-03T16:15:30Z"`
	Synchronized bool   `json:"synchronized" example:"true"`
	BatteryOK    bool   `json:"battery_ok" example:"true"`
	Device       string `json:"device,omitempty" example:"/dev/rtc0"`
}

// WatchdogInfo contains watchdog information.
// @Description Hardware watchdog status
type WatchdogInfo struct {
	Device  string `json:"device" example:"/dev/watchdog"`
	Enabled bool   `json:"enabled" example:"true"`
	Timeout int    `json:"timeout" example:"15"`
}

// ChargingRequest represents charging control request.
// @Description Charging control parameters
type ChargingRequest struct {
	Enabled bool `json:"enabled" example:"true"`
}

// WakeAlarmRequest represents wake alarm request.
// @Description Wake alarm parameters
type WakeAlarmRequest struct {
	Time string `json:"time" example:"2026-02-04T08:00:00Z"`
}

// ============================================================================
// Power Status Handlers
// ============================================================================

// GetPowerStatus returns complete power status.
// @Summary Get power status
// @Description Returns complete power status including UPS, battery, uptime, RTC, and watchdog
// @Tags Power
// @Accept json
// @Produce json
// @Success 200 {object} PowerStatus
// @Failure 500 {object} ErrorResponse
// @Router /power/status [get]
func (h *HALHandler) GetPowerStatus(w http.ResponseWriter, r *http.Request) {
	status := PowerStatus{
		UPS:         h.getUPSInfo(),
		Battery:     h.getBatteryStatus(),
		Uptime:      h.getUptimeInfo(),
		RTC:         h.getRTCStatus(),
		Watchdog:    h.getWatchdogInfo(),
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
	}

	jsonResponse(w, http.StatusOK, status)
}

// GetBatteryStatus returns battery status.
// @Summary Get battery status
// @Description Returns battery voltage, percentage, and charging status from X1202 UPS
// @Tags Power
// @Accept json
// @Produce json
// @Success 200 {object} BatteryStatus
// @Failure 500 {object} ErrorResponse
// @Router /power/battery [get]
func (h *HALHandler) GetBatteryStatus(w http.ResponseWriter, r *http.Request) {
	status := h.getBatteryStatus()
	jsonResponse(w, http.StatusOK, status)
}

// GetUPSInfo returns UPS hardware info.
// @Summary Get UPS info
// @Description Returns UPS hardware detection information (X1202 with MAX17040)
// @Tags Power
// @Accept json
// @Produce json
// @Success 200 {object} UPSInfo
// @Failure 500 {object} ErrorResponse
// @Router /power/ups [get]
func (h *HALHandler) GetUPSInfo(w http.ResponseWriter, r *http.Request) {
	info := h.getUPSInfo()
	jsonResponse(w, http.StatusOK, info)
}

// SetChargingEnabled controls battery charging.
// @Summary Control charging
// @Description Enables or disables battery charging via GPIO
// @Tags Power
// @Accept json
// @Produce json
// @Param request body ChargingRequest true "Charging state"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /power/charging [post]
func (h *HALHandler) SetChargingEnabled(w http.ResponseWriter, r *http.Request) {
	r = limitBody(r, 1<<20) // 1MB
	var req ChargingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// GPIO16: LOW = charging, HIGH = not charging
	value := 0
	if !req.Enabled {
		value = 1
	}

	if _, err := execWithTimeout(r.Context(), "gpioset", "gpiochip4", fmt.Sprintf("%d=%d", GPIOChargeCtrl, value)); err != nil {
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("set charging state", err))
		return
	}

	state := "enabled"
	if !req.Enabled {
		state = "disabled"
	}
	successResponse(w, fmt.Sprintf("charging %s", state))
}

// QuickStartBattery performs fuel gauge quick-start.
// @Summary Quick-start battery
// @Description Performs MAX17040 fuel gauge quick-start for re-calibration
// @Tags Power
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /power/battery/quickstart [post]
func (h *HALHandler) QuickStartBattery(w http.ResponseWriter, r *http.Request) {
	if _, err := execWithTimeout(r.Context(), "i2cset", "-y", "1", "0x36", "0x06", "0x40", "0x00", "i"); err != nil {
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("battery quick-start", err))
		return
	}

	successResponse(w, "battery fuel gauge quick-start initiated")
}

// StartPowerMonitor starts power monitoring.
// @Summary Start power monitor
// @Description Starts background power monitoring (not yet implemented)
// @Tags Power
// @Accept json
// @Produce json
// @Success 501 {object} ErrorResponse
// @Router /power/monitor/start [post]
func (h *HALHandler) StartPowerMonitor(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, http.StatusNotImplemented, "power monitoring not yet implemented")
}

// StopPowerMonitor stops power monitoring.
// @Summary Stop power monitor
// @Description Stops background power monitoring (not yet implemented)
// @Tags Power
// @Accept json
// @Produce json
// @Success 501 {object} ErrorResponse
// @Router /power/monitor/stop [post]
func (h *HALHandler) StopPowerMonitor(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, http.StatusNotImplemented, "power monitoring not yet implemented")
}

// ============================================================================
// Uptime Handler
// ============================================================================

// GetUptime returns system uptime.
// @Summary Get system uptime
// @Description Returns system uptime in seconds, formatted string, boot time, and load average
// @Tags System
// @Accept json
// @Produce json
// @Success 200 {object} UptimeInfo
// @Failure 500 {object} ErrorResponse
// @Router /system/uptime [get]
func (h *HALHandler) GetUptime(w http.ResponseWriter, r *http.Request) {
	info := h.getUptimeInfo()
	jsonResponse(w, http.StatusOK, info)
}

// ============================================================================
// RTC Handlers
// ============================================================================

// GetRTCStatus returns RTC status.
// @Summary Get RTC status
// @Description Returns Real-Time Clock status and current time
// @Tags Power
// @Accept json
// @Produce json
// @Success 200 {object} RTCStatus
// @Failure 500 {object} ErrorResponse
// @Router /rtc/status [get]
func (h *HALHandler) GetRTCStatus(w http.ResponseWriter, r *http.Request) {
	status := h.getRTCStatus()
	jsonResponse(w, http.StatusOK, status)
}

// SetRTCTime sets RTC from system time.
// @Summary Set RTC time
// @Description Sets the RTC time from system clock (hwclock -w)
// @Tags Power
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /rtc/sync-to-rtc [post]
func (h *HALHandler) SetRTCTime(w http.ResponseWriter, r *http.Request) {
	if _, err := execWithTimeout(r.Context(), "hwclock", "-w"); err != nil {
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("set RTC time", err))
		return
	}

	successResponse(w, "RTC time set from system clock")
}

// SyncTimeFromRTC syncs system time from RTC.
// @Summary Sync from RTC
// @Description Sets system time from RTC (hwclock -s)
// @Tags Power
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /rtc/sync-from-rtc [post]
func (h *HALHandler) SyncTimeFromRTC(w http.ResponseWriter, r *http.Request) {
	if _, err := execWithTimeout(r.Context(), "hwclock", "-s"); err != nil {
		errorResponse(w, http.StatusInternalServerError, sanitizeExecError("sync time from RTC", err))
		return
	}

	successResponse(w, "system time synced from RTC")
}

// SetWakeAlarm sets RTC wake alarm.
// @Summary Set wake alarm
// @Description Sets RTC wake alarm for scheduled wake-up
// @Tags Power
// @Accept json
// @Produce json
// @Param request body WakeAlarmRequest true "Wake time"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /rtc/wakealarm [post]
func (h *HALHandler) SetWakeAlarm(w http.ResponseWriter, r *http.Request) {
	r = limitBody(r, 1<<20) // 1MB
	var req WakeAlarmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	t, err := time.Parse(time.RFC3339, req.Time)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid time format, use RFC3339")
		return
	}

	alarmPath := "/sys/class/rtc/rtc0/wakealarm"

	// Clear existing alarm first
	os.WriteFile(alarmPath, []byte("0"), 0644)

	// Set new alarm (unix timestamp)
	if err := os.WriteFile(alarmPath, []byte(strconv.FormatInt(t.Unix(), 10)), 0644); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to set wake alarm: "+err.Error())
		return
	}

	successResponse(w, fmt.Sprintf("wake alarm set for %s", req.Time))
}

// ClearWakeAlarm clears RTC wake alarm.
// @Summary Clear wake alarm
// @Description Clears the RTC wake alarm
// @Tags Power
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /rtc/wakealarm [delete]
func (h *HALHandler) ClearWakeAlarm(w http.ResponseWriter, r *http.Request) {
	alarmPath := "/sys/class/rtc/rtc0/wakealarm"
	if err := os.WriteFile(alarmPath, []byte("0"), 0644); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to clear wake alarm: "+err.Error())
		return
	}

	successResponse(w, "wake alarm cleared")
}

// ============================================================================
// Watchdog Handlers
// ============================================================================

// GetWatchdogStatus returns watchdog status.
// @Summary Get watchdog status
// @Description Returns hardware watchdog status and configuration
// @Tags Power
// @Accept json
// @Produce json
// @Success 200 {object} WatchdogInfo
// @Failure 500 {object} ErrorResponse
// @Router /watchdog/status [get]
func (h *HALHandler) GetWatchdogStatus(w http.ResponseWriter, r *http.Request) {
	info := h.getWatchdogInfo()
	jsonResponse(w, http.StatusOK, info)
}

// PetWatchdog pets the watchdog.
// @Summary Pet watchdog
// @Description Writes to watchdog device to prevent system reset
// @Tags Power
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /watchdog/pet [post]
func (h *HALHandler) PetWatchdog(w http.ResponseWriter, r *http.Request) {
	f, err := os.OpenFile("/dev/watchdog", os.O_WRONLY, 0)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to open watchdog: "+err.Error())
		return
	}
	defer f.Close()

	if _, err := f.Write([]byte{0}); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to pet watchdog: "+err.Error())
		return
	}

	successResponse(w, "watchdog petted")
}

// EnableWatchdog enables the watchdog.
// @Summary Enable watchdog
// @Description Enables the hardware watchdog
// @Tags Power
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Router /watchdog/enable [post]
func (h *HALHandler) EnableWatchdog(w http.ResponseWriter, r *http.Request) {
	successResponse(w, "watchdog enabled (managed by systemd)")
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *HALHandler) getUptimeInfo() UptimeInfo {
	info := UptimeInfo{}

	data, err := os.ReadFile("/proc/uptime")
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			info.Seconds, _ = strconv.ParseFloat(fields[0], 64)
		}
	}

	duration := time.Duration(info.Seconds) * time.Second
	days := int(duration.Hours() / 24)
	hours := int(duration.Hours()) % 24
	minutes := int(duration.Minutes()) % 60
	seconds := int(duration.Seconds()) % 60

	if days > 0 {
		info.Formatted = fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	} else if hours > 0 {
		info.Formatted = fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	} else if minutes > 0 {
		info.Formatted = fmt.Sprintf("%dm %ds", minutes, seconds)
	} else {
		info.Formatted = fmt.Sprintf("%ds", seconds)
	}

	bootTime := time.Now().Add(-duration)
	info.BootTime = bootTime.UTC().Format(time.RFC3339)

	loadData, err := os.ReadFile("/proc/loadavg")
	if err == nil {
		fields := strings.Fields(string(loadData))
		if len(fields) >= 3 {
			info.LoadAverage = make([]float64, 3)
			info.LoadAverage[0], _ = strconv.ParseFloat(fields[0], 64)
			info.LoadAverage[1], _ = strconv.ParseFloat(fields[1], 64)
			info.LoadAverage[2], _ = strconv.ParseFloat(fields[2], 64)
		}
	}

	return info
}

func (h *HALHandler) getBatteryStatus() BatteryStatus {
	status := BatteryStatus{
		Available:   false,
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
	}

	ctx := context.Background()

	// Read voltage from MAX17040
	if output, err := execWithTimeout(ctx, "i2cget", "-y", "1", "0x36", "0x02", "w"); err == nil {
		valStr := strings.TrimSpace(output)
		if val, err := strconv.ParseInt(strings.TrimPrefix(valStr, "0x"), 16, 64); err == nil {
			swapped := ((val & 0xFF) << 8) | ((val >> 8) & 0xFF)
			status.VoltageRaw = uint16(swapped)
			status.Voltage = float64(swapped>>4) * 1.25 / 1000.0
			status.Available = true
		}
	}

	// Read SOC
	if output, err := execWithTimeout(ctx, "i2cget", "-y", "1", "0x36", "0x04", "w"); err == nil {
		valStr := strings.TrimSpace(output)
		if val, err := strconv.ParseInt(strings.TrimPrefix(valStr, "0x"), 16, 64); err == nil {
			swapped := ((val & 0xFF) << 8) | ((val >> 8) & 0xFF)
			status.PercentageRaw = uint16(swapped)
			status.Percentage = float64(swapped>>8) + float64(swapped&0xFF)/256.0
		}
	}

	// Check GPIO for AC present
	if output, err := execWithTimeout(ctx, "gpioget", "gpiochip4", "6"); err == nil {
		status.ACPresent = strings.TrimSpace(output) == "1"
	}

	// Check GPIO for charging enabled
	if output, err := execWithTimeout(ctx, "gpioget", "gpiochip4", "16"); err == nil {
		status.ChargingEnabled = strings.TrimSpace(output) == "0"
	}

	status.IsLow = status.Percentage < LowBatteryThreshold
	status.IsCritical = status.Percentage < CriticalBatteryThreshold

	return status
}

func (h *HALHandler) getUPSInfo() UPSInfo {
	info := UPSInfo{
		Model:      "Geekworm X1202",
		I2CAddress: "0x36",
		I2CBus:     1,
		FuelGauge:  "MAX17040",
		GPIOChip:   "gpiochip4",
		PiVersion:  5,
	}

	if output, err := execWithTimeout(context.Background(), "i2cget", "-y", "1", "0x36", "0x08", "w"); err == nil {
		valStr := strings.TrimSpace(output)
		if val, err := strconv.ParseInt(strings.TrimPrefix(valStr, "0x"), 16, 64); err == nil {
			info.ChipVersion = uint16(val)
			info.Detected = true
		}
	}

	return info
}

func (h *HALHandler) getRTCStatus() RTCStatus {
	status := RTCStatus{
		Available: false,
		Device:    "/dev/rtc0",
	}

	if _, err := os.Stat("/dev/rtc0"); err == nil {
		status.Available = true

		if output, err := execWithTimeout(context.Background(), "hwclock", "-r"); err == nil {
			status.Time = strings.TrimSpace(output)
		}

		status.Synchronized = true
		status.BatteryOK = true
	}

	return status
}

func (h *HALHandler) getWatchdogInfo() WatchdogInfo {
	info := WatchdogInfo{
		Device:  "/dev/watchdog",
		Enabled: false,
		Timeout: 15,
	}

	if _, err := os.Stat("/dev/watchdog"); err == nil {
		info.Enabled = true
	}

	if data, err := os.ReadFile("/sys/class/watchdog/watchdog0/timeout"); err == nil {
		if timeout, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			info.Timeout = timeout
		}
	}

	return info
}
