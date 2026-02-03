package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"cubeos-hal/internal/devices"
)

// ============================================================================
// Constants - Geekworm X1202 / MAX17040
// ============================================================================

const (
	// I2C
	DefaultI2CBus      = 1
	MAX17040Address    = 0x36
	MAX17040RegVCELL   = 0x02 // Battery voltage
	MAX17040RegSOC     = 0x04 // State of charge
	MAX17040RegMODE    = 0x06 // Mode (quick-start)
	MAX17040RegVERSION = 0x08 // IC version
	MAX17040RegRCOMP   = 0x0C // Compensation
	MAX17040RegCOMMAND = 0xFE // Command register

	// GPIO pins (BCM numbering)
	GPIOPowerLoss   = 6  // Input: HIGH = AC present, LOW = power lost
	GPIOChargeCtrl  = 16 // Output: LOW = charging, HIGH = not charging

	// Thresholds
	LowBatteryThreshold      = 15.0 // Percent - trigger warning
	CriticalBatteryThreshold = 5.0  // Percent - trigger shutdown
	ShutdownDelaySeconds     = 30   // Seconds to wait before shutdown on power loss
)

// ============================================================================
// Types
// ============================================================================

// BatteryStatus represents current battery state
type BatteryStatus struct {
	Available           bool    `json:"available"`
	Voltage             float64 `json:"voltage"`               // Volts
	VoltageRaw          uint16  `json:"voltage_raw"`           // Raw register value
	Percentage          float64 `json:"percentage"`            // 0-100 (from fuel gauge)
	PercentageEstimated float64 `json:"percentage_estimated"`  // 0-100 (from voltage lookup, more reliable)
	PercentageRaw       uint16  `json:"percentage_raw"`        // Raw register value
	IsCharging          bool    `json:"is_charging"`           // Inferred from voltage trend
	ChargingEnabled     bool    `json:"charging_enabled"`      // GPIO16 state
	ACPresent           bool    `json:"ac_present"`            // GPIO6 state
	IsLow               bool    `json:"is_low"`                // Below warning threshold
	IsCritical          bool    `json:"is_critical"`           // Below critical threshold
	LastUpdated         string  `json:"last_updated"`
}

// UPSInfo contains UPS hardware information
type UPSInfo struct {
	Model       string `json:"model"`
	Detected    bool   `json:"detected"`
	I2CAddress  string `json:"i2c_address"`
	I2CBus      int    `json:"i2c_bus"`
	FuelGauge   string `json:"fuel_gauge"`
	GPIOChip    string `json:"gpio_chip"`
	PiVersion   int    `json:"pi_version"`
	ChipVersion uint16 `json:"chip_version,omitempty"`
}

// PowerStatus combines all power-related information
type PowerStatus struct {
	UPS         UPSInfo       `json:"ups"`
	Battery     BatteryStatus `json:"battery"`
	Uptime      UptimeInfo    `json:"uptime"`
	RTC         RTCStatus     `json:"rtc"`
	Watchdog    WatchdogInfo  `json:"watchdog"`
	LastUpdated string        `json:"last_updated"`
}

// UptimeInfo contains system uptime information
type UptimeInfo struct {
	Seconds     float64 `json:"seconds"`
	Formatted   string  `json:"formatted"` // "5d 3h 22m 15s"
	BootTime    string  `json:"boot_time"` // ISO timestamp
	LoadAverage []float64 `json:"load_average"`
}

// RTCStatus contains RTC information
type RTCStatus struct {
	Available     bool   `json:"available"`
	Time          string `json:"time"`           // Current RTC time
	Synchronized  bool   `json:"synchronized"`   // Synced with system
	BatteryOK     bool   `json:"battery_ok"`     // RTC battery present
	WakeAlarmSet  bool   `json:"wake_alarm_set"` // Wake alarm configured
	WakeAlarmTime string `json:"wake_alarm_time,omitempty"`
}

// WatchdogInfo contains watchdog status
type WatchdogInfo struct {
	Available bool   `json:"available"`
	Active    bool   `json:"active"`
	Timeout   int    `json:"timeout"`   // Seconds
	Identity  string `json:"identity"`  // Driver name
	Device    string `json:"device"`    // /dev/watchdog
}

// ============================================================================
// Package State
// ============================================================================

var (
	powerMonitorOnce     sync.Once
	powerMonitorCancel   context.CancelFunc
	powerMonitorMu       sync.RWMutex
	lastBatteryStatus    BatteryStatus
	lastVoltage          float64 // For charging inference
	voltageHistory       []float64
	voltageHistoryMu     sync.Mutex
)

// ============================================================================
// Public Handlers
// ============================================================================

// GetPowerStatus returns comprehensive power status
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

// GetBatteryStatus returns current battery status
func (h *HALHandler) GetBatteryStatus(w http.ResponseWriter, r *http.Request) {
	status := h.getBatteryStatus()
	jsonResponse(w, http.StatusOK, status)
}

// GetUPSInfo returns UPS hardware information
func (h *HALHandler) GetUPSInfo(w http.ResponseWriter, r *http.Request) {
	info := h.getUPSInfo()
	jsonResponse(w, http.StatusOK, info)
}

// SetChargingEnabled enables or disables battery charging
func (h *HALHandler) SetChargingEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.setCharging(req.Enabled); err != nil {
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	action := "enabled"
	if !req.Enabled {
		action = "disabled"
	}
	successResponse(w, fmt.Sprintf("charging %s", action))
}

// QuickStartBattery performs a quick-start on the fuel gauge
func (h *HALHandler) QuickStartBattery(w http.ResponseWriter, r *http.Request) {
	bus, err := devices.OpenI2CBus(DefaultI2CBus)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to open I2C bus: "+err.Error())
		return
	}
	defer bus.Close()

	// Write 0x4000 to MODE register for quick-start
	if err := bus.WriteWord(MAX17040Address, MAX17040RegMODE, 0x4000); err != nil {
		errorResponse(w, http.StatusInternalServerError, "quick-start failed: "+err.Error())
		return
	}

	successResponse(w, "battery fuel gauge quick-start initiated")
}

// GetUptime returns system uptime information
func (h *HALHandler) GetUptime(w http.ResponseWriter, r *http.Request) {
	info := h.getUptimeInfo()
	jsonResponse(w, http.StatusOK, info)
}

// GetRTCStatus returns RTC status
func (h *HALHandler) GetRTCStatus(w http.ResponseWriter, r *http.Request) {
	status := h.getRTCStatus()
	jsonResponse(w, http.StatusOK, status)
}

// SetRTCTime sets the RTC time from system time
func (h *HALHandler) SetRTCTime(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("hwclock", "-w")
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to set RTC: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "RTC time set from system clock")
}

// SyncTimeFromRTC sets system time from RTC
func (h *HALHandler) SyncTimeFromRTC(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("hwclock", "-s")
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync from RTC: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "system time synced from RTC")
}

// SetWakeAlarm sets the RTC wake alarm
func (h *HALHandler) SetWakeAlarm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SecondsFromNow int    `json:"seconds_from_now,omitempty"`
		Timestamp      string `json:"timestamp,omitempty"` // RFC3339 format
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var alarmTime int64
	if req.SecondsFromNow > 0 {
		alarmTime = time.Now().Unix() + int64(req.SecondsFromNow)
	} else if req.Timestamp != "" {
		t, err := time.Parse(time.RFC3339, req.Timestamp)
		if err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid timestamp format, use RFC3339")
			return
		}
		alarmTime = t.Unix()
	} else {
		errorResponse(w, http.StatusBadRequest, "specify seconds_from_now or timestamp")
		return
	}

	// Write to wakealarm sysfs
	alarmStr := fmt.Sprintf("%d", alarmTime)
	if err := os.WriteFile("/sys/class/rtc/rtc0/wakealarm", []byte(alarmStr), 0644); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to set wake alarm: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"wake_alarm": alarmTime,
		"wake_time":  time.Unix(alarmTime, 0).UTC().Format(time.RFC3339),
	})
}

// ClearWakeAlarm clears the RTC wake alarm
func (h *HALHandler) ClearWakeAlarm(w http.ResponseWriter, r *http.Request) {
	if err := os.WriteFile("/sys/class/rtc/rtc0/wakealarm", []byte("0"), 0644); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to clear wake alarm: "+err.Error())
		return
	}

	successResponse(w, "wake alarm cleared")
}

// GetWatchdogStatus returns watchdog information
func (h *HALHandler) GetWatchdogStatus(w http.ResponseWriter, r *http.Request) {
	info := h.getWatchdogInfo()
	jsonResponse(w, http.StatusOK, info)
}

// StartPowerMonitor starts background power monitoring
func (h *HALHandler) StartPowerMonitor(w http.ResponseWriter, r *http.Request) {
	h.startPowerMonitor()
	successResponse(w, "power monitor started")
}

// StopPowerMonitor stops background power monitoring
func (h *HALHandler) StopPowerMonitor(w http.ResponseWriter, r *http.Request) {
	if powerMonitorCancel != nil {
		powerMonitorCancel()
		powerMonitorCancel = nil
	}
	successResponse(w, "power monitor stopped")
}

// ============================================================================
// I2C Scan Handlers
// ============================================================================

// ListI2CBuses returns available I2C buses
func (h *HALHandler) ListI2CBuses(w http.ResponseWriter, r *http.Request) {
	var buses []map[string]interface{}

	// Check for common I2C buses
	for i := 0; i <= 10; i++ {
		path := fmt.Sprintf("/dev/i2c-%d", i)
		if _, err := os.Stat(path); err == nil {
			buses = append(buses, map[string]interface{}{
				"bus":  i,
				"path": path,
			})
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"buses": buses,
		"count": len(buses),
	})
}

// ScanI2CBus scans an I2C bus for devices
func (h *HALHandler) ScanI2CBus(w http.ResponseWriter, r *http.Request) {
	busStr := r.URL.Query().Get("bus")
	if busStr == "" {
		busStr = "1" // Default to bus 1
	}

	busNum, err := strconv.Atoi(busStr)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid bus number")
		return
	}

	bus, err := devices.OpenI2CBus(busNum)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer bus.Close()

	addresses := bus.ScanBus()
	var deviceList []devices.I2CDeviceInfo
	for _, addr := range addresses {
		deviceList = append(deviceList, devices.GetDeviceInfo(addr))
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"bus":     busNum,
		"devices": deviceList,
		"count":   len(deviceList),
	})
}

// ============================================================================
// Private Methods - Battery/UPS
// ============================================================================

func (h *HALHandler) getBatteryStatus() BatteryStatus {
	status := BatteryStatus{
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
	}

	bus, err := devices.OpenI2CBus(DefaultI2CBus)
	if err != nil {
		return status
	}
	defer bus.Close()

	// Read voltage (register 0x02)
	voltageRaw, err := bus.ReadWord(MAX17040Address, MAX17040RegVCELL)
	if err != nil {
		return status
	}
	status.Available = true
	status.VoltageRaw = voltageRaw
	// MAX17040: 12-bit value, upper 12 bits, 1.25mV per bit
	status.Voltage = float64(voltageRaw>>4) * 0.00125

	// Calculate voltage-based SOC estimate (more reliable without calibration)
	status.PercentageEstimated = estimateSOCFromVoltage(status.Voltage)

	// Read SOC (register 0x04)
	socRaw, err := bus.ReadWord(MAX17040Address, MAX17040RegSOC)
	if err == nil {
		status.PercentageRaw = socRaw
		// High byte = integer %, low byte = 1/256%
		status.Percentage = float64(socRaw>>8) + float64(socRaw&0xFF)/256.0
	}

	// Check AC power via GPIO6
	status.ACPresent = h.readGPIO(GPIOPowerLoss) == 1

	// Check charging control via GPIO16 (LOW = charging enabled)
	status.ChargingEnabled = h.readGPIO(GPIOChargeCtrl) == 0

	// Infer charging state from voltage trend
	voltageHistoryMu.Lock()
	voltageHistory = append(voltageHistory, status.Voltage)
	if len(voltageHistory) > 10 {
		voltageHistory = voltageHistory[1:]
	}
	if len(voltageHistory) >= 3 {
		// Charging if voltage trending up and AC present
		trend := voltageHistory[len(voltageHistory)-1] - voltageHistory[0]
		status.IsCharging = trend > 0.01 && status.ACPresent
	}
	voltageHistoryMu.Unlock()

	// Check thresholds
	status.IsLow = status.Percentage < LowBatteryThreshold
	status.IsCritical = status.Percentage < CriticalBatteryThreshold

	// Update cached status
	powerMonitorMu.Lock()
	lastBatteryStatus = status
	powerMonitorMu.Unlock()

	return status
}

// estimateSOCFromVoltage calculates battery percentage from voltage
// This is more reliable than the fuel gauge without calibration
// Li-ion discharge curve for single cell (nominal 3.7V, 4.2V max)
func estimateSOCFromVoltage(voltage float64) float64 {
	switch {
	case voltage >= 4.20:
		return 100.0
	case voltage >= 4.00:
		// 80-100% range
		return 80.0 + (voltage-4.00)*100.0
	case voltage >= 3.85:
		// 65-80% range
		return 65.0 + (voltage-3.85)*100.0
	case voltage >= 3.70:
		// 40-65% range
		return 40.0 + (voltage-3.70)*166.67
	case voltage >= 3.50:
		// 15-40% range
		return 15.0 + (voltage-3.50)*125.0
	case voltage >= 3.30:
		// 0-15% range
		return (voltage - 3.30) * 75.0
	default:
		return 0.0
	}
}

func (h *HALHandler) getUPSInfo() UPSInfo {
	piVersion, gpioChip := devices.DetectPiVersion()

	info := UPSInfo{
		Model:      "Geekworm X1202",
		I2CAddress: fmt.Sprintf("0x%02X", MAX17040Address),
		I2CBus:     DefaultI2CBus,
		FuelGauge:  "MAX17040",
		GPIOChip:   gpioChip,
		PiVersion:  piVersion,
	}

	// Try to read from the fuel gauge to confirm it's present
	bus, err := devices.OpenI2CBus(DefaultI2CBus)
	if err != nil {
		return info
	}
	defer bus.Close()

	version, err := bus.ReadWord(MAX17040Address, MAX17040RegVERSION)
	if err == nil {
		info.Detected = true
		info.ChipVersion = version
	}

	return info
}

func (h *HALHandler) setCharging(enabled bool) error {
	piVersion, gpioChip := devices.DetectPiVersion()
	_ = piVersion

	chip, err := devices.OpenGPIOChip(gpioChip)
	if err != nil {
		return fmt.Errorf("failed to open GPIO chip: %w", err)
	}
	defer chip.Close()

	// Request GPIO16 as output
	// LOW = charging enabled, HIGH = charging disabled
	var value uint8 = 1 // Disabled
	if enabled {
		value = 0 // Enabled
	}

	line, err := chip.RequestLine(GPIOChargeCtrl, true, value, "cubeos-hal")
	if err != nil {
		return fmt.Errorf("failed to request GPIO line: %w", err)
	}
	defer line.Close()

	return line.SetValue(value)
}

func (h *HALHandler) readGPIO(pin uint32) uint8 {
	_, gpioChip := devices.DetectPiVersion()

	chip, err := devices.OpenGPIOChip(gpioChip)
	if err != nil {
		return 0
	}
	defer chip.Close()

	line, err := chip.RequestLine(pin, false, 0, "cubeos-hal")
	if err != nil {
		return 0
	}
	defer line.Close()

	value, err := line.GetValue()
	if err != nil {
		return 0
	}

	return value
}

// ============================================================================
// Private Methods - Uptime
// ============================================================================

func (h *HALHandler) getUptimeInfo() UptimeInfo {
	info := UptimeInfo{}

	// Read uptime from /proc/uptime
	data, err := os.ReadFile("/proc/uptime")
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			info.Seconds, _ = strconv.ParseFloat(fields[0], 64)
		}
	}

	// Format uptime nicely
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

	// Calculate boot time
	bootTime := time.Now().Add(-duration)
	info.BootTime = bootTime.UTC().Format(time.RFC3339)

	// Read load average from /proc/loadavg
	loadData, err := os.ReadFile("/proc/loadavg")
	if err == nil {
		fields := strings.Fields(string(loadData))
		if len(fields) >= 3 {
			load1, _ := strconv.ParseFloat(fields[0], 64)
			load5, _ := strconv.ParseFloat(fields[1], 64)
			load15, _ := strconv.ParseFloat(fields[2], 64)
			info.LoadAverage = []float64{load1, load5, load15}
		}
	}

	return info
}

// ============================================================================
// Private Methods - RTC
// ============================================================================

func (h *HALHandler) getRTCStatus() RTCStatus {
	status := RTCStatus{}

	// Check if RTC device exists
	if _, err := os.Stat("/dev/rtc0"); err == nil {
		status.Available = true
	} else {
		return status
	}

	// Read RTC time using hwclock
	cmd := exec.Command("hwclock", "-r", "--utc")
	output, err := cmd.Output()
	if err == nil {
		status.Time = strings.TrimSpace(string(output))
	}

	// Check if synchronized (compare with system time)
	rtcTime, err := time.Parse("2006-01-02 15:04:05.999999-07:00", status.Time)
	if err == nil {
		diff := time.Since(rtcTime)
		if diff < 0 {
			diff = -diff
		}
		status.Synchronized = diff < 5*time.Second
	}

	// Check RTC battery by reading sysfs (Pi 5 specific)
	if data, err := os.ReadFile("/sys/class/rtc/rtc0/device/battery_voltage"); err == nil {
		voltage := strings.TrimSpace(string(data))
		if v, err := strconv.Atoi(voltage); err == nil && v > 2000000 { // > 2V in microvolts
			status.BatteryOK = true
		}
	} else {
		// Assume OK if we can't read (might not be Pi 5)
		status.BatteryOK = true
	}

	// Check wake alarm
	if data, err := os.ReadFile("/sys/class/rtc/rtc0/wakealarm"); err == nil {
		alarmStr := strings.TrimSpace(string(data))
		if alarmStr != "" && alarmStr != "0" {
			status.WakeAlarmSet = true
			if epoch, err := strconv.ParseInt(alarmStr, 10, 64); err == nil {
				status.WakeAlarmTime = time.Unix(epoch, 0).UTC().Format(time.RFC3339)
			}
		}
	}

	return status
}

// ============================================================================
// Private Methods - Watchdog
// ============================================================================

func (h *HALHandler) getWatchdogInfo() WatchdogInfo {
	info := WatchdogInfo{
		Device: "/dev/watchdog",
	}

	// Check if watchdog device exists
	if _, err := os.Stat("/dev/watchdog"); err == nil {
		info.Available = true
	} else {
		return info
	}

	// Read identity from sysfs
	if data, err := os.ReadFile("/sys/class/watchdog/watchdog0/identity"); err == nil {
		info.Identity = strings.TrimSpace(string(data))
	}

	// Read timeout from sysfs
	if data, err := os.ReadFile("/sys/class/watchdog/watchdog0/timeout"); err == nil {
		if timeout, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			info.Timeout = timeout
		}
	}

	// Check if watchdog is active (state file)
	if data, err := os.ReadFile("/sys/class/watchdog/watchdog0/state"); err == nil {
		state := strings.TrimSpace(string(data))
		info.Active = state == "active"
	}

	return info
}

// ============================================================================
// Background Power Monitor
// ============================================================================

func (h *HALHandler) startPowerMonitor() {
	powerMonitorOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		powerMonitorCancel = cancel

		go h.powerMonitorLoop(ctx)
	})
}

func (h *HALHandler) powerMonitorLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var powerLostTime time.Time
	powerLost := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status := h.getBatteryStatus()

			// Check for AC power loss
			if !status.ACPresent && !powerLost {
				powerLost = true
				powerLostTime = time.Now()
				// Log warning
				fmt.Printf("[POWER] AC power lost! Battery at %.1f%%\n", status.Percentage)
			} else if status.ACPresent && powerLost {
				powerLost = false
				fmt.Printf("[POWER] AC power restored. Battery at %.1f%%\n", status.Percentage)
			}

			// Check for critical battery or prolonged power loss
			if status.IsCritical {
				fmt.Printf("[POWER] CRITICAL: Battery at %.1f%%, initiating shutdown!\n", status.Percentage)
				h.initiateGracefulShutdown("critical battery level")
				return
			}

			if powerLost && time.Since(powerLostTime) > time.Duration(ShutdownDelaySeconds)*time.Second {
				if status.Percentage < 50 { // Only shutdown if battery isn't full
					fmt.Printf("[POWER] Extended power loss, battery at %.1f%%, initiating shutdown!\n", status.Percentage)
					h.initiateGracefulShutdown("extended power loss")
					return
				}
			}
		}
	}
}

func (h *HALHandler) initiateGracefulShutdown(reason string) {
	fmt.Printf("[POWER] Graceful shutdown initiated: %s\n", reason)

	// Give services time to clean up
	time.Sleep(5 * time.Second)

	// Execute shutdown
	cmd := exec.Command("shutdown", "-h", "now", fmt.Sprintf("UPS: %s", reason))
	cmd.Run()
}

// ============================================================================
// Watchdog Pet Handler (for external use)
// ============================================================================

// PetWatchdog writes to the watchdog device to prevent reset
func (h *HALHandler) PetWatchdog(w http.ResponseWriter, r *http.Request) {
	file, err := os.OpenFile("/dev/watchdog", os.O_WRONLY, 0)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to open watchdog: "+err.Error())
		return
	}
	defer file.Close()

	// Write any byte to pet the watchdog
	_, err = file.Write([]byte("1"))
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to pet watchdog: "+err.Error())
		return
	}

	successResponse(w, "watchdog pet successful")
}

// EnableWatchdog opens the watchdog (starts the timer)
func (h *HALHandler) EnableWatchdog(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Timeout int `json:"timeout"` // Seconds (max 15 for Pi)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Timeout = 14 // Default to 14 seconds
	}

	if req.Timeout > 15 {
		req.Timeout = 15 // Hardware max
	}

	// Set timeout via ioctl
	file, err := os.OpenFile("/dev/watchdog", os.O_WRONLY, 0)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to open watchdog: "+err.Error())
		return
	}
	// Note: Don't close the file - closing disables watchdog unless nowayout=1
	// This is intentional - we keep it open

	// Set timeout using WDIOC_SETTIMEOUT
	const WDIOC_SETTIMEOUT = 0xC0045706
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		file.Fd(),
		WDIOC_SETTIMEOUT,
		uintptr(unsafe.Pointer(&req.Timeout)),
	)
	if errno != 0 {
		file.Close()
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to set timeout: %v", errno))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": "watchdog enabled",
		"timeout": req.Timeout,
		"warning": "watchdog file kept open - closing would disable it",
	})
}
