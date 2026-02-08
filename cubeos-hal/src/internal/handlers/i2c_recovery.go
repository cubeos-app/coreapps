package handlers

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// ============================================================================
// I2C Bus Recovery
// ============================================================================
//
// The DesignWare I2C controller on the RP1 (Raspberry Pi 5) can enter a stuck
// state where all transactions time out, even though SDA/SCL lines are idle.
// Recovery is achieved by unbinding and rebinding the platform driver via sysfs:
//
//   echo "<device>" > /sys/bus/platform/drivers/i2c_designware/unbind
//   echo "<device>" > /sys/bus/platform/drivers/i2c_designware/bind
//
// This module tracks consecutive I2C read errors and triggers the recovery
// automatically when the threshold is reached, with rate limiting to prevent
// reset storms.

const (
	defaultI2CDevicePath       = "1f00074000.i2c" // RP1 I2C1 on Pi 5
	defaultI2CDriverPath       = "/sys/bus/platform/drivers/i2c_designware"
	defaultRecoveryThreshold   = 3               // consecutive errors before recovery
	defaultRecoveryMinInterval = 5 * time.Minute // minimum time between recovery attempts
	defaultRecoverySettleTime  = 2 * time.Second // wait after rebind before retrying
)

// I2CRecovery handles automatic recovery of stuck DesignWare I2C controllers.
type I2CRecovery struct {
	mu                sync.Mutex
	devicePath        string        // e.g. "1f00074000.i2c"
	driverPath        string        // e.g. "/sys/bus/platform/drivers/i2c_designware"
	threshold         int           // consecutive errors before attempting recovery
	minInterval       time.Duration // minimum time between recovery attempts
	settleTime        time.Duration // wait after rebind
	consecutiveErrors int           // current consecutive error count
	lastAttemptAt     time.Time     // when we last attempted recovery
	totalRecoveries   int           // lifetime recovery count
	lastRecoveryOK    bool          // whether last recovery succeeded
}

// NewI2CRecovery creates an I2CRecovery with configuration from environment variables.
//
// Environment variables:
//   - HAL_I2C_DEVICE:            RP1 device path (default: "1f00074000.i2c")
//   - HAL_I2C_DRIVER_PATH:       sysfs driver path (default: "/sys/bus/platform/drivers/i2c_designware")
//   - HAL_I2C_RECOVERY_THRESHOLD: consecutive errors before recovery (default: 3)
func NewI2CRecovery() *I2CRecovery {
	devicePath := getEnvOrDefault("HAL_I2C_DEVICE", defaultI2CDevicePath)
	driverPath := getEnvOrDefault("HAL_I2C_DRIVER_PATH", defaultI2CDriverPath)

	threshold := defaultRecoveryThreshold
	if v := os.Getenv("HAL_I2C_RECOVERY_THRESHOLD"); v != "" {
		if n := parseIntOrDefault(v, defaultRecoveryThreshold); n > 0 && n <= 20 {
			threshold = n
		}
	}

	return &I2CRecovery{
		devicePath:  devicePath,
		driverPath:  driverPath,
		threshold:   threshold,
		minInterval: defaultRecoveryMinInterval,
		settleTime:  defaultRecoverySettleTime,
	}
}

// RecordError increments the consecutive error counter.
// Returns true if recovery should be attempted (threshold reached and rate limit allows).
func (r *I2CRecovery) RecordError() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.consecutiveErrors++

	if r.consecutiveErrors < r.threshold {
		return false
	}

	// Check rate limit
	if !r.lastAttemptAt.IsZero() && time.Since(r.lastAttemptAt) < r.minInterval {
		return false
	}

	return true
}

// RecordSuccess resets the consecutive error counter.
func (r *I2CRecovery) RecordSuccess() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.consecutiveErrors = 0
}

// AttemptRecovery performs the I2C controller unbind/bind sequence.
// Returns nil on success. Thread-safe and rate-limited.
func (r *I2CRecovery) AttemptRecovery() error {
	r.mu.Lock()
	// Double-check rate limit under lock
	if !r.lastAttemptAt.IsZero() && time.Since(r.lastAttemptAt) < r.minInterval {
		r.mu.Unlock()
		return fmt.Errorf("recovery rate-limited (last attempt %s ago, minimum interval %s)",
			time.Since(r.lastAttemptAt).Round(time.Second), r.minInterval)
	}
	r.lastAttemptAt = time.Now()
	r.consecutiveErrors = 0 // Reset counter regardless of outcome
	device := r.devicePath
	driver := r.driverPath
	settle := r.settleTime
	r.mu.Unlock()

	unbindPath := driver + "/unbind"
	bindPath := driver + "/bind"

	log.Printf("I2CRecovery: attempting controller reset for %s", device)

	// Step 1: Unbind the device
	if err := os.WriteFile(unbindPath, []byte(device), 0200); err != nil {
		r.mu.Lock()
		r.lastRecoveryOK = false
		r.mu.Unlock()
		return fmt.Errorf("unbind %s: %w", device, err)
	}
	log.Printf("I2CRecovery: unbound %s", device)

	// Wait for controller to release
	time.Sleep(1 * time.Second)

	// Step 2: Rebind the device
	if err := os.WriteFile(bindPath, []byte(device), 0200); err != nil {
		r.mu.Lock()
		r.lastRecoveryOK = false
		r.mu.Unlock()
		return fmt.Errorf("bind %s: %w", device, err)
	}
	log.Printf("I2CRecovery: rebound %s", device)

	// Wait for controller to settle before any I2C access
	time.Sleep(settle)

	r.mu.Lock()
	r.totalRecoveries++
	r.lastRecoveryOK = true
	r.mu.Unlock()

	log.Printf("I2CRecovery: controller reset complete (total recoveries: %d)", r.totalRecoveries)
	return nil
}

// Stats returns recovery statistics for inclusion in status responses.
func (r *I2CRecovery) Stats() I2CRecoveryStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	stats := I2CRecoveryStats{
		ConsecutiveErrors: r.consecutiveErrors,
		TotalRecoveries:   r.totalRecoveries,
		DevicePath:        r.devicePath,
	}

	if !r.lastAttemptAt.IsZero() {
		t := r.lastAttemptAt.UTC().Format(time.RFC3339)
		stats.LastAttemptAt = &t
		stats.LastRecoveryOK = r.lastRecoveryOK
	}

	return stats
}

// I2CRecoveryStats is the JSON-serializable recovery status.
type I2CRecoveryStats struct {
	ConsecutiveErrors int     `json:"consecutive_errors"`
	TotalRecoveries   int     `json:"total_recoveries"`
	DevicePath        string  `json:"device_path"`
	LastAttemptAt     *string `json:"last_attempt_at"`
	LastRecoveryOK    bool    `json:"last_recovery_ok"`
}

// parseIntOrDefault parses a string as int, returning defaultVal on failure.
func parseIntOrDefault(s string, defaultVal int) int {
	var val int
	for _, c := range s {
		if c < '0' || c > '9' {
			return defaultVal
		}
		val = val*10 + int(c-'0')
	}
	return val
}
