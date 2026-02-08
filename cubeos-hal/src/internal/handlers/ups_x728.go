package handlers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// ============================================================================
// Geekworm X728 Driver (Pi 2/3/4)
// ============================================================================
//
// 18650 UPS & Power Management Board with Auto On & Safe Shutdown.
// Same MAX17040 fuel gauge as X1202 at I2C 0x36, plus onboard MCU for
// button/shutdown management and DS1307 RTC at 0x68.
//
// CRITICAL: GPIO 6 polarity is INVERTED compared to X1202:
//   - X1202: GPIO 6 HIGH = AC present
//   - X728:  GPIO 6 HIGH = AC LOST
//
// GPIO (BCM, gpiochip0 on Pi 2/3/4):
//   - GPIO 6  input:  HIGH = AC LOST (inverted!)
//   - GPIO 5  input:  Shutdown/reboot signal from MCU (pulse-width encoded)
//   - GPIO 12 output: Boot-OK heartbeat — MUST set HIGH on boot
//   - GPIO 26 output: Software shutdown signal (V2.0+) — pulse HIGH 3s
//   - GPIO 20 output: Buzzer (V2.1+)
//
// Shutdown protocol (MANDATORY):
//  1. Set GPIO 26 HIGH for 3 seconds, then LOW
//  2. Execute systemctl poweroff
//  3. OS halts → GPIO 12 goes LOW → MCU cuts 5V → enters standby
//
// Calling shutdown without pulsing GPIO 26 leaves the X728 draining batteries.

// X728Driver implements UPSDriver for the Geekworm X728 UPS board.
type X728Driver struct {
	i2cBus   string // e.g. "1"
	gpioChip string // e.g. "gpiochip0"
}

func (d *X728Driver) Name() string {
	return "Geekworm X728"
}

// ReadStatus reads battery status from MAX17040 and GPIO pins.
// GPIO 6 polarity is inverted compared to X1202.
func (d *X728Driver) ReadStatus(ctx context.Context) (*BatteryReading, error) {
	reading := &BatteryReading{
		Available:  false,
		DeviceName: d.Name(),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	// Read voltage from MAX17040 register 0x02 — same as X1202
	raw, err := readI2CWord(ctx, d.i2cBus, "0x36", "0x02")
	if err != nil {
		return reading, fmt.Errorf("read voltage: %w", err)
	}
	reading.Voltage = float64(raw>>4) * 1.25 / 1000.0
	reading.Available = true

	// Read SOC from MAX17040 register 0x04 — same as X1202
	socRaw, err := readI2CWord(ctx, d.i2cBus, "0x36", "0x04")
	if err != nil {
		log.Printf("PowerMonitor: X728 SOC read error: %v", err)
	} else {
		reading.Percentage = float64(socRaw>>8) + float64(socRaw&0xFF)/256.0
	}

	// Check GPIO 6 for AC power: HIGH = AC LOST (inverted from X1202!)
	if output, err := execWithTimeout(ctx, "gpioget", d.gpioChip, "6"); err == nil {
		// X728: HIGH (1) means AC lost, so AC present = value is "0"
		reading.ACPresent = strings.TrimSpace(output) == "0"
	}

	// X728 V2.5 has GPIO 16 charge control, but not all versions.
	// Default to charging enabled when AC is present.
	reading.ChargingEnabled = reading.ACPresent
	reading.IsCharging = reading.ACPresent

	return reading, nil
}

func (d *X728Driver) SupportsChargeControl() bool {
	// Only V2.5 has GPIO 16 charge control. Since we can't reliably
	// detect the hardware version, report false by default.
	return false
}

// InitiateShutdown performs the X728 shutdown protocol:
// Pulse GPIO 26 HIGH for 3 seconds to tell the MCU to prepare for power cutoff.
// Falls back to GPIO 13 for V1.x boards if GPIO 26 fails.
func (d *X728Driver) InitiateShutdown(ctx context.Context) error {
	log.Printf("PowerMonitor: X728 shutdown — pulsing GPIO 26 HIGH for 3 seconds")

	// Try GPIO 26 first (V2.0+)
	if _, err := execWithTimeout(ctx, "gpioset", d.gpioChip, "26=1"); err != nil {
		// Fall back to GPIO 13 for V1.x boards
		log.Printf("PowerMonitor: X728 GPIO 26 failed, trying GPIO 13 (V1.x fallback)")
		if _, err := execWithTimeout(ctx, "gpioset", d.gpioChip, "13=1"); err != nil {
			return fmt.Errorf("X728 shutdown signal failed on both GPIO 26 and 13: %w", err)
		}
		time.Sleep(3 * time.Second)
		execWithTimeout(ctx, "gpioset", d.gpioChip, "13=0") //nolint: errcheck
		return nil
	}

	time.Sleep(3 * time.Second)

	if _, err := execWithTimeout(ctx, "gpioset", d.gpioChip, "26=0"); err != nil {
		log.Printf("PowerMonitor: X728 GPIO 26 LOW failed (non-fatal): %v", err)
	}

	log.Printf("PowerMonitor: X728 shutdown signal complete")
	return nil
}

// OnBoot sets GPIO 12 HIGH to signal the X728 MCU that the Pi has booted.
// If this signal is not sent, the MCU may cut power thinking boot failed.
func (d *X728Driver) OnBoot(ctx context.Context) error {
	log.Printf("PowerMonitor: X728 boot — setting GPIO 12 HIGH (boot-OK signal)")

	if _, err := execWithTimeout(ctx, "gpioset", d.gpioChip, "12=1"); err != nil {
		return fmt.Errorf("X728 boot-OK signal failed: %w", err)
	}

	log.Printf("PowerMonitor: X728 boot-OK signal sent")
	return nil
}
