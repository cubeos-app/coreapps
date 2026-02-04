package handlers

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ============================================================================
// Log Types
// ============================================================================

// LogsResponse represents log output.
// @Description Log entries
type LogsResponse struct {
	Lines []string `json:"lines"`
	Count int      `json:"count" example:"100"`
}

// HardwareLogsResponse represents hardware-specific logs.
// @Description Hardware-specific log entries
type HardwareLogsResponse struct {
	Category string   `json:"category" example:"net"`
	Entries  []string `json:"entries"`
	Count    int      `json:"count" example:"50"`
}

// ============================================================================
// Log Handlers
// ============================================================================

// GetKernelLogs returns kernel logs.
// @Summary Get kernel logs
// @Description Returns kernel ring buffer (dmesg) output
// @Tags Logs
// @Accept json
// @Produce json
// @Param lines query int false "Number of lines" default(100)
// @Param level query string false "Log level filter (emerg, alert, crit, err, warn, notice, info, debug)"
// @Success 200 {object} LogsResponse
// @Failure 500 {object} ErrorResponse
// @Router /logs/kernel [get]
func (h *HALHandler) GetKernelLogs(w http.ResponseWriter, r *http.Request) {
	linesParam := r.URL.Query().Get("lines")
	lines := 100
	if linesParam != "" {
		if n, err := strconv.Atoi(linesParam); err == nil && n > 0 {
			lines = n
		}
	}

	args := []string{"-T"}

	// Add level filter if specified
	if level := r.URL.Query().Get("level"); level != "" {
		args = append(args, "-l", level)
	}

	cmd := exec.Command("dmesg", args...)
	output, err := cmd.Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get kernel logs: "+err.Error())
		return
	}

	allLines := strings.Split(string(output), "\n")

	// Remove empty last line
	if len(allLines) > 0 && allLines[len(allLines)-1] == "" {
		allLines = allLines[:len(allLines)-1]
	}

	// Get last N lines
	start := 0
	if len(allLines) > lines {
		start = len(allLines) - lines
	}
	resultLines := allLines[start:]

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"lines": resultLines,
		"count": len(resultLines),
	})
}

// GetJournalLogs returns systemd journal logs.
// @Summary Get journal logs
// @Description Returns systemd journal entries
// @Tags Logs
// @Accept json
// @Produce json
// @Param lines query int false "Number of lines" default(100)
// @Param unit query string false "Systemd unit filter" example(cubeos-hal)
// @Param since query string false "Time filter" example(1 hour ago)
// @Param priority query int false "Priority level (0-7, where 0=emerg, 7=debug)"
// @Success 200 {object} LogsResponse
// @Failure 500 {object} ErrorResponse
// @Router /logs/journal [get]
func (h *HALHandler) GetJournalLogs(w http.ResponseWriter, r *http.Request) {
	linesParam := r.URL.Query().Get("lines")
	lines := 100
	if linesParam != "" {
		if n, err := strconv.Atoi(linesParam); err == nil && n > 0 {
			lines = n
		}
	}

	journalArgs := []string{"-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso"}

	if unit := r.URL.Query().Get("unit"); unit != "" {
		journalArgs = append(journalArgs, "-u", unit)
	}

	if since := r.URL.Query().Get("since"); since != "" {
		journalArgs = append(journalArgs, "--since", since)
	}

	if priority := r.URL.Query().Get("priority"); priority != "" {
		journalArgs = append(journalArgs, "-p", priority)
	}

	// Use nsenter to access host's journalctl (Alpine doesn't have systemd)
	// HAL runs with pid:host so nsenter -t 1 -m accesses host mount namespace
	args := append([]string{"-t", "1", "-m", "--", "journalctl"}, journalArgs...)
	cmd := exec.Command("nsenter", args...)
	output, err := cmd.Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get journal: "+err.Error())
		return
	}

	logLines := strings.Split(strings.TrimSpace(string(output)), "\n")

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"lines": logLines,
		"count": len(logLines),
	})
}

// GetHardwareLogs returns hardware-specific logs.
// @Summary Get hardware logs
// @Description Returns hardware-specific kernel log entries filtered by category
// @Tags Logs
// @Accept json
// @Produce json
// @Param category query string false "Hardware category" Enums(i2c, gpio, usb, pcie, mmc, net, power, thermal, all) default(all)
// @Success 200 {object} HardwareLogsResponse
// @Failure 500 {object} ErrorResponse
// @Router /logs/hardware [get]
func (h *HALHandler) GetHardwareLogs(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	if category == "" {
		category = "all"
	}

	cmd := exec.Command("dmesg", "-T")
	output, err := cmd.Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get logs: "+err.Error())
		return
	}

	// Category filters
	filters := map[string][]string{
		"i2c":     {"i2c", "I2C"},
		"gpio":    {"gpio", "GPIO", "pinctrl"},
		"usb":     {"usb", "USB", "hub"},
		"pcie":    {"pci", "PCI", "PCIe"},
		"mmc":     {"mmc", "MMC", "sdhci", "SD"},
		"net":     {"eth", "wlan", "wifi", "net", "link"},
		"power":   {"power", "battery", "voltage", "regulator"},
		"thermal": {"thermal", "temperature", "throttl", "overheat"},
	}

	lines := strings.Split(string(output), "\n")
	var entries []string

	if category == "all" {
		// Return last 200 lines for 'all'
		start := 0
		if len(lines) > 200 {
			start = len(lines) - 200
		}
		entries = lines[start:]
	} else {
		patterns := filters[category]
		if patterns == nil {
			errorResponse(w, http.StatusBadRequest, "invalid category: "+category)
			return
		}

		for _, line := range lines {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					entries = append(entries, line)
					break
				}
			}
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"category": category,
		"entries":  entries,
		"count":    len(entries),
	})
}

// GetSupportBundle generates a support bundle ZIP.
// @Summary Download support bundle
// @Description Generates and downloads a ZIP file containing logs and diagnostics
// @Tags Logs
// @Produce application/zip
// @Success 200 {file} binary "ZIP file"
// @Failure 500 {object} ErrorResponse
// @Router /support/bundle.zip [get]
func (h *HALHandler) GetSupportBundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=cubeos-support-bundle.zip")

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	// System information
	h.addCommandOutput(zipWriter, "system-info.txt", "uname", "-a")
	h.addCommandOutput(zipWriter, "hostname.txt", "hostname", "-f")
	h.addCommandOutput(zipWriter, "uptime.txt", "uptime")
	h.addCommandOutput(zipWriter, "free.txt", "free", "-h")
	h.addCommandOutput(zipWriter, "ps.txt", "ps", "auxf")

	// Storage
	h.addCommandOutput(zipWriter, "df.txt", "df", "-h")
	h.addCommandOutput(zipWriter, "lsblk.txt", "lsblk", "-a")
	h.addCommandOutput(zipWriter, "mount.txt", "mount")

	// Network
	h.addCommandOutput(zipWriter, "ip-addr.txt", "ip", "addr")
	h.addCommandOutput(zipWriter, "ip-route.txt", "ip", "route")
	h.addCommandOutput(zipWriter, "ip-link.txt", "ip", "link")
	h.addCommandOutput(zipWriter, "ss.txt", "ss", "-tulpn")
	h.addCommandOutput(zipWriter, "iptables.txt", "iptables", "-L", "-n", "-v")

	// Hardware
	h.addCommandOutput(zipWriter, "lsusb.txt", "lsusb", "-v")
	h.addCommandOutput(zipWriter, "lspci.txt", "lspci", "-v")
	h.addCommandOutput(zipWriter, "i2cdetect.txt", "i2cdetect", "-y", "1")
	h.addCommandOutput(zipWriter, "vcgencmd-throttled.txt", "vcgencmd", "get_throttled")
	h.addCommandOutput(zipWriter, "vcgencmd-temp.txt", "vcgencmd", "measure_temp")
	h.addCommandOutput(zipWriter, "vcgencmd-bootloader.txt", "vcgencmd", "bootloader_version")
	h.addCommandOutput(zipWriter, "cpuinfo.txt", "cat", "/proc/cpuinfo")
	h.addCommandOutput(zipWriter, "meminfo.txt", "cat", "/proc/meminfo")

	// Logs
	h.addCommandOutput(zipWriter, "dmesg.txt", "dmesg", "-T")
	h.addHostCommandOutput(zipWriter, "journalctl.txt", "journalctl", "-n", "2000", "--no-pager")
	h.addHostCommandOutput(zipWriter, "journalctl-errors.txt", "journalctl", "-p", "err", "-n", "500", "--no-pager")

	// Services
	h.addHostCommandOutput(zipWriter, "systemctl-status.txt", "systemctl", "status")
	h.addHostCommandOutput(zipWriter, "systemctl-failed.txt", "systemctl", "--failed")
	h.addHostCommandOutput(zipWriter, "systemctl-list-units.txt", "systemctl", "list-units", "--type=service")

	// Docker
	h.addCommandOutput(zipWriter, "docker-info.txt", "docker", "info")
	h.addCommandOutput(zipWriter, "docker-ps.txt", "docker", "ps", "-a")
	h.addCommandOutput(zipWriter, "docker-images.txt", "docker", "images")
	h.addCommandOutput(zipWriter, "docker-swarm-nodes.txt", "docker", "node", "ls")
	h.addCommandOutput(zipWriter, "docker-swarm-services.txt", "docker", "service", "ls")

	// Config files
	h.addFileToZip(zipWriter, "/boot/firmware/config.txt", "config/boot-config.txt")
	h.addFileToZip(zipWriter, "/boot/config.txt", "config/boot-config-alt.txt")
	h.addFileToZip(zipWriter, "/etc/hostapd/hostapd.conf", "config/hostapd.conf")
	h.addFileToZip(zipWriter, "/etc/dnsmasq.conf", "config/dnsmasq.conf")
	h.addFileToZip(zipWriter, "/etc/tor/torrc", "config/torrc")
	h.addFileToZip(zipWriter, "/etc/netplan/01-netcfg.yaml", "config/netplan.yaml")
	h.addFileToZip(zipWriter, "/var/lib/misc/dnsmasq.leases", "config/dhcp-leases.txt")
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *HALHandler) addCommandOutput(zw *zip.Writer, filename string, cmdName string, args ...string) {
	cmd := exec.Command(cmdName, args...)
	output, err := cmd.CombinedOutput()

	f, err2 := zw.Create(filename)
	if err2 != nil {
		return
	}

	if err != nil {
		f.Write([]byte(fmt.Sprintf("Command failed: %s\nOutput:\n%s", err.Error(), string(output))))
		return
	}

	f.Write(output)
}

// addHostCommandOutput runs a command on the host via nsenter (for journalctl, systemctl, etc.)
func (h *HALHandler) addHostCommandOutput(zw *zip.Writer, filename string, cmdName string, args ...string) {
	nsenterArgs := append([]string{"-t", "1", "-m", "--", cmdName}, args...)
	h.addCommandOutput(zw, filename, "nsenter", nsenterArgs...)
}

func (h *HALHandler) addFileToZip(zw *zip.Writer, srcPath, dstName string) {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		// File doesn't exist, skip
		return
	}
	defer srcFile.Close()

	f, err := zw.Create(dstName)
	if err != nil {
		return
	}

	io.Copy(f, srcFile)
}
