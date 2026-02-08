package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// Iridium Types
// ============================================================================

// IridiumDevice represents an Iridium satellite modem.
// @Description Iridium satellite modem information
type IridiumDevice struct {
	Port       string `json:"port" example:"/dev/ttyUSB0"`
	Name       string `json:"name" example:"RockBLOCK 9603"`
	IMEI       string `json:"imei,omitempty" example:"300234010123456"`
	Model      string `json:"model,omitempty" example:"9603"`
	Connected  bool   `json:"connected" example:"true"`
	Registered bool   `json:"registered" example:"true"`
}

// IridiumStatus represents Iridium modem status.
// @Description Iridium satellite modem status
type IridiumStatus struct {
	Available     bool   `json:"available" example:"true"`
	Connected     bool   `json:"connected" example:"true"`
	SignalQuality int    `json:"signal_quality" example:"4"`
	Registered    bool   `json:"registered" example:"true"`
	NetworkTime   string `json:"network_time,omitempty"`
	MOQueue       int    `json:"mo_queue" example:"0"`
	MTQueue       int    `json:"mt_queue" example:"1"`
	LastContact   string `json:"last_contact,omitempty"`
	IMEI          string `json:"imei,omitempty"`
}

// IridiumSignal represents Iridium signal info.
// @Description Iridium satellite signal strength
type IridiumSignal struct {
	Quality int    `json:"quality" example:"4"`
	Bars    int    `json:"bars" example:"4"`
	Status  string `json:"status" example:"Good"`
}

// IridiumSendRequest represents an SBD message to send.
// @Description Iridium SBD message parameters
type IridiumSendRequest struct {
	Message string `json:"message" example:"Test message"`
	Binary  bool   `json:"binary,omitempty" example:"false"`
	Data    string `json:"data,omitempty"` // Base64 for binary
}

// IridiumMessage represents a received SBD message.
// @Description Received Iridium SBD message
type IridiumMessage struct {
	MTMSN     int    `json:"mtmsn" example:"1"`
	Data      string `json:"data" example:"Hello from satellite"`
	Binary    bool   `json:"binary" example:"false"`
	Timestamp string `json:"timestamp" example:"2026-02-03T16:30:00Z"`
	Length    int    `json:"length" example:"20"`
}

// ============================================================================
// Iridium Handlers
// ============================================================================

// GetIridiumDevices lists Iridium devices.
// @Summary List Iridium devices
// @Description Returns list of connected Iridium satellite modems
// @Tags Iridium
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /hal/iridium/devices [get]
func (h *HALHandler) GetIridiumDevices(w http.ResponseWriter, r *http.Request) {
	devices := h.scanIridiumDevices(r.Context())
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"count":   len(devices),
		"devices": devices,
	})
}

// GetIridiumStatus returns Iridium status.
// @Summary Get Iridium status
// @Description Returns Iridium satellite modem status
// @Tags Iridium
// @Accept json
// @Produce json
// @Param port query string false "Serial port" default(/dev/ttyUSB0)
// @Success 200 {object} IridiumStatus
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /hal/iridium/status [get]
func (h *HALHandler) GetIridiumStatus(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	if port == "" {
		port = "/dev/ttyUSB0"
	}

	// HF05-01: Validate serial port path
	if err := validateSerialPort(port); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	status := IridiumStatus{
		Available: false,
	}

	// Check if port exists
	if _, err := os.Stat(port); err != nil {
		jsonResponse(w, http.StatusOK, status)
		return
	}

	status.Available = true

	// HF05-11: Configure serial port with timeout
	if _, err := execWithTimeout(ctx, "stty", "-F", port, "19200", "raw", "-echo"); err != nil {
		log.Printf("iridium: stty failed for %s: %v", port, err)
	}

	// Try to communicate with modem — send AT command
	response := h.sendATCommand(port, "AT", 2)
	if strings.Contains(response, "OK") {
		status.Connected = true
	}

	// Get IMEI
	response = h.sendATCommand(port, "AT+CGSN", 2)
	if !strings.Contains(response, "ERROR") {
		lines := strings.Split(response, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if len(line) == 15 && strings.HasPrefix(line, "3") {
				status.IMEI = line
				break
			}
		}
	}

	// Get signal quality (0-5)
	response = h.sendATCommand(port, "AT+CSQ", 2)
	if strings.Contains(response, "+CSQ:") {
		if idx := strings.Index(response, "+CSQ:"); idx != -1 {
			sigStr := strings.TrimSpace(response[idx+5:])
			if sig, err := strconv.Atoi(strings.Split(sigStr, "\n")[0]); err == nil {
				status.SignalQuality = sig
			}
		}
	}

	// Check registration
	response = h.sendATCommand(port, "AT+SBDREG?", 2)
	if strings.Contains(response, "SBDREG:2") {
		status.Registered = true
	}

	// Get message queue status
	response = h.sendATCommand(port, "AT+SBDSX", 2)
	if strings.Contains(response, "+SBDSX:") {
		// Format: +SBDSX: MO flag, MOMSN, MT flag, MTMSN, RA flag, msg waiting
		if idx := strings.Index(response, "+SBDSX:"); idx != -1 {
			parts := strings.Split(response[idx+7:], ",")
			if len(parts) >= 6 {
				// MT queue is in parts[5]
				mtWaiting := strings.TrimSpace(parts[5])
				status.MTQueue, _ = strconv.Atoi(strings.Split(mtWaiting, "\n")[0])
			}
		}
	}

	status.LastContact = time.Now().UTC().Format(time.RFC3339)

	jsonResponse(w, http.StatusOK, status)
}

// GetIridiumSignal returns Iridium signal.
// @Summary Get Iridium signal
// @Description Returns Iridium satellite signal quality (0-5)
// @Tags Iridium
// @Accept json
// @Produce json
// @Param port query string false "Serial port" default(/dev/ttyUSB0)
// @Success 200 {object} IridiumSignal
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /hal/iridium/signal [get]
func (h *HALHandler) GetIridiumSignal(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	if port == "" {
		port = "/dev/ttyUSB0"
	}

	// HF05-01: Validate serial port path
	if err := validateSerialPort(port); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	signal := IridiumSignal{
		Quality: 0,
		Bars:    0,
		Status:  "No Signal",
	}

	// HF05-11: Configure serial port with timeout
	if _, err := execWithTimeout(ctx, "stty", "-F", port, "19200", "raw", "-echo"); err != nil {
		log.Printf("iridium: stty failed for %s: %v", port, err)
	}

	// Get signal quality
	response := h.sendATCommand(port, "AT+CSQ", 2)
	if strings.Contains(response, "+CSQ:") {
		if idx := strings.Index(response, "+CSQ:"); idx != -1 {
			sigStr := strings.TrimSpace(response[idx+5:])
			if sig, err := strconv.Atoi(strings.Split(sigStr, "\n")[0]); err == nil {
				signal.Quality = sig
				signal.Bars = sig // 0-5 maps directly to bars

				switch sig {
				case 0:
					signal.Status = "No Signal"
				case 1:
					signal.Status = "Poor"
				case 2:
					signal.Status = "Fair"
				case 3:
					signal.Status = "Good"
				case 4:
					signal.Status = "Very Good"
				case 5:
					signal.Status = "Excellent"
				}
			}
		}
	}

	jsonResponse(w, http.StatusOK, signal)
}

// SendIridiumMessage sends an SBD message.
// @Summary Send Iridium SBD message
// @Description Sends a Short Burst Data message via Iridium satellite
// @Tags Iridium
// @Accept json
// @Produce json
// @Param port query string false "Serial port" default(/dev/ttyUSB0)
// @Param request body IridiumSendRequest true "Message parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /hal/iridium/send [post]
func (h *HALHandler) SendIridiumMessage(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	if port == "" {
		port = "/dev/ttyUSB0"
	}

	// HF05-01: Validate serial port path
	if err := validateSerialPort(port); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// HF05-09: Apply body limit
	r = limitBody(r, 1<<20)

	var req IridiumSendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Message == "" && req.Data == "" {
		errorResponse(w, http.StatusBadRequest, "message or data required")
		return
	}

	// HF05-02: Validate Iridium message — prevents AT command injection
	// The message is concatenated into "AT+SBDWT=<msg>" and sent over serial.
	// CR/LF in the message would terminate the AT command early and allow
	// injecting arbitrary AT commands (e.g., AT+CFUN=0 to disable radio).
	if req.Message != "" {
		if err := validateIridiumMessage(req.Message); err != nil {
			errorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	ctx := r.Context()

	// HF05-11: Configure serial port with timeout
	if _, err := execWithTimeout(ctx, "stty", "-F", port, "19200", "raw", "-echo"); err != nil {
		log.Printf("iridium: stty failed for %s: %v", port, err)
	}

	// Clear MO buffer
	response := h.sendATCommand(port, "AT+SBDD0", 2)
	if strings.Contains(response, "ERROR") {
		errorResponse(w, http.StatusInternalServerError, "failed to clear MO buffer")
		return
	}

	// Write message to MO buffer
	message := req.Message
	if req.Binary && req.Data != "" {
		// For binary, use AT+SBDWB
		errorResponse(w, http.StatusBadRequest, "binary messages not yet implemented")
		return
	}

	// Write text message — message is validated (no CR/LF/null)
	cmd := fmt.Sprintf("AT+SBDWT=%s", message)
	response = h.sendATCommand(port, cmd, 5)
	if !strings.Contains(response, "OK") {
		errorResponse(w, http.StatusInternalServerError, "failed to write message to modem")
		return
	}

	// Initiate SBD session (long timeout for satellite link)
	response = h.sendATCommand(port, "AT+SBDIX", 60)
	if !strings.Contains(response, "+SBDIX:") {
		errorResponse(w, http.StatusInternalServerError, "SBD session failed")
		return
	}

	// Parse result
	// +SBDIX: MO status, MOMSN, MT status, MTMSN, MT length, MT queued
	if idx := strings.Index(response, "+SBDIX:"); idx != -1 {
		parts := strings.Split(response[idx+7:], ",")
		if len(parts) >= 1 {
			moStatus, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
			if moStatus <= 4 {
				successResponse(w, fmt.Sprintf("message sent successfully (status: %d)", moStatus))
				return
			} else {
				errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("send failed with status: %d", moStatus))
				return
			}
		}
	}

	errorResponse(w, http.StatusInternalServerError, "unexpected modem response")
}

// ReceiveIridiumMessage receives SBD messages.
// @Summary Receive Iridium SBD messages
// @Description Checks for and receives pending SBD messages from Iridium
// @Tags Iridium
// @Accept json
// @Produce json
// @Param port query string false "Serial port" default(/dev/ttyUSB0)
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /hal/iridium/receive [get]
func (h *HALHandler) ReceiveIridiumMessage(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	if port == "" {
		port = "/dev/ttyUSB0"
	}

	// HF05-01: Validate serial port path
	if err := validateSerialPort(port); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()

	// HF05-11: Configure serial port with timeout
	if _, err := execWithTimeout(ctx, "stty", "-F", port, "19200", "raw", "-echo"); err != nil {
		log.Printf("iridium: stty failed for %s: %v", port, err)
	}

	var messages []IridiumMessage

	// Check for MT message
	response := h.sendATCommand(port, "AT+SBDRT", 5)
	if strings.Contains(response, "+SBDRT:") {
		if idx := strings.Index(response, "+SBDRT:"); idx != -1 {
			// Message follows the +SBDRT: line
			msgStart := idx + 8
			lines := strings.Split(response[msgStart:], "\n")
			if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
				msg := IridiumMessage{
					Data:      strings.TrimSpace(lines[0]),
					Binary:    false,
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Length:    len(strings.TrimSpace(lines[0])),
				}
				messages = append(messages, msg)
			}
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"count":    len(messages),
		"messages": messages,
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *HALHandler) scanIridiumDevices(ctx context.Context) []IridiumDevice {
	var devices []IridiumDevice

	// Check common serial ports
	ports := []string{
		"/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2",
	}

	for _, port := range ports {
		if _, err := os.Stat(port); err == nil {
			// HF05-11: Configure port with timeout
			if _, err := execWithTimeout(ctx, "stty", "-F", port, "19200", "raw", "-echo"); err != nil {
				continue
			}

			// Try AT command
			response := h.sendATCommand(port, "AT", 2)
			if strings.Contains(response, "OK") {
				device := IridiumDevice{
					Port:      port,
					Name:      "Iridium Modem",
					Connected: true,
				}

				// Get IMEI
				response = h.sendATCommand(port, "AT+CGSN", 2)
				if !strings.Contains(response, "ERROR") {
					lines := strings.Split(response, "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if len(line) == 15 && strings.HasPrefix(line, "3") {
							device.IMEI = line
							break
						}
					}
				}

				// Get model
				response = h.sendATCommand(port, "AT+CGMM", 2)
				if !strings.Contains(response, "ERROR") {
					lines := strings.Split(response, "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line != "" && line != "OK" && !strings.HasPrefix(line, "AT") {
							device.Model = line
							if strings.Contains(line, "9603") {
								device.Name = "RockBLOCK 9603"
							}
							break
						}
					}
				}

				// Check registration
				response = h.sendATCommand(port, "AT+SBDREG?", 2)
				if strings.Contains(response, "SBDREG:2") {
					device.Registered = true
				}

				devices = append(devices, device)
			}
		}
	}

	return devices
}

func (h *HALHandler) sendATCommand(port string, command string, timeout int) string {
	// Simple AT command sender via direct serial I/O
	// In production, consider a proper serial library

	// Write command
	f, err := os.OpenFile(port, os.O_RDWR, 0)
	if err != nil {
		return ""
	}
	defer f.Close()

	// Send command with CR
	if _, err := f.WriteString(command + "\r"); err != nil {
		return ""
	}

	// Read response with timeout
	buf := make([]byte, 1024)
	f.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	n, err := f.Read(buf)
	if err != nil {
		return ""
	}

	return string(buf[:n])
}

// SendIridiumSBD is a stub — real implementation is SendIridiumMessage.
// Kept for backward compatibility; routes.go now points to SendIridiumMessage.
func (h *HALHandler) SendIridiumSBD(w http.ResponseWriter, r *http.Request) {
	h.SendIridiumMessage(w, r)
}

// GetIridiumMessages retrieves Iridium messages.
// Delegates to ReceiveIridiumMessage for the real implementation.
func (h *HALHandler) GetIridiumMessages(w http.ResponseWriter, r *http.Request) {
	h.ReceiveIridiumMessage(w, r)
}

// CheckIridiumMailbox checks the Iridium mailbox.
func (h *HALHandler) CheckIridiumMailbox(w http.ResponseWriter, r *http.Request) {
	errorResponse(w, http.StatusNotImplemented, "Iridium mailbox check not yet implemented")
}
