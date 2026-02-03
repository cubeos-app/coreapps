package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
)

// ============================================================================
// Audio Types
// ============================================================================

// AudioDevice represents an audio device.
// @Description Audio device information
type AudioDevice struct {
	Card        int    `json:"card" example:"0"`
	Device      int    `json:"device" example:"0"`
	Name        string `json:"name" example:"bcm2835 Headphones"`
	Type        string `json:"type" example:"playback"`
	Description string `json:"description,omitempty"`
	State       string `json:"state,omitempty" example:"RUNNING"`
}

// AudioDevicesResponse represents audio devices list.
// @Description List of audio devices
type AudioDevicesResponse struct {
	Playback []AudioDevice `json:"playback"`
	Capture  []AudioDevice `json:"capture"`
}

// VolumeInfo represents volume information.
// @Description Audio volume information
type VolumeInfo struct {
	Control string `json:"control" example:"Master"`
	Volume  int    `json:"volume" example:"75"`
	Muted   bool   `json:"muted" example:"false"`
	Min     int    `json:"min" example:"0"`
	Max     int    `json:"max" example:"100"`
}

// VolumeRequest represents volume set request.
// @Description Volume set parameters
type VolumeRequest struct {
	Volume  int    `json:"volume" example:"75"`
	Control string `json:"control,omitempty" example:"Master"`
	Card    int    `json:"card,omitempty" example:"0"`
}

// MuteRequest represents mute request.
// @Description Mute parameters
type MuteRequest struct {
	Muted   bool   `json:"muted" example:"true"`
	Control string `json:"control,omitempty" example:"Master"`
	Card    int    `json:"card,omitempty" example:"0"`
}

// ============================================================================
// Audio Device Handlers
// ============================================================================

// GetAudioDevices lists audio devices.
// @Summary List audio devices
// @Description Returns list of ALSA audio devices
// @Tags Audio
// @Accept json
// @Produce json
// @Success 200 {object} AudioDevicesResponse
// @Failure 500 {object} ErrorResponse
// @Router /audio/devices [get]
func (h *HALHandler) GetAudioDevices(w http.ResponseWriter, r *http.Request) {
	response := AudioDevicesResponse{
		Playback: h.getAudioDevices("playback"),
		Capture:  h.getAudioDevices("capture"),
	}

	jsonResponse(w, http.StatusOK, response)
}

// GetPlaybackDevices lists playback devices.
// @Summary List playback devices
// @Description Returns list of audio playback devices
// @Tags Audio
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /audio/playback [get]
func (h *HALHandler) GetPlaybackDevices(w http.ResponseWriter, r *http.Request) {
	devices := h.getAudioDevices("playback")
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"count":   len(devices),
		"devices": devices,
	})
}

// GetCaptureDevices lists capture devices.
// @Summary List capture devices
// @Description Returns list of audio capture (microphone) devices
// @Tags Audio
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /audio/capture [get]
func (h *HALHandler) GetCaptureDevices(w http.ResponseWriter, r *http.Request) {
	devices := h.getAudioDevices("capture")
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"count":   len(devices),
		"devices": devices,
	})
}

// ============================================================================
// Volume Control Handlers
// ============================================================================

// GetVolume returns current volume.
// @Summary Get volume
// @Description Returns current volume level
// @Tags Audio
// @Accept json
// @Produce json
// @Param control query string false "Mixer control" default(Master)
// @Param card query int false "Sound card" default(0)
// @Success 200 {object} VolumeInfo
// @Failure 500 {object} ErrorResponse
// @Router /audio/volume [get]
func (h *HALHandler) GetVolume(w http.ResponseWriter, r *http.Request) {
	control := r.URL.Query().Get("control")
	if control == "" {
		control = "Master"
	}

	card := 0
	if cardParam := r.URL.Query().Get("card"); cardParam != "" {
		card, _ = strconv.Atoi(cardParam)
	}

	info := h.getVolumeInfo(card, control)
	jsonResponse(w, http.StatusOK, info)
}

// SetVolume sets volume level.
// @Summary Set volume
// @Description Sets audio volume level
// @Tags Audio
// @Accept json
// @Produce json
// @Param request body VolumeRequest true "Volume parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /audio/volume [post]
func (h *HALHandler) SetVolume(w http.ResponseWriter, r *http.Request) {
	var req VolumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Volume < 0 || req.Volume > 100 {
		errorResponse(w, http.StatusBadRequest, "volume must be 0-100")
		return
	}

	control := req.Control
	if control == "" {
		control = "Master"
	}

	// Use amixer to set volume
	cardArg := fmt.Sprintf("-c%d", req.Card)
	volumeArg := fmt.Sprintf("%d%%", req.Volume)

	cmd := exec.Command("amixer", cardArg, "sset", control, volumeArg)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to set volume: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("volume set to %d%%", req.Volume))
}

// SetMute sets mute state.
// @Summary Set mute
// @Description Sets audio mute state
// @Tags Audio
// @Accept json
// @Produce json
// @Param request body MuteRequest true "Mute parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /audio/mute [post]
func (h *HALHandler) SetMute(w http.ResponseWriter, r *http.Request) {
	var req MuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	control := req.Control
	if control == "" {
		control = "Master"
	}

	muteArg := "unmute"
	if req.Muted {
		muteArg = "mute"
	}

	cardArg := fmt.Sprintf("-c%d", req.Card)

	cmd := exec.Command("amixer", cardArg, "sset", control, muteArg)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to set mute: %s - %s", err, string(output)))
		return
	}

	state := "unmuted"
	if req.Muted {
		state = "muted"
	}
	successResponse(w, fmt.Sprintf("audio %s", state))
}

// ============================================================================
// Audio Test Handlers
// ============================================================================

// PlayTestTone plays a test tone.
// @Summary Play test tone
// @Description Plays a test tone on the specified audio device
// @Tags Audio
// @Accept json
// @Produce json
// @Param card query int false "Sound card" default(0)
// @Param device query int false "Device" default(0)
// @Param duration query int false "Duration in seconds" default(2)
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /audio/test [post]
func (h *HALHandler) PlayTestTone(w http.ResponseWriter, r *http.Request) {
	card := 0
	if cardParam := r.URL.Query().Get("card"); cardParam != "" {
		card, _ = strconv.Atoi(cardParam)
	}

	device := 0
	if deviceParam := r.URL.Query().Get("device"); deviceParam != "" {
		device, _ = strconv.Atoi(deviceParam)
	}

	duration := 2
	if durParam := r.URL.Query().Get("duration"); durParam != "" {
		duration, _ = strconv.Atoi(durParam)
	}

	// Use speaker-test
	deviceArg := fmt.Sprintf("plughw:%d,%d", card, device)
	durationArg := strconv.Itoa(duration)

	cmd := exec.Command("speaker-test", "-D", deviceArg, "-t", "sine", "-f", "440", "-l", "1", "-p", durationArg)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("test tone failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "test tone played")
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *HALHandler) getAudioDevices(deviceType string) []AudioDevice {
	var devices []AudioDevice

	// Use aplay -l for playback, arecord -l for capture
	var cmd *exec.Cmd
	if deviceType == "playback" {
		cmd = exec.Command("aplay", "-l")
	} else {
		cmd = exec.Command("arecord", "-l")
	}

	output, err := cmd.Output()
	if err != nil {
		return devices
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Parse lines like: "card 0: Headphones [bcm2835 Headphones], device 0: bcm2835 Headphones [bcm2835 Headphones]"
		if strings.HasPrefix(line, "card ") {
			device := AudioDevice{Type: deviceType}

			// Extract card number
			if idx := strings.Index(line, "card "); idx != -1 {
				cardStr := line[idx+5:]
				if colonIdx := strings.Index(cardStr, ":"); colonIdx != -1 {
					device.Card, _ = strconv.Atoi(cardStr[:colonIdx])
				}
			}

			// Extract device number
			if idx := strings.Index(line, "device "); idx != -1 {
				devStr := line[idx+7:]
				if colonIdx := strings.Index(devStr, ":"); colonIdx != -1 {
					device.Device, _ = strconv.Atoi(devStr[:colonIdx])
				}
			}

			// Extract name from brackets
			if idx := strings.Index(line, "["); idx != -1 {
				if endIdx := strings.Index(line[idx:], "]"); endIdx != -1 {
					device.Name = line[idx+1 : idx+endIdx]
				}
			}

			// Extract description after colon
			if idx := strings.Index(line, ": "); idx != -1 {
				parts := strings.Split(line[idx+2:], ",")
				if len(parts) > 0 {
					// Get just the name part
					namePart := strings.TrimSpace(parts[0])
					if bracketIdx := strings.Index(namePart, " ["); bracketIdx != -1 {
						device.Description = namePart[:bracketIdx]
					} else {
						device.Description = namePart
					}
				}
			}

			if device.Name != "" {
				devices = append(devices, device)
			}
		}
	}

	return devices
}

func (h *HALHandler) getVolumeInfo(card int, control string) VolumeInfo {
	info := VolumeInfo{
		Control: control,
		Min:     0,
		Max:     100,
	}

	cardArg := fmt.Sprintf("-c%d", card)
	cmd := exec.Command("amixer", cardArg, "sget", control)
	output, err := cmd.Output()
	if err != nil {
		return info
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Parse lines like: "  Mono: Playback 400 [61%] [on]"
		// or: "  Front Left: Playback 400 [61%] [on]"
		if strings.Contains(line, "Playback") || strings.Contains(line, "Capture") {
			// Extract percentage
			if idx := strings.Index(line, "["); idx != -1 {
				percentStr := line[idx+1:]
				if endIdx := strings.Index(percentStr, "%"); endIdx != -1 {
					info.Volume, _ = strconv.Atoi(percentStr[:endIdx])
				}
			}

			// Check mute status
			info.Muted = strings.Contains(line, "[off]")
			break
		}
	}

	return info
}
