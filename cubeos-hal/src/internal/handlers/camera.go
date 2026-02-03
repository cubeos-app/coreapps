package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// Camera Types
// ============================================================================

// CameraDevice represents a camera device.
// @Description Camera device information
type CameraDevice struct {
	Index       int      `json:"index" example:"0"`
	Name        string   `json:"name" example:"Pi Camera Module 3"`
	Path        string   `json:"path" example:"/dev/video0"`
	Driver      string   `json:"driver,omitempty" example:"bcm2835-v4l2"`
	Type        string   `json:"type" example:"csi"`
	Resolutions []string `json:"resolutions,omitempty"`
	Formats     []string `json:"formats,omitempty"`
	Available   bool     `json:"available" example:"true"`
}

// CameraDevicesResponse represents camera list.
// @Description List of camera devices
type CameraDevicesResponse struct {
	Count   int            `json:"count" example:"2"`
	Cameras []CameraDevice `json:"cameras"`
}

// CaptureRequest represents image capture request.
// @Description Camera capture parameters
type CaptureRequest struct {
	Width    int    `json:"width,omitempty" example:"1920"`
	Height   int    `json:"height,omitempty" example:"1080"`
	Quality  int    `json:"quality,omitempty" example:"85"`
	Format   string `json:"format,omitempty" example:"jpeg"`
	Camera   int    `json:"camera,omitempty" example:"0"`
	Rotation int    `json:"rotation,omitempty" example:"0"`
	HFlip    bool   `json:"hflip,omitempty" example:"false"`
	VFlip    bool   `json:"vflip,omitempty" example:"false"`
}

// CaptureResponse represents capture result.
// @Description Camera capture result
type CaptureResponse struct {
	Success   bool   `json:"success" example:"true"`
	Path      string `json:"path,omitempty" example:"/tmp/capture.jpg"`
	Size      int64  `json:"size,omitempty" example:"245678"`
	Width     int    `json:"width,omitempty" example:"1920"`
	Height    int    `json:"height,omitempty" example:"1080"`
	Timestamp string `json:"timestamp" example:"2026-02-03T16:30:00Z"`
	Base64    string `json:"base64,omitempty"`
}

// StreamInfo represents stream information.
// @Description Camera stream information
type StreamInfo struct {
	Active bool   `json:"active" example:"true"`
	URL    string `json:"url,omitempty" example:"http://cubeos.cube:8080/stream"`
	Camera int    `json:"camera" example:"0"`
	Width  int    `json:"width" example:"1280"`
	Height int    `json:"height" example:"720"`
	FPS    int    `json:"fps" example:"30"`
	Format string `json:"format" example:"mjpeg"`
}

// ============================================================================
// Camera Handlers
// ============================================================================

// GetCameras lists available cameras.
// @Summary List cameras
// @Description Returns list of available camera devices (Pi Camera + USB webcams)
// @Tags Camera
// @Accept json
// @Produce json
// @Success 200 {object} CameraDevicesResponse
// @Failure 500 {object} ErrorResponse
// @Router /camera/devices [get]
func (h *HALHandler) GetCameras(w http.ResponseWriter, r *http.Request) {
	cameras := h.scanCameras()
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"count":   len(cameras),
		"cameras": cameras,
	})
}

// GetCameraInfo returns info about a specific camera.
// @Summary Get camera info
// @Description Returns detailed information about a specific camera
// @Tags Camera
// @Accept json
// @Produce json
// @Param index query int false "Camera index" default(0)
// @Success 200 {object} CameraDevice
// @Failure 404 {object} ErrorResponse "Camera not found"
// @Failure 500 {object} ErrorResponse
// @Router /camera/info [get]
func (h *HALHandler) GetCameraInfo(w http.ResponseWriter, r *http.Request) {
	index := 0
	if idx := r.URL.Query().Get("index"); idx != "" {
		index, _ = strconv.Atoi(idx)
	}

	cameras := h.scanCameras()
	if index >= len(cameras) {
		errorResponse(w, http.StatusNotFound, "camera not found")
		return
	}

	jsonResponse(w, http.StatusOK, cameras[index])
}

// CaptureImage captures a still image.
// @Summary Capture image
// @Description Captures a still image from the camera
// @Tags Camera
// @Accept json
// @Produce json
// @Param request body CaptureRequest false "Capture parameters"
// @Success 200 {object} CaptureResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /camera/capture [post]
func (h *HALHandler) CaptureImage(w http.ResponseWriter, r *http.Request) {
	var req CaptureRequest
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}

	// Set defaults
	if req.Width == 0 {
		req.Width = 1920
	}
	if req.Height == 0 {
		req.Height = 1080
	}
	if req.Quality == 0 {
		req.Quality = 85
	}
	if req.Format == "" {
		req.Format = "jpeg"
	}

	// Generate output path
	timestamp := time.Now().Format("20060102-150405")
	outputPath := fmt.Sprintf("/tmp/capture_%s.jpg", timestamp)

	// Try libcamera-still first (Pi Camera)
	args := []string{
		"-o", outputPath,
		"--width", strconv.Itoa(req.Width),
		"--height", strconv.Itoa(req.Height),
		"-q", strconv.Itoa(req.Quality),
		"-n",      // No preview
		"-t", "1", // 1ms timeout (immediate capture)
	}

	if req.Rotation != 0 {
		args = append(args, "--rotation", strconv.Itoa(req.Rotation))
	}
	if req.HFlip {
		args = append(args, "--hflip")
	}
	if req.VFlip {
		args = append(args, "--vflip")
	}
	if req.Camera > 0 {
		args = append(args, "--camera", strconv.Itoa(req.Camera))
	}

	cmd := exec.Command("libcamera-still", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Try fswebcam for USB cameras
		args = []string{
			"-r", fmt.Sprintf("%dx%d", req.Width, req.Height),
			"--jpeg", strconv.Itoa(req.Quality),
			"-d", fmt.Sprintf("/dev/video%d", req.Camera),
			"--no-banner",
			outputPath,
		}
		cmd = exec.Command("fswebcam", args...)
		if output2, err2 := cmd.CombinedOutput(); err2 != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("capture failed: %s / %s", string(output), string(output2)))
			return
		}
	}

	// Get file info
	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to read captured image: "+err.Error())
		return
	}

	response := CaptureResponse{
		Success:   true,
		Path:      outputPath,
		Size:      fileInfo.Size(),
		Width:     req.Width,
		Height:    req.Height,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Include base64 if image is small enough
	if fileInfo.Size() < 2*1024*1024 { // < 2MB
		if data, err := os.ReadFile(outputPath); err == nil {
			response.Base64 = base64.StdEncoding.EncodeToString(data)
		}
	}

	jsonResponse(w, http.StatusOK, response)
}

// GetCapturedImage serves a captured image.
// @Summary Get captured image
// @Description Returns a previously captured image file
// @Tags Camera
// @Produce image/jpeg
// @Param path query string true "Image path"
// @Success 200 {file} binary "JPEG image"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /camera/image [get]
func (h *HALHandler) GetCapturedImage(w http.ResponseWriter, r *http.Request) {
	imagePath := r.URL.Query().Get("path")
	if imagePath == "" {
		errorResponse(w, http.StatusBadRequest, "path required")
		return
	}

	// Security: only allow files from /tmp
	if !strings.HasPrefix(imagePath, "/tmp/") {
		errorResponse(w, http.StatusBadRequest, "invalid path")
		return
	}

	data, err := os.ReadFile(imagePath)
	if err != nil {
		errorResponse(w, http.StatusNotFound, "image not found")
		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

// GetStreamInfo returns stream information.
// @Summary Get stream info
// @Description Returns camera stream status and URL
// @Tags Camera
// @Accept json
// @Produce json
// @Success 200 {object} StreamInfo
// @Failure 500 {object} ErrorResponse
// @Router /camera/stream/status [get]
func (h *HALHandler) GetStreamInfo(w http.ResponseWriter, r *http.Request) {
	// Check if mjpg-streamer or similar is running
	info := StreamInfo{
		Active: false,
	}

	// Check for common streaming services
	cmd := exec.Command("pgrep", "-f", "mjpg_streamer")
	if err := cmd.Run(); err == nil {
		info.Active = true
		info.URL = "http://cubeos.cube:8080/?action=stream"
		info.Format = "mjpeg"
		info.FPS = 30
	}

	cmd = exec.Command("pgrep", "-f", "libcamera-vid")
	if err := cmd.Run(); err == nil {
		info.Active = true
	}

	jsonResponse(w, http.StatusOK, info)
}

// StartStream starts camera streaming.
// @Summary Start stream
// @Description Starts MJPEG camera streaming
// @Tags Camera
// @Accept json
// @Produce json
// @Param camera query int false "Camera index" default(0)
// @Param width query int false "Stream width" default(1280)
// @Param height query int false "Stream height" default(720)
// @Param fps query int false "Frames per second" default(30)
// @Success 200 {object} StreamInfo
// @Failure 500 {object} ErrorResponse
// @Router /camera/stream/start [post]
func (h *HALHandler) StartStream(w http.ResponseWriter, r *http.Request) {
	camera := 0
	if idx := r.URL.Query().Get("camera"); idx != "" {
		camera, _ = strconv.Atoi(idx)
	}

	width := 1280
	if w := r.URL.Query().Get("width"); w != "" {
		width, _ = strconv.Atoi(w)
	}

	height := 720
	if h := r.URL.Query().Get("height"); h != "" {
		height, _ = strconv.Atoi(h)
	}

	fps := 30
	if f := r.URL.Query().Get("fps"); f != "" {
		fps, _ = strconv.Atoi(f)
	}

	// Try mjpg-streamer
	cmd := exec.Command("mjpg_streamer",
		"-i", fmt.Sprintf("input_uvc.so -d /dev/video%d -r %dx%d -f %d", camera, width, height, fps),
		"-o", "output_http.so -p 8080 -w /usr/share/mjpg-streamer/www",
	)

	if err := cmd.Start(); err != nil {
		// Try libcamera approach
		cmd = exec.Command("libcamera-vid",
			"-t", "0",
			"--width", strconv.Itoa(width),
			"--height", strconv.Itoa(height),
			"--framerate", strconv.Itoa(fps),
			"--codec", "mjpeg",
			"-o", "tcp://0.0.0.0:8080",
		)
		if err := cmd.Start(); err != nil {
			errorResponse(w, http.StatusInternalServerError, "failed to start stream: "+err.Error())
			return
		}
	}

	info := StreamInfo{
		Active: true,
		URL:    "http://cubeos.cube:8080/?action=stream",
		Camera: camera,
		Width:  width,
		Height: height,
		FPS:    fps,
		Format: "mjpeg",
	}

	jsonResponse(w, http.StatusOK, info)
}

// StopStream stops camera streaming.
// @Summary Stop stream
// @Description Stops camera streaming
// @Tags Camera
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /camera/stream/stop [post]
func (h *HALHandler) StopStream(w http.ResponseWriter, r *http.Request) {
	// Kill streaming processes
	exec.Command("pkill", "-f", "mjpg_streamer").Run()
	exec.Command("pkill", "-f", "libcamera-vid").Run()

	successResponse(w, "stream stopped")
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *HALHandler) scanCameras() []CameraDevice {
	var cameras []CameraDevice

	// Check for Pi Camera using libcamera
	cmd := exec.Command("libcamera-hello", "--list-cameras")
	if output, err := cmd.Output(); err == nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "Available cameras") {
			// Parse camera info
			lines := strings.Split(outputStr, "\n")
			for i, line := range lines {
				if strings.Contains(line, ": ") && strings.Contains(line, "imx") {
					camera := CameraDevice{
						Index:     len(cameras),
						Type:      "csi",
						Driver:    "libcamera",
						Available: true,
					}

					// Extract name
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						camera.Name = strings.TrimSpace(parts[1])
					}

					// Get resolutions from next lines
					for j := i + 1; j < len(lines) && j < i+5; j++ {
						if strings.Contains(lines[j], "x") && strings.Contains(lines[j], "/") {
							res := strings.TrimSpace(lines[j])
							camera.Resolutions = append(camera.Resolutions, res)
						}
					}

					cameras = append(cameras, camera)
				}
			}
		}
	}

	// Check for V4L2 devices (USB webcams)
	entries, _ := filepath.Glob("/dev/video*")
	for _, entry := range entries {
		// Skip odd-numbered devices (usually metadata)
		devNum := strings.TrimPrefix(entry, "/dev/video")
		num, _ := strconv.Atoi(devNum)
		if num%2 != 0 {
			continue
		}

		// Get device info using v4l2-ctl
		cmd := exec.Command("v4l2-ctl", "--device", entry, "--info")
		if output, err := cmd.Output(); err == nil {
			camera := CameraDevice{
				Index:     len(cameras),
				Path:      entry,
				Type:      "usb",
				Available: true,
			}

			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "Card type") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						camera.Name = strings.TrimSpace(parts[1])
					}
				}
				if strings.Contains(line, "Driver name") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						camera.Driver = strings.TrimSpace(parts[1])
					}
				}
			}

			// Get supported formats
			cmd = exec.Command("v4l2-ctl", "--device", entry, "--list-formats-ext")
			if fmtOutput, err := cmd.Output(); err == nil {
				fmtLines := strings.Split(string(fmtOutput), "\n")
				for _, line := range fmtLines {
					if strings.Contains(line, "Size:") {
						parts := strings.Split(line, "Size:")
						if len(parts) == 2 {
							res := strings.TrimSpace(parts[1])
							camera.Resolutions = append(camera.Resolutions, res)
						}
					}
				}
			}

			if camera.Name != "" {
				cameras = append(cameras, camera)
			}
		}
	}

	return cameras
}
