package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// ============================================================================
// USB Storage Types
// ============================================================================

// USBStorageDevice represents a USB storage device.
// @Description USB storage device information
type USBStorageDevice struct {
	Path       string `json:"path" example:"/dev/sda1"`
	Name       string `json:"name" example:"sda1"`
	Size       int64  `json:"size"`
	SizeHuman  string `json:"size_human" example:"32 GB"`
	Vendor     string `json:"vendor,omitempty" example:"SanDisk"`
	Model      string `json:"model,omitempty" example:"Cruzer Blade"`
	Serial     string `json:"serial,omitempty"`
	Filesystem string `json:"filesystem,omitempty" example:"exfat"`
	Label      string `json:"label,omitempty" example:"USBDRIVE"`
	Mountpoint string `json:"mountpoint,omitempty" example:"/mnt/usb"`
	Mounted    bool   `json:"mounted" example:"false"`
	Removable  bool   `json:"removable" example:"true"`
}

// USBStorageResponse represents USB storage list.
// @Description List of USB storage devices
type USBStorageResponse struct {
	Count   int                `json:"count" example:"2"`
	Devices []USBStorageDevice `json:"devices"`
}

// USBMountRequest represents USB mount request.
// @Description USB mount parameters
type USBMountRequest struct {
	Device     string `json:"device" example:"/dev/sda1"`
	Mountpoint string `json:"mountpoint,omitempty" example:"/mnt/usb"`
	Options    string `json:"options,omitempty" example:"rw,noatime"`
}

// ============================================================================
// USB Storage Handlers
// ============================================================================

// GetUSBStorageDevices lists USB storage devices.
// @Summary List USB storage devices
// @Description Returns list of connected USB storage devices
// @Tags USB
// @Accept json
// @Produce json
// @Success 200 {object} USBStorageResponse
// @Failure 500 {object} ErrorResponse
// @Router /storage/usb [get]
func (h *HALHandler) GetUSBStorageDevices(w http.ResponseWriter, r *http.Request) {
	devices := h.scanUSBStorage()
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"count":   len(devices),
		"devices": devices,
	})
}

// MountUSBStorage mounts a USB device.
// @Summary Mount USB storage
// @Description Mounts a USB storage device to specified mountpoint
// @Tags USB
// @Accept json
// @Produce json
// @Param request body USBMountRequest true "Mount parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /storage/usb/mount [post]
func (h *HALHandler) MountUSBStorage(w http.ResponseWriter, r *http.Request) {
	var req USBMountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Device == "" {
		errorResponse(w, http.StatusBadRequest, "device required")
		return
	}

	mountpoint := req.Mountpoint
	if mountpoint == "" {
		// Auto-generate mountpoint based on device name
		devName := strings.TrimPrefix(req.Device, "/dev/")
		mountpoint = "/mnt/" + devName
	}

	// Create mountpoint
	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create mountpoint: "+err.Error())
		return
	}

	// Build mount options
	options := "rw,noatime"
	if req.Options != "" {
		options = req.Options
	}

	// Mount
	cmd := exec.Command("mount", "-o", options, req.Device, mountpoint)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("mount failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("mounted %s at %s", req.Device, mountpoint))
}

// UnmountUSBStorage unmounts a USB device.
// @Summary Unmount USB storage
// @Description Unmounts a USB storage device
// @Tags USB
// @Accept json
// @Produce json
// @Param request body USBMountRequest true "Unmount parameters (mountpoint or device required)"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /storage/usb/unmount [post]
func (h *HALHandler) UnmountUSBStorage(w http.ResponseWriter, r *http.Request) {
	var req USBMountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	target := req.Mountpoint
	if target == "" {
		target = req.Device
	}
	if target == "" {
		errorResponse(w, http.StatusBadRequest, "mountpoint or device required")
		return
	}

	// Sync before unmount
	exec.Command("sync").Run()

	cmd := exec.Command("umount", target)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unmount failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("unmounted %s", target))
}

// EjectUSBStorage safely ejects a USB device.
// @Summary Eject USB storage
// @Description Safely ejects a USB storage device (sync + power off)
// @Tags USB
// @Accept json
// @Produce json
// @Param request body USBMountRequest true "Eject parameters (device required)"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /storage/usb/eject [post]
func (h *HALHandler) EjectUSBStorage(w http.ResponseWriter, r *http.Request) {
	var req USBMountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Device == "" {
		errorResponse(w, http.StatusBadRequest, "device required")
		return
	}

	// Sync first
	exec.Command("sync").Run()

	// Get base device (sda from sda1)
	baseDev := strings.TrimRight(req.Device, "0123456789")
	baseDev = strings.TrimPrefix(baseDev, "/dev/")

	// Try to unmount all partitions first
	cmd := exec.Command("bash", "-c", fmt.Sprintf("umount /dev/%s* 2>/dev/null || true", baseDev))
	cmd.Run()

	// Eject
	cmd = exec.Command("eject", "/dev/"+baseDev)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Try udisks2 as fallback
		cmd = exec.Command("udisksctl", "power-off", "-b", "/dev/"+baseDev)
		if output2, err2 := cmd.CombinedOutput(); err2 != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("eject failed: %s - %s / %s", err, string(output), string(output2)))
			return
		}
	}

	successResponse(w, fmt.Sprintf("ejected %s", baseDev))
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *HALHandler) scanUSBStorage() []USBStorageDevice {
	var devices []USBStorageDevice

	// Use lsblk to get block devices with detailed info
	cmd := exec.Command("lsblk", "-J", "-b", "-o", "NAME,SIZE,TYPE,VENDOR,MODEL,SERIAL,FSTYPE,LABEL,MOUNTPOINT,RM,TRAN,PATH")
	output, err := cmd.Output()
	if err != nil {
		return devices
	}

	var result struct {
		Blockdevices []struct {
			Name       string `json:"name"`
			Size       int64  `json:"size"`
			Type       string `json:"type"`
			Vendor     string `json:"vendor"`
			Model      string `json:"model"`
			Serial     string `json:"serial"`
			Fstype     string `json:"fstype"`
			Label      string `json:"label"`
			Mountpoint string `json:"mountpoint"`
			Rm         bool   `json:"rm"`
			Tran       string `json:"tran"`
			Path       string `json:"path"`
			Children   []struct {
				Name       string `json:"name"`
				Size       int64  `json:"size"`
				Type       string `json:"type"`
				Fstype     string `json:"fstype"`
				Label      string `json:"label"`
				Mountpoint string `json:"mountpoint"`
				Path       string `json:"path"`
			} `json:"children,omitempty"`
		} `json:"blockdevices"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return devices
	}

	for _, dev := range result.Blockdevices {
		// Only USB devices
		if dev.Tran != "usb" {
			continue
		}

		// Process partitions
		if len(dev.Children) > 0 {
			for _, part := range dev.Children {
				if part.Type != "part" {
					continue
				}
				devices = append(devices, USBStorageDevice{
					Path:       part.Path,
					Name:       part.Name,
					Size:       part.Size,
					SizeHuman:  formatBytes(part.Size),
					Vendor:     strings.TrimSpace(dev.Vendor),
					Model:      strings.TrimSpace(dev.Model),
					Serial:     strings.TrimSpace(dev.Serial),
					Filesystem: part.Fstype,
					Label:      part.Label,
					Mountpoint: part.Mountpoint,
					Mounted:    part.Mountpoint != "",
					Removable:  dev.Rm,
				})
			}
		} else if dev.Type == "disk" {
			// Whole disk without partitions
			devices = append(devices, USBStorageDevice{
				Path:       dev.Path,
				Name:       dev.Name,
				Size:       dev.Size,
				SizeHuman:  formatBytes(dev.Size),
				Vendor:     strings.TrimSpace(dev.Vendor),
				Model:      strings.TrimSpace(dev.Model),
				Serial:     strings.TrimSpace(dev.Serial),
				Filesystem: dev.Fstype,
				Label:      dev.Label,
				Mountpoint: dev.Mountpoint,
				Mounted:    dev.Mountpoint != "",
				Removable:  dev.Rm,
			})
		}
	}

	return devices
}
