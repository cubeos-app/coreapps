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
// Mount Types
// ============================================================================

// NetworkMount represents a network mount.
// @Description Network mount (SMB/NFS)
type NetworkMount struct {
	Type       string `json:"type" example:"smb"`
	Source     string `json:"source" example:"//192.168.1.100/share"`
	Mountpoint string `json:"mountpoint" example:"/mnt/nas"`
	Options    string `json:"options,omitempty" example:"username=user,password=***"`
	Mounted    bool   `json:"mounted" example:"true"`
	Available  int64  `json:"available,omitempty"`
	Used       int64  `json:"used,omitempty"`
	Total      int64  `json:"total,omitempty"`
}

// NetworkMountsResponse represents network mounts list.
// @Description List of network mounts
type NetworkMountsResponse struct {
	Count  int            `json:"count" example:"2"`
	Mounts []NetworkMount `json:"mounts"`
}

// SMBMountRequest represents SMB mount request.
// @Description SMB mount parameters
type SMBMountRequest struct {
	Server     string `json:"server" example:"192.168.1.100"`
	Share      string `json:"share" example:"share"`
	Mountpoint string `json:"mountpoint" example:"/mnt/nas"`
	Username   string `json:"username,omitempty" example:"user"`
	Password   string `json:"password,omitempty" example:"secret"`
	Domain     string `json:"domain,omitempty" example:"WORKGROUP"`
	Version    string `json:"version,omitempty" example:"3.0"`
}

// NFSMountRequest represents NFS mount request.
// @Description NFS mount parameters
type NFSMountRequest struct {
	Server     string `json:"server" example:"192.168.1.100"`
	Export     string `json:"export" example:"/export/share"`
	Mountpoint string `json:"mountpoint" example:"/mnt/nfs"`
	Options    string `json:"options,omitempty" example:"ro,noatime"`
	Version    string `json:"version,omitempty" example:"4"`
}

// UnmountRequest represents unmount request.
// @Description Unmount parameters
type UnmountRequest struct {
	Mountpoint string `json:"mountpoint" example:"/mnt/nas"`
	Force      bool   `json:"force,omitempty" example:"false"`
	Lazy       bool   `json:"lazy,omitempty" example:"false"`
}

// ============================================================================
// Network Mount Handlers
// ============================================================================

// GetNetworkMounts lists network mounts.
// @Summary List network mounts
// @Description Returns list of active network mounts (SMB/NFS)
// @Tags Mounts
// @Accept json
// @Produce json
// @Success 200 {object} NetworkMountsResponse
// @Failure 500 {object} ErrorResponse
// @Router /mounts [get]
func (h *HALHandler) GetNetworkMounts(w http.ResponseWriter, r *http.Request) {
	mounts := h.scanNetworkMounts()
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"count":  len(mounts),
		"mounts": mounts,
	})
}

// MountSMB mounts an SMB share.
// @Summary Mount SMB share
// @Description Mounts a Windows/Samba network share
// @Tags Mounts
// @Accept json
// @Produce json
// @Param request body SMBMountRequest true "SMB mount parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /mounts/smb [post]
func (h *HALHandler) MountSMB(w http.ResponseWriter, r *http.Request) {
	var req SMBMountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Server == "" || req.Share == "" || req.Mountpoint == "" {
		errorResponse(w, http.StatusBadRequest, "server, share, and mountpoint required")
		return
	}

	// Create mountpoint
	if err := os.MkdirAll(req.Mountpoint, 0755); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create mountpoint: "+err.Error())
		return
	}

	// Build mount options
	source := fmt.Sprintf("//%s/%s", req.Server, req.Share)
	options := []string{}

	if req.Username != "" {
		options = append(options, "username="+req.Username)
		if req.Password != "" {
			options = append(options, "password="+req.Password)
		}
	} else {
		options = append(options, "guest")
	}

	if req.Domain != "" {
		options = append(options, "domain="+req.Domain)
	}

	if req.Version != "" {
		options = append(options, "vers="+req.Version)
	}

	// Add common options
	options = append(options, "iocharset=utf8")

	optString := strings.Join(options, ",")

	// Mount
	cmd := exec.Command("mount", "-t", "cifs", "-o", optString, source, req.Mountpoint)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("mount failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("mounted %s at %s", source, req.Mountpoint))
}

// MountNFS mounts an NFS share.
// @Summary Mount NFS share
// @Description Mounts an NFS network share
// @Tags Mounts
// @Accept json
// @Produce json
// @Param request body NFSMountRequest true "NFS mount parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /mounts/nfs [post]
func (h *HALHandler) MountNFS(w http.ResponseWriter, r *http.Request) {
	var req NFSMountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Server == "" || req.Export == "" || req.Mountpoint == "" {
		errorResponse(w, http.StatusBadRequest, "server, export, and mountpoint required")
		return
	}

	// Create mountpoint
	if err := os.MkdirAll(req.Mountpoint, 0755); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create mountpoint: "+err.Error())
		return
	}

	// Build source
	source := fmt.Sprintf("%s:%s", req.Server, req.Export)

	// Build options
	options := []string{}
	if req.Options != "" {
		options = append(options, req.Options)
	}
	if req.Version != "" {
		options = append(options, "nfsvers="+req.Version)
	}

	args := []string{"-t", "nfs"}
	if len(options) > 0 {
		args = append(args, "-o", strings.Join(options, ","))
	}
	args = append(args, source, req.Mountpoint)

	// Mount
	cmd := exec.Command("mount", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("mount failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("mounted %s at %s", source, req.Mountpoint))
}

// UnmountNetwork unmounts a network share.
// @Summary Unmount network share
// @Description Unmounts a network share (SMB/NFS)
// @Tags Mounts
// @Accept json
// @Produce json
// @Param request body UnmountRequest true "Unmount parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /mounts/unmount [post]
func (h *HALHandler) UnmountNetwork(w http.ResponseWriter, r *http.Request) {
	var req UnmountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Mountpoint == "" {
		errorResponse(w, http.StatusBadRequest, "mountpoint required")
		return
	}

	// Sync first
	exec.Command("sync").Run()

	// Build umount command
	args := []string{}
	if req.Force {
		args = append(args, "-f")
	}
	if req.Lazy {
		args = append(args, "-l")
	}
	args = append(args, req.Mountpoint)

	cmd := exec.Command("umount", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("unmount failed: %s - %s", err, string(output)))
		return
	}

	successResponse(w, fmt.Sprintf("unmounted %s", req.Mountpoint))
}

// CheckSMBServer checks if an SMB server is available.
// @Summary Check SMB server
// @Description Checks if an SMB server is reachable and lists shares
// @Tags Mounts
// @Accept json
// @Produce json
// @Param server query string true "Server address" example(192.168.1.100)
// @Param username query string false "Username"
// @Param password query string false "Password"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /mounts/smb/check [get]
func (h *HALHandler) CheckSMBServer(w http.ResponseWriter, r *http.Request) {
	server := r.URL.Query().Get("server")
	if server == "" {
		errorResponse(w, http.StatusBadRequest, "server required")
		return
	}

	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")

	// Use smbclient to list shares
	args := []string{"-L", server, "-N"} // -N for no password
	if username != "" {
		args = []string{"-L", server, "-U", username}
		if password != "" {
			args = []string{"-L", server, "-U", username + "%" + password}
		}
	}

	cmd := exec.Command("smbclient", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("SMB check failed: %s - %s", err, string(output)))
		return
	}

	// Parse shares from output
	var shares []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Share lines typically start with share name
		if strings.Contains(line, "Disk") || strings.Contains(line, "IPC") || strings.Contains(line, "Printer") {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				shares = append(shares, parts[0])
			}
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"server":    server,
		"available": true,
		"shares":    shares,
	})
}

// CheckNFSServer checks if an NFS server is available.
// @Summary Check NFS server
// @Description Checks if an NFS server is reachable and lists exports
// @Tags Mounts
// @Accept json
// @Produce json
// @Param server query string true "Server address" example(192.168.1.100)
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /mounts/nfs/check [get]
func (h *HALHandler) CheckNFSServer(w http.ResponseWriter, r *http.Request) {
	server := r.URL.Query().Get("server")
	if server == "" {
		errorResponse(w, http.StatusBadRequest, "server required")
		return
	}

	// Use showmount to list exports
	cmd := exec.Command("showmount", "-e", server)
	output, err := cmd.CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("NFS check failed: %s - %s", err, string(output)))
		return
	}

	// Parse exports from output
	var exports []string
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}
		line = strings.TrimSpace(line)
		if line != "" {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				exports = append(exports, parts[0])
			}
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"server":    server,
		"available": true,
		"exports":   exports,
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

func (h *HALHandler) scanNetworkMounts() []NetworkMount {
	var mounts []NetworkMount

	// Read /proc/mounts
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return mounts
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		source := fields[0]
		mountpoint := fields[1]
		fstype := fields[2]

		// Check if it's a network mount
		if fstype == "cifs" || fstype == "nfs" || fstype == "nfs4" {
			mount := NetworkMount{
				Source:     source,
				Mountpoint: mountpoint,
				Mounted:    true,
			}

			if fstype == "cifs" {
				mount.Type = "smb"
			} else {
				mount.Type = "nfs"
			}

			// Get usage stats
			if usage := h.getMountUsage(mountpoint); usage != nil {
				mount.Total = usage["total"]
				mount.Used = usage["used"]
				mount.Available = usage["available"]
			}

			mounts = append(mounts, mount)
		}
	}

	return mounts
}

func (h *HALHandler) getMountUsage(mountpoint string) map[string]int64 {
	cmd := exec.Command("df", "-B1", mountpoint)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return nil
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return nil
	}

	total, _ := parseInt64(fields[1])
	used, _ := parseInt64(fields[2])
	available, _ := parseInt64(fields[3])

	return map[string]int64{
		"total":     total,
		"used":      used,
		"available": available,
	}
}

func parseInt64(s string) (int64, error) {
	var val int64
	_, err := fmt.Sscanf(s, "%d", &val)
	return val, err
}
