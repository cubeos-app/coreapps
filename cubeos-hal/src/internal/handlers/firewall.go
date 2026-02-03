package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ============================================================================
// Firewall Types
// ============================================================================

// FirewallRule represents a firewall rule.
// @Description Firewall rule
type FirewallRule struct {
	Chain       string `json:"chain" example:"INPUT"`
	Target      string `json:"target" example:"ACCEPT"`
	Protocol    string `json:"protocol" example:"tcp"`
	Source      string `json:"source,omitempty" example:"10.42.24.0/24"`
	Destination string `json:"destination,omitempty"`
	Port        int    `json:"port,omitempty" example:"22"`
	Interface   string `json:"interface,omitempty" example:"eth0"`
}

// FirewallRulesResponse represents firewall rules list.
// @Description List of firewall rules
type FirewallRulesResponse struct {
	Rules []FirewallRule `json:"rules"`
	Raw   string         `json:"raw,omitempty"`
}

// FirewallRuleRequest represents a firewall rule add/delete request.
// @Description Firewall rule parameters
type FirewallRuleRequest struct {
	Chain       string `json:"chain" example:"INPUT"`
	Target      string `json:"target" example:"ACCEPT"`
	Protocol    string `json:"protocol" example:"tcp"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Port        int    `json:"port,omitempty" example:"22"`
	Interface   string `json:"interface,omitempty"`
}

// ============================================================================
// Firewall Handlers
// ============================================================================

// GetFirewallRules returns firewall rules.
// @Summary Get firewall rules
// @Description Returns current iptables rules
// @Tags Firewall
// @Accept json
// @Produce json
// @Success 200 {object} FirewallRulesResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/rules [get]
func (h *HALHandler) GetFirewallRules(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("iptables", "-L", "-n", "-v")
	output, err := cmd.Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get firewall rules: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"raw":   string(output),
		"rules": []FirewallRule{},
	})
}

// EnableNAT enables NAT/masquerading.
// @Summary Enable NAT
// @Description Enables NAT/masquerading for internet sharing
// @Tags Firewall
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/nat/enable [post]
func (h *HALHandler) EnableNAT(w http.ResponseWriter, r *http.Request) {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to enable IP forwarding: "+err.Error())
		return
	}

	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE")
	if output, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(output), "already") {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to enable NAT: %s - %s", err, string(output)))
			return
		}
	}

	successResponse(w, "NAT enabled")
}

// DisableNAT disables NAT/masquerading.
// @Summary Disable NAT
// @Description Disables NAT/masquerading
// @Tags Firewall
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/nat/disable [post]
func (h *HALHandler) DisableNAT(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE")
	cmd.Run()

	os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644)

	successResponse(w, "NAT disabled")
}

// EnableIPForward enables IP forwarding.
// @Summary Enable IP forwarding
// @Description Enables IP packet forwarding between interfaces
// @Tags Firewall
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/forward/enable [post]
func (h *HALHandler) EnableIPForward(w http.ResponseWriter, r *http.Request) {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to enable IP forwarding: "+err.Error())
		return
	}
	successResponse(w, "IP forwarding enabled")
}

// DisableIPForward disables IP forwarding.
// @Summary Disable IP forwarding
// @Description Disables IP packet forwarding between interfaces
// @Tags Firewall
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/forward/disable [post]
func (h *HALHandler) DisableIPForward(w http.ResponseWriter, r *http.Request) {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to disable IP forwarding: "+err.Error())
		return
	}
	successResponse(w, "IP forwarding disabled")
}

// AddFirewallRule adds a firewall rule.
// @Summary Add firewall rule
// @Description Adds an iptables rule
// @Tags Firewall
// @Accept json
// @Produce json
// @Param request body FirewallRuleRequest true "Rule parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/rule [post]
func (h *HALHandler) AddFirewallRule(w http.ResponseWriter, r *http.Request) {
	var req FirewallRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	args := []string{"-A", req.Chain}

	if req.Protocol != "" {
		args = append(args, "-p", req.Protocol)
	}
	if req.Source != "" {
		args = append(args, "-s", req.Source)
	}
	if req.Destination != "" {
		args = append(args, "-d", req.Destination)
	}
	if req.Port > 0 {
		args = append(args, "--dport", strconv.Itoa(req.Port))
	}
	if req.Interface != "" {
		args = append(args, "-i", req.Interface)
	}
	args = append(args, "-j", req.Target)

	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to add rule: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "firewall rule added")
}

// DeleteFirewallRule deletes a firewall rule.
// @Summary Delete firewall rule
// @Description Deletes an iptables rule
// @Tags Firewall
// @Accept json
// @Produce json
// @Param request body FirewallRuleRequest true "Rule parameters"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/rule [delete]
func (h *HALHandler) DeleteFirewallRule(w http.ResponseWriter, r *http.Request) {
	var req FirewallRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	args := []string{"-D", req.Chain}

	if req.Protocol != "" {
		args = append(args, "-p", req.Protocol)
	}
	if req.Source != "" {
		args = append(args, "-s", req.Source)
	}
	if req.Destination != "" {
		args = append(args, "-d", req.Destination)
	}
	if req.Port > 0 {
		args = append(args, "--dport", strconv.Itoa(req.Port))
	}
	if req.Interface != "" {
		args = append(args, "-i", req.Interface)
	}
	args = append(args, "-j", req.Target)

	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete rule: %s - %s", err, string(output)))
		return
	}

	successResponse(w, "firewall rule deleted")
}
