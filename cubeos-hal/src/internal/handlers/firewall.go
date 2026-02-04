package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// GetFirewallRules returns iptables rules
// @Summary Get firewall rules
// @Description Returns all iptables rules from filter and nat tables
// @Tags Firewall
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /firewall/rules [get]
func (h *HALHandler) GetFirewallRules(w http.ResponseWriter, r *http.Request) {
	// Get filter table rules
	filterOutput, err := exec.Command("iptables", "-L", "-n", "-v", "--line-numbers").Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get filter rules: %v", err))
		return
	}

	// Get NAT table rules
	natOutput, _ := exec.Command("iptables", "-t", "nat", "-L", "-n", "-v", "--line-numbers").Output()

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"filter": parseIptablesOutput(string(filterOutput)),
		"nat":    parseIptablesOutput(string(natOutput)),
	})
}

// GetFirewallStatus returns overall firewall status
// @Summary Get firewall status
// @Description Returns overall firewall status including forwarding and NAT state
// @Tags Firewall
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /firewall/status [get]
func (h *HALHandler) GetFirewallStatus(w http.ResponseWriter, r *http.Request) {
	// Get forwarding status
	forwardData, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	forwardingEnabled := strings.TrimSpace(string(forwardData)) == "1"

	// Count rules in each chain
	filterOutput, _ := exec.Command("iptables", "-L", "-n", "--line-numbers").Output()
	natOutput, _ := exec.Command("iptables", "-t", "nat", "-L", "-n", "--line-numbers").Output()

	// Check if NAT is enabled by looking for MASQUERADE rules
	natEnabled := strings.Contains(string(natOutput), "MASQUERADE")

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"enabled":            true,
		"forwarding_enabled": forwardingEnabled,
		"nat_enabled":        natEnabled,
		"rules_count":        countIptablesRules(string(filterOutput)),
		"nat_rules_count":    countIptablesRules(string(natOutput)),
	})
}

// GetForwardingStatus returns IP forwarding status
// @Summary Get IP forwarding status
// @Description Returns whether IP forwarding is enabled by reading /proc/sys/net/ipv4/ip_forward
// @Tags Firewall
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /firewall/forwarding [get]
func (h *HALHandler) GetForwardingStatus(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to read ip_forward: %v", err))
		return
	}

	value := strings.TrimSpace(string(data))
	enabled := value == "1"

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"enabled": enabled,
		"value":   value,
		"source":  "/proc/sys/net/ipv4/ip_forward",
	})
}

// GetIPForwardStatus is an alias for GetForwardingStatus
// @Summary Get IP forward sysctl value
// @Description Returns the ip_forward sysctl value (alias for /forwarding endpoint)
// @Tags Firewall
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /firewall/ipforward [get]
func (h *HALHandler) GetIPForwardStatus(w http.ResponseWriter, r *http.Request) {
	h.GetForwardingStatus(w, r)
}

// GetNATStatus returns NAT status
// @Summary Get NAT status
// @Description Returns whether NAT/masquerading is enabled by checking POSTROUTING chain
// @Tags Firewall
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /firewall/nat/status [get]
func (h *HALHandler) GetNATStatus(w http.ResponseWriter, r *http.Request) {
	output, err := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v").Output()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get NAT rules: %v", err))
		return
	}

	enabled := strings.Contains(string(output), "MASQUERADE")

	var sourceNet, outInterface string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "MASQUERADE") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.Contains(f, "/") && !strings.HasPrefix(f, "0.0.0.0") {
					sourceNet = f
				}
				if strings.HasPrefix(f, "eth") || strings.HasPrefix(f, "wlan") {
					outInterface = f
				}
			}
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"enabled":       enabled,
		"source":        sourceNet,
		"out_interface": outInterface,
	})
}

// AddFirewallRule adds a firewall rule
// @Summary Add firewall rule
// @Description Adds a new iptables rule to the specified chain
// @Tags Firewall
// @Accept json
// @Produce json
// @Param request body object true "Firewall rule" example({"chain":"INPUT","protocol":"tcp","port":"80","action":"ACCEPT"})
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/rule [post]
func (h *HALHandler) AddFirewallRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Chain       string `json:"chain"`
		Protocol    string `json:"protocol"`
		Port        string `json:"port"`
		Source      string `json:"source"`
		Destination string `json:"destination"`
		Action      string `json:"action"`
		Interface   string `json:"interface"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Chain == "" {
		req.Chain = "INPUT"
	}
	if req.Action == "" {
		req.Action = "ACCEPT"
	}

	args := []string{"-A", req.Chain}

	if req.Interface != "" {
		args = append(args, "-i", req.Interface)
	}
	if req.Protocol != "" {
		args = append(args, "-p", req.Protocol)
	}
	if req.Port != "" {
		args = append(args, "--dport", req.Port)
	}
	if req.Source != "" {
		args = append(args, "-s", req.Source)
	}
	if req.Destination != "" {
		args = append(args, "-d", req.Destination)
	}
	args = append(args, "-j", req.Action)

	output, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to add rule: %v - %s", err, string(output)))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"rule":    req,
	})
}

// DeleteFirewallRule deletes a firewall rule
// @Summary Delete firewall rule
// @Description Deletes an iptables rule by chain and rule number
// @Tags Firewall
// @Accept json
// @Produce json
// @Param request body object true "Rule to delete" example({"chain":"INPUT","rule_number":"1"})
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/rule [delete]
func (h *HALHandler) DeleteFirewallRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Chain      string `json:"chain"`
		RuleNumber string `json:"rule_number"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Chain == "" || req.RuleNumber == "" {
		errorResponse(w, http.StatusBadRequest, "chain and rule_number required")
		return
	}

	output, err := exec.Command("iptables", "-D", req.Chain, req.RuleNumber).CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete rule: %v - %s", err, string(output)))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"chain":   req.Chain,
		"deleted": req.RuleNumber,
	})
}

// EnableNAT enables NAT/masquerading
// @Summary Enable NAT
// @Description Enables NAT masquerading for the specified source network and output interface
// @Tags Firewall
// @Accept json
// @Produce json
// @Param request body object false "NAT config" example({"source":"10.42.24.0/24","out_interface":"eth0"})
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/nat/enable [post]
func (h *HALHandler) EnableNAT(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source       string `json:"source"`
		OutInterface string `json:"out_interface"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body with defaults
		req.Source = "10.42.24.0/24"
		req.OutInterface = "eth0"
	}

	if req.Source == "" {
		req.Source = "10.42.24.0/24"
	}
	if req.OutInterface == "" {
		req.OutInterface = "eth0"
	}

	args := []string{"-t", "nat", "-A", "POSTROUTING", "-s", req.Source, "-o", req.OutInterface, "-j", "MASQUERADE"}
	output, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to enable NAT: %v - %s", err, string(output)))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":       true,
		"source":        req.Source,
		"out_interface": req.OutInterface,
	})
}

// DisableNAT disables NAT/masquerading
// @Summary Disable NAT
// @Description Disables NAT masquerading by flushing the POSTROUTING chain
// @Tags Firewall
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/nat/disable [post]
func (h *HALHandler) DisableNAT(w http.ResponseWriter, r *http.Request) {
	output, err := exec.Command("iptables", "-t", "nat", "-F", "POSTROUTING").CombinedOutput()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to disable NAT: %v - %s", err, string(output)))
		return
	}

	successResponse(w, "NAT disabled")
}

// EnableIPForward enables IP forwarding
// @Summary Enable IP forwarding
// @Description Enables IP forwarding by writing 1 to /proc/sys/net/ipv4/ip_forward
// @Tags Firewall
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/forward/enable [post]
func (h *HALHandler) EnableIPForward(w http.ResponseWriter, r *http.Request) {
	err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to enable forwarding: %v", err))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"enabled": true,
	})
}

// DisableIPForward disables IP forwarding
// @Summary Disable IP forwarding
// @Description Disables IP forwarding by writing 0 to /proc/sys/net/ipv4/ip_forward
// @Tags Firewall
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /firewall/forward/disable [post]
func (h *HALHandler) DisableIPForward(w http.ResponseWriter, r *http.Request) {
	err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to disable forwarding: %v", err))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"enabled": false,
	})
}

// Helper functions

func countIptablesRules(output string) int {
	count := 0
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
			count++
		}
	}
	return count
}

func parseIptablesOutput(output string) []map[string]string {
	var rules []map[string]string
	lines := strings.Split(output, "\n")

	currentChain := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Chain ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentChain = parts[1]
			}
			continue
		}

		if line == "" || strings.HasPrefix(line, "num") || strings.HasPrefix(line, "pkts") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			rule := map[string]string{
				"chain":  currentChain,
				"target": fields[2],
				"prot":   fields[3],
			}
			if len(fields) >= 8 {
				rule["source"] = fields[7]
			}
			if len(fields) >= 9 {
				rule["destination"] = fields[8]
			}
			rules = append(rules, rule)
		}
	}

	return rules
}
