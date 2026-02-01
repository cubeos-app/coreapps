#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CubeOS AppArmor Fix for Ubuntu 24.04
# ═══════════════════════════════════════════════════════════════════════════════
# 
# Run this ONCE on the Pi before deploying Swarm stacks.
# This disables the docker-default AppArmor profile which blocks
# certain container operations in Swarm mode.
#
# ═══════════════════════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  CubeOS AppArmor Fix${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Check if AppArmor is active
if ! command -v aa-status &> /dev/null; then
    echo -e "${GREEN}AppArmor not installed - no fix needed${NC}"
    exit 0
fi

# Check if docker-default profile exists
if aa-status 2>/dev/null | grep -q "docker-default"; then
    echo -e "${YELLOW}Disabling docker-default AppArmor profile...${NC}"
    
    # Method 1: Disable the profile
    if [ -f /etc/apparmor.d/docker-default ]; then
        aa-disable /etc/apparmor.d/docker-default 2>/dev/null || true
    fi
    
    # Method 2: Also try removing from kernel
    if [ -f /sys/kernel/security/apparmor/profiles ]; then
        echo -n "docker-default" > /sys/kernel/security/apparmor/.remove 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✓ docker-default profile disabled${NC}"
else
    echo -e "${GREEN}docker-default profile not loaded - no fix needed${NC}"
fi

# Verify
echo ""
echo "Current AppArmor profiles for Docker:"
aa-status 2>/dev/null | grep -i docker || echo "  None"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  AppArmor fix complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "You can now deploy Swarm stacks without privileged mode."
