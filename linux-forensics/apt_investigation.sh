#!/bin/bash

# APT Investigation Module - Simplified and Fixed
# Modul 2: APT Investigation untuk Digital Forensics Lab

echo "=================================================="
echo "    🕵️  MODUL 2: APT INVESTIGATION"
echo "=================================================="
echo ""
echo "🎯 Learning Objectives:"
echo "  ✓ Identify APT attack patterns"
echo "  ✓ Understand persistence mechanisms"
echo "  ✓ Trace attack timeline"
echo "  ✓ Map to MITRE ATT&CK framework"
echo ""

# Configuration
LAB_DIR="/Users/ekosakti/Code/forensics/linux-forensics/linux-forensics"
CONTAINER_NAME="compromised-ubuntu"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Step 1: Check and cleanup existing containers
echo -e "${BLUE}[STEP 1]${NC} Checking container status..."
if docker ps -a | grep -q "$CONTAINER_NAME"; then
    echo "Stopping existing container..."
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
fi

# Step 2: Build container image
echo -e "${BLUE}[STEP 2]${NC} Building compromised Ubuntu container..."
docker build -f Dockerfile.compromised -t compromised-ubuntu . > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to build container image${NC}"
    exit 1
fi

# Step 3: Start container
echo -e "${BLUE}[STEP 3]${NC} Starting container..."
CONTAINER_ID=$(docker run -d -p 2222:22 -p 8080:80 --name "$CONTAINER_NAME" compromised-ubuntu)

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to start container${NC}"
    exit 1
fi

echo "Container started with ID: ${CONTAINER_ID:0:12}"

# Step 4: Wait for container to be ready
echo -e "${BLUE}[STEP 4]${NC} Waiting for container to initialize..."
sleep 5

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo -e "${RED}❌ Container failed to start properly${NC}"
    exit 1
fi

# Step 5: Deploy APT simulation
echo -e "${BLUE}[STEP 5]${NC} Deploying APT attack scenario..."

# Check if APT simulation script exists
if [ ! -f "apt_simulation.sh" ]; then
    echo -e "${RED}❌ APT simulation script not found in current directory${NC}"
    echo "Available scripts:"
    ls -la *.sh | grep simulation
    exit 1
fi

# Copy and execute APT simulation
echo "  Copying APT simulation script to container..."
docker cp apt_simulation.sh "$CONTAINER_NAME":/tmp/

echo "  Executing APT attack simulation..."
docker exec "$CONTAINER_NAME" chmod +x /tmp/apt_simulation.sh
docker exec "$CONTAINER_NAME" /tmp/apt_simulation.sh > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ APT scenario deployed successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  APT simulation completed with warnings${NC}"
fi

echo ""
echo -e "${CYAN}📋 INVESTIGATION STEPS:${NC}"
echo "1. Collect evidence:"
echo "   ./forensic_collector_fixed.sh $CONTAINER_NAME"
echo ""
echo "2. Analyze findings:"
echo "   ./evidence_analyzer.sh ./evidence/CASE_*"
echo ""
echo "3. Look for APT indicators:"
echo "   - SSH backdoor keys"
echo "   - Malicious systemd services"
echo "   - C2 communication artifacts"
echo "   - Spear phishing evidence"
echo ""
echo -e "${CYAN}🔍 MANUAL INVESTIGATION:${NC}"
echo "SSH access: ssh root@localhost -p 2222 (password: rootpass)"
echo "Web access: http://localhost:8080"
echo ""
echo "Manual commands to try:"
echo "  docker exec $CONTAINER_NAME find /tmp -name '.*' -type f"
echo "  docker exec $CONTAINER_NAME ps aux | grep -E 'python|curl|wget'"
echo "  docker exec $CONTAINER_NAME netstat -tulpn | grep -v ':22\\|:80'"
echo "  docker exec $CONTAINER_NAME cat /etc/crontab"
echo ""
echo -e "${GREEN}🎯 Expected findings:${NC}"
echo "  • Silent Dragon APT group artifacts"
echo "  • Operation Shadow Harvest campaign" 
echo "  • C2 domain: update.system-analytics.com"
echo "  • SSH keys, systemd services, cron jobs"
echo ""
echo -e "${YELLOW}⏭️  Next: Run evidence collection and analysis${NC}"
echo "Use: ./forensic_collector_fixed.sh $CONTAINER_NAME"