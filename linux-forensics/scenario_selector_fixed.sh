#!/bin/bash

# Digital Forensics Lab - Simple Scenario Selector
# Fixed version that works with current directory structure

SCENARIO="$1"
CONTAINER_NAME="compromised-ubuntu"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

print_banner() {
    echo "=============================================="
    echo "   REAL-WORLD FORENSIC SCENARIO SELECTOR"
    echo "=============================================="
    echo ""
}

show_menu() {
    echo -e "${WHITE}Available Scenarios:${NC}"
    echo ""
    echo -e "${GREEN}1.${NC} ${BLUE}apt${NC}        - APT (Advanced Persistent Threat) investigation"
    echo -e "${GREEN}2.${NC} ${BLUE}ransomware${NC} - Ransomware attack investigation"
    echo -e "${GREEN}3.${NC} ${BLUE}insider${NC}    - Insider threat investigation"
    echo -e "${GREEN}4.${NC} ${BLUE}webapp${NC}     - Web application attack investigation"
    echo -e "${GREEN}5.${NC} ${BLUE}combined${NC}   - All scenarios combined"
    echo ""
    echo -e "${WHITE}Usage:${NC}"
    echo "  ./scenario_selector.sh apt"
    echo "  ./scenario_selector.sh ransomware"
    echo ""
}

setup_container() {
    echo "Checking container status..."
    
    # Stop and remove existing container if running
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        echo "Stopping existing container..."
        docker stop "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
    fi
    
    # Build image if needed
    if ! docker images | grep -q "compromised-ubuntu"; then
        echo "Building container image..."
        docker build -f Dockerfile.compromised -t compromised-ubuntu . > /dev/null 2>&1
    fi
    
    # Start container
    echo "Starting container..."
    docker run -d \
        --name "$CONTAINER_NAME" \
        -p 2222:22 \
        -p 8080:80 \
        compromised-ubuntu:latest
    
    sleep 5
    
    # Verify container is running
    if ! docker ps | grep -q "$CONTAINER_NAME"; then
        echo -e "${RED}❌ Failed to start container${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ Container ready${NC}"
}

run_apt_scenario() {
    echo -e "${YELLOW}[EXECUTING] APT Simulation Scenario${NC}"
    
    if [ ! -f "apt_simulation.sh" ]; then
        echo -e "${RED}APT simulation script not found!${NC}"
        return 1
    fi
    
    # Copy and execute APT simulation
    docker cp apt_simulation.sh "$CONTAINER_NAME":/tmp/
    docker exec "$CONTAINER_NAME" chmod +x /tmp/apt_simulation.sh
    docker exec "$CONTAINER_NAME" /tmp/apt_simulation.sh > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ APT scenario deployed successfully!${NC}"
        show_investigation_steps
    else
        echo -e "${YELLOW}⚠️  APT simulation completed with warnings${NC}"
    fi
}

run_ransomware_scenario() {
    echo -e "${RED}[EXECUTING] Ransomware Attack Scenario${NC}"
    
    if [ ! -f "ransomware_simulation.sh" ]; then
        echo -e "${RED}Ransomware simulation script not found!${NC}"
        return 1
    fi
    
    docker cp ransomware_simulation.sh "$CONTAINER_NAME":/tmp/
    docker exec "$CONTAINER_NAME" chmod +x /tmp/ransomware_simulation.sh
    docker exec "$CONTAINER_NAME" /tmp/ransomware_simulation.sh > /dev/null 2>&1
    
    echo -e "${GREEN}✅ Ransomware scenario deployed successfully!${NC}"
    show_investigation_steps
}

run_insider_scenario() {
    echo -e "${BLUE}[EXECUTING] Insider Threat Scenario${NC}"
    
    if [ ! -f "insider_threat_simulation.sh" ]; then
        echo -e "${RED}Insider threat simulation script not found!${NC}"
        return 1
    fi
    
    docker cp insider_threat_simulation.sh "$CONTAINER_NAME":/tmp/
    docker exec "$CONTAINER_NAME" chmod +x /tmp/insider_threat_simulation.sh
    docker exec "$CONTAINER_NAME" /tmp/insider_threat_simulation.sh > /dev/null 2>&1
    
    echo -e "${GREEN}✅ Insider threat scenario deployed successfully!${NC}"
    show_investigation_steps
}

run_webapp_scenario() {
    echo -e "${CYAN}[EXECUTING] Web Application Attack Scenario${NC}"
    
    if [ ! -f "webapp_attack_simulation.sh" ]; then
        echo -e "${RED}Web application attack simulation script not found!${NC}"
        return 1
    fi
    
    docker cp webapp_attack_simulation.sh "$CONTAINER_NAME":/tmp/
    docker exec "$CONTAINER_NAME" chmod +x /tmp/webapp_attack_simulation.sh
    docker exec "$CONTAINER_NAME" /tmp/webapp_attack_simulation.sh > /dev/null 2>&1
    
    echo -e "${GREEN}✅ Web application attack scenario deployed successfully!${NC}"
    show_investigation_steps
}

run_combined_scenario() {
    echo -e "${RED}[EXECUTING] Combined Multi-Vector Attack${NC}"
    echo "This will run all scenarios. This may take several minutes..."
    
    # Run all scenarios
    if [ -f "apt_simulation.sh" ]; then
        docker cp apt_simulation.sh "$CONTAINER_NAME":/tmp/
        docker exec "$CONTAINER_NAME" /tmp/apt_simulation.sh > /dev/null 2>&1
    fi
    
    if [ -f "ransomware_simulation.sh" ]; then
        docker cp ransomware_simulation.sh "$CONTAINER_NAME":/tmp/
        docker exec "$CONTAINER_NAME" /tmp/ransomware_simulation.sh > /dev/null 2>&1
    fi
    
    if [ -f "insider_threat_simulation.sh" ]; then
        docker cp insider_threat_simulation.sh "$CONTAINER_NAME":/tmp/
        docker exec "$CONTAINER_NAME" /tmp/insider_threat_simulation.sh > /dev/null 2>&1
    fi
    
    if [ -f "webapp_attack_simulation.sh" ]; then
        docker cp webapp_attack_simulation.sh "$CONTAINER_NAME":/tmp/
        docker exec "$CONTAINER_NAME" /tmp/webapp_attack_simulation.sh > /dev/null 2>&1
    fi
    
    echo -e "${GREEN}✅ All attack scenarios deployed successfully!${NC}"
    show_investigation_steps
}

show_investigation_steps() {
    echo ""
    echo -e "${CYAN}📋 NEXT STEPS:${NC}"
    echo "1. Collect evidence:"
    echo "   ./forensic_collector_fixed.sh $CONTAINER_NAME"
    echo ""
    echo "2. Analyze findings:"
    echo "   ./evidence_analyzer.sh ./evidence/CASE_*"
    echo ""
    echo "3. Access system:"
    echo "   SSH: ssh root@localhost -p 2222 (password: rootpass)"
    echo "   Web: http://localhost:8080"
    echo ""
    echo -e "${WHITE}Manual investigation commands:${NC}"
    echo "  docker exec $CONTAINER_NAME find /tmp -name '.*' -type f"
    echo "  docker exec $CONTAINER_NAME ps aux | grep -E 'python|curl|wget'"
    echo "  docker exec $CONTAINER_NAME netstat -tulpn"
    echo ""
}

# Main logic
print_banner

case "$SCENARIO" in
    "1"|"apt")
        setup_container
        run_apt_scenario
        ;;
    "2"|"ransomware")
        setup_container
        run_ransomware_scenario
        ;;
    "3"|"insider")
        setup_container
        run_insider_scenario
        ;;
    "4"|"webapp")
        setup_container
        run_webapp_scenario
        ;;
    "5"|"combined")
        setup_container
        run_combined_scenario
        ;;
    *)
        show_menu
        echo -e "${WHITE}Select a scenario number or name to begin investigation.${NC}"
        ;;
esac

echo ""
echo -e "${CYAN}Happy Investigating! 🔍${NC}"