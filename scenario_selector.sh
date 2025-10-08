#!/bin/bash

# Real-World Scenario Selector
# Allows forensic investigators to choose specific attack scenarios to simulate

echo "=============================================="
echo "   REAL-WORLD FORENSIC SCENARIO SELECTOR"
echo "=============================================="
echo ""

# Configuration
LAB_DIR="/Users/ekosakti/Code/forensics/lab"
SCENARIOS_DIR="$LAB_DIR/scenarios"
CONTAINER_NAME="compromised-ubuntu"

# Ensure scenarios directory exists
mkdir -p "$SCENARIOS_DIR"

# Function to display available scenarios
show_scenarios() {
    echo "Available Real-World Attack Scenarios:"
    echo "======================================"
    echo ""
    echo "1. APT (Advanced Persistent Threat)"
    echo "   - Nation-state style attack"
    echo "   - Spear phishing, watering hole attacks"
    echo "   - Supply chain compromise"
    echo "   - Living off the land techniques"
    echo "   - Fileless malware simulation"
    echo ""
    echo "2. Ransomware Attack"
    echo "   - RDP brute force initial access"
    echo "   - Lateral movement and credential dumping"
    echo "   - Data exfiltration (double extortion)"
    echo "   - File encryption simulation"
    echo "   - Ransom note deployment"
    echo ""
    echo "3. Insider Threat"
    echo "   - Legitimate access abuse"
    echo "   - After-hours suspicious activity"
    echo "   - Data theft and sabotage"
    echo "   - Financial fraud simulation"
    echo "   - Social engineering internal targets"
    echo ""
    echo "4. Web Application Attack"
    echo "   - SQL injection and authentication bypass"
    echo "   - Web shell deployment"
    echo "   - XSS and session hijacking"
    echo "   - API exploitation"
    echo "   - Database compromise"
    echo ""
    echo "5. Multi-Stage Combined Attack"
    echo "   - All scenarios combined"
    echo "   - Realistic enterprise compromise"
    echo "   - Multiple attack vectors"
    echo "   - Advanced evasion techniques"
    echo ""
    echo "6. Custom Scenario Builder"
    echo "   - Build your own attack scenario"
    echo "   - Mix and match techniques"
    echo "   - Custom IoC generation"
    echo ""
}

# Function to execute specific scenario
execute_scenario() {
    local scenario="$1"
    
    case "$scenario" in
        "1"|"apt")
            echo "[EXECUTING] APT Simulation Scenario"
            if [ -f "$SCENARIOS_DIR/apt_simulation.sh" ]; then
                docker exec "$CONTAINER_NAME" /tmp/scenarios/apt_simulation.sh
            else
                echo "APT simulation script not found!"
                return 1
            fi
            ;;
        "2"|"ransomware")
            echo "[EXECUTING] Ransomware Attack Scenario"
            if [ -f "$SCENARIOS_DIR/ransomware_simulation.sh" ]; then
                docker exec "$CONTAINER_NAME" /tmp/scenarios/ransomware_simulation.sh
            else
                echo "Ransomware simulation script not found!"
                return 1
            fi
            ;;
        "3"|"insider")
            echo "[EXECUTING] Insider Threat Scenario"
            if [ -f "$SCENARIOS_DIR/insider_threat_simulation.sh" ]; then
                docker exec "$CONTAINER_NAME" /tmp/scenarios/insider_threat_simulation.sh
            else
                echo "Insider threat simulation script not found!"
                return 1
            fi
            ;;
        "4"|"webapp")
            echo "[EXECUTING] Web Application Attack Scenario"
            if [ -f "$SCENARIOS_DIR/webapp_attack_simulation.sh" ]; then
                docker exec "$CONTAINER_NAME" /tmp/scenarios/webapp_attack_simulation.sh
            else
                echo "Web application attack simulation script not found!"
                return 1
            fi
            ;;
        "5"|"combined")
            echo "[EXECUTING] Multi-Stage Combined Attack Scenario"
            execute_scenario "1"
            sleep 2
            execute_scenario "2"
            sleep 2
            execute_scenario "3"
            sleep 2
            execute_scenario "4"
            ;;
        "6"|"custom")
            custom_scenario_builder
            ;;
        *)
            echo "Invalid scenario selection: $scenario"
            return 1
            ;;
    esac
}

# Function for custom scenario builder
custom_scenario_builder() {
    echo ""
    echo "=== Custom Scenario Builder ==="
    echo "Select techniques to include (separate multiple choices with spaces):"
    echo ""
    echo "Initial Access:"
    echo "  a) SSH Brute Force"
    echo "  b) Spear Phishing"
    echo "  c) Web Application Exploit"
    echo "  d) Supply Chain Compromise"
    echo ""
    echo "Persistence:"
    echo "  e) SSH Keys"
    echo "  f) Systemd Services"
    echo "  g) Cron Jobs"
    echo "  h) Web Shells"
    echo ""
    echo "Privilege Escalation:"
    echo "  i) SUID Exploitation"
    echo "  j) Sudo Abuse"
    echo "  k) Kernel Exploits"
    echo ""
    echo "Defense Evasion:"
    echo "  l) Log Tampering"
    echo "  m) Timestomping"
    echo "  n) Process Hiding"
    echo ""
    echo "Data Exfiltration:"
    echo "  o) Database Theft"
    echo "  p) File Compression"
    echo "  q) Network Transfer"
    echo ""
    
    read -p "Enter your choices: " choices
    
    echo ""
    echo "Building custom scenario with techniques: $choices"
    
    # Generate custom scenario based on selections
    cat << 'EOF' > /tmp/custom_scenario.sh
#!/bin/bash
echo "[CUSTOM SCENARIO] Executing selected techniques..."
EOF
    
    for choice in $choices; do
        case "$choice" in
            "a") echo 'echo "  [SSH] Brute force simulation..."' >> /tmp/custom_scenario.sh ;;
            "b") echo 'echo "  [PHISH] Spear phishing simulation..."' >> /tmp/custom_scenario.sh ;;
            "c") echo 'echo "  [WEB] Web exploit simulation..."' >> /tmp/custom_scenario.sh ;;
            "d") echo 'echo "  [SUPPLY] Supply chain simulation..."' >> /tmp/custom_scenario.sh ;;
            "e") echo 'echo "  [SSH-KEY] SSH key persistence..."' >> /tmp/custom_scenario.sh ;;
            "f") echo 'echo "  [SYSTEMD] Service persistence..."' >> /tmp/custom_scenario.sh ;;
            "g") echo 'echo "  [CRON] Cron job persistence..."' >> /tmp/custom_scenario.sh ;;
            "h") echo 'echo "  [SHELL] Web shell deployment..."' >> /tmp/custom_scenario.sh ;;
            "i") echo 'echo "  [SUID] SUID exploitation..."' >> /tmp/custom_scenario.sh ;;
            "j") echo 'echo "  [SUDO] Sudo abuse..."' >> /tmp/custom_scenario.sh ;;
            "k") echo 'echo "  [KERNEL] Kernel exploit..."' >> /tmp/custom_scenario.sh ;;
            "l") echo 'echo "  [LOGS] Log tampering..."' >> /tmp/custom_scenario.sh ;;
            "m") echo 'echo "  [TIME] Timestamp modification..."' >> /tmp/custom_scenario.sh ;;
            "n") echo 'echo "  [HIDE] Process hiding..."' >> /tmp/custom_scenario.sh ;;
            "o") echo 'echo "  [DB] Database theft..."' >> /tmp/custom_scenario.sh ;;
            "p") echo 'echo "  [COMPRESS] File compression..."' >> /tmp/custom_scenario.sh ;;
            "q") echo 'echo "  [TRANSFER] Network transfer..."' >> /tmp/custom_scenario.sh ;;
        esac
    done
    
    echo 'echo "[CUSTOM SCENARIO] Custom scenario complete!"' >> /tmp/custom_scenario.sh
    chmod +x /tmp/custom_scenario.sh
    
    # Copy to container and execute
    docker cp /tmp/custom_scenario.sh "$CONTAINER_NAME:/tmp/"
    docker exec "$CONTAINER_NAME" /tmp/custom_scenario.sh
    
    rm -f /tmp/custom_scenario.sh
}

# Function to setup container for scenarios
setup_container() {
    echo "Checking container status..."
    if ! docker ps | grep -q "$CONTAINER_NAME"; then
        echo "Container not running. Starting container..."
        docker run -d --name "$CONTAINER_NAME" \
            -p 2222:22 \
            -p 8080:80 \
            compromised-ubuntu:latest
        sleep 10
    fi
    
    echo "Copying scenario scripts to container..."
    docker cp "$SCENARIOS_DIR" "$CONTAINER_NAME:/tmp/" 2>/dev/null || echo "No scenarios directory found"
    docker exec "$CONTAINER_NAME" find /tmp/scenarios -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
}

# Function to display scenario status
show_status() {
    echo ""
    echo "=== Scenario Execution Status ==="
    if docker ps | grep -q "$CONTAINER_NAME"; then
        echo "✅ Container Status: Running"
        echo "📡 SSH Access: localhost:2222"
        echo "🌐 Web Access: http://localhost:8080"
        
        # Check for compromise indicators
        echo ""
        echo "Quick IoC Check:"
        docker exec "$CONTAINER_NAME" ls -la /tmp/.* 2>/dev/null | grep -E "(hidden|creds|exfil)" | head -3 || echo "  No obvious indicators found"
    else
        echo "❌ Container Status: Not Running"
    fi
}

# Function to collect evidence after scenario
collect_evidence() {
    echo ""
    echo "=== Evidence Collection ==="
    read -p "Collect forensic evidence now? (y/n): " collect
    
    if [ "$collect" == "y" ] || [ "$collect" == "Y" ]; then
        echo "Starting evidence collection..."
        "$LAB_DIR/forensic_collector.sh" "$CONTAINER_NAME"
        
        # Quick analysis
        LATEST_CASE=$(ls -1t "$LAB_DIR/evidence" | head -1)
        if [ -n "$LATEST_CASE" ]; then
            echo "Running quick analysis..."
            "$LAB_DIR/evidence_analyzer.sh" "$LAB_DIR/evidence/$LATEST_CASE"
            
            # Show IoC summary
            IOC_COUNT=$(grep -c "IOC:" "$LAB_DIR/evidence/$LATEST_CASE/indicators_of_compromise.txt" 2>/dev/null || echo "0")
            echo ""
            echo "📊 Analysis Complete!"
            echo "🔍 Indicators of Compromise Found: $IOC_COUNT"
            
            if [ "$IOC_COUNT" -gt 0 ]; then
                echo ""
                echo "Top IoCs:"
                grep "IOC:" "$LAB_DIR/evidence/$LATEST_CASE/indicators_of_compromise.txt" | head -5
            fi
        fi
    fi
}

# Main execution
main() {
    case "${1:-interactive}" in
        "list")
            show_scenarios
            ;;
        "status")
            show_status
            ;;
        "setup")
            setup_container
            ;;
        "collect")
            collect_evidence
            ;;
        "interactive")
            show_scenarios
            echo ""
            read -p "Select scenario (1-6): " choice
            
            setup_container
            echo ""
            execute_scenario "$choice"
            show_status
            collect_evidence
            ;;
        *)
            # Direct scenario execution
            setup_container
            execute_scenario "$1"
            show_status
            ;;
    esac
}

# Handle command line arguments
if [ $# -eq 0 ]; then
    main "interactive"
else
    main "$@"
fi