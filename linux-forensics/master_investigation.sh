#!/bin/bash

# Master Digital Forensics Investigation Script
# Orchestrates the complete forensic investigation process

set -e

echo "=============================================="
echo "   DIGITAL FORENSICS INVESTIGATION LAB"
echo "=============================================="
echo ""

# Configuration
LAB_DIR="/Users/ekosakti/Code/forensics/lab"
EVIDENCE_DIR="$LAB_DIR/evidence"
REPORTS_DIR="$LAB_DIR/reports"
CONTAINER_NAME="compromised-ubuntu"
CASE_ID="CASE_$(date +%Y%m%d_%H%M%S)"

# Make scripts executable
chmod +x "$LAB_DIR"/*.sh

echo "Lab Configuration:"
echo "  Lab Directory: $LAB_DIR"
echo "  Evidence Directory: $EVIDENCE_DIR"
echo "  Reports Directory: $REPORTS_DIR"
echo "  Container Name: $CONTAINER_NAME"
echo "  Case ID: $CASE_ID"
echo ""

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        echo "ERROR: Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

# Function to build and start the compromised container
setup_lab_environment() {
    echo "[PHASE 1] Setting up lab environment..."
    
    # Build the compromised container
    echo "  Building compromised Ubuntu container..."
    cd "$LAB_DIR"
    docker build -f Dockerfile.compromised -t compromised-ubuntu:latest .
    
    # Stop and remove existing container if it exists
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
    
    # Start the container
    echo "  Starting container: $CONTAINER_NAME"
    docker run -d --name "$CONTAINER_NAME" \
        -p 2222:22 \
        -p 8080:80 \
        compromised-ubuntu:latest
    
    # Wait for container to be ready
    echo "  Waiting for container to initialize..."
    sleep 10
    
    echo "  Container ready!"
    echo ""
}

# Function to simulate the compromise
simulate_compromise() {
    echo "[PHASE 2] Simulating advanced multi-stage system compromise..."
    
    # Copy all compromise scripts to container
    docker cp "$LAB_DIR/compromise.sh" "$CONTAINER_NAME:/tmp/"
    docker cp "$LAB_DIR/scenarios" "$CONTAINER_NAME:/tmp/" 2>/dev/null || echo "  Scenarios directory not found, using basic compromise only"
    
    # Make scripts executable
    docker exec "$CONTAINER_NAME" chmod +x /tmp/compromise.sh
    docker exec "$CONTAINER_NAME" find /tmp/scenarios -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    
    # Execute main compromise simulation
    echo "  [2.1] Executing primary compromise scenario..."
    docker exec "$CONTAINER_NAME" /tmp/compromise.sh
    
    # Execute additional real-world scenarios if available
    if docker exec "$CONTAINER_NAME" test -d /tmp/scenarios; then
        echo "  [2.2] Executing APT simulation..."
        docker exec "$CONTAINER_NAME" /tmp/scenarios/apt_simulation.sh 2>/dev/null || echo "    APT simulation not available"
        
        echo "  [2.3] Executing ransomware simulation..."
        docker exec "$CONTAINER_NAME" /tmp/scenarios/ransomware_simulation.sh 2>/dev/null || echo "    Ransomware simulation not available"
        
        echo "  [2.4] Executing insider threat simulation..."
        docker exec "$CONTAINER_NAME" /tmp/scenarios/insider_threat_simulation.sh 2>/dev/null || echo "    Insider threat simulation not available"
        
        echo "  [2.5] Executing web application attack simulation..."
        docker exec "$CONTAINER_NAME" /tmp/scenarios/webapp_attack_simulation.sh 2>/dev/null || echo "    Web app attack simulation not available"
    fi
    
    echo "  ✅ Advanced multi-stage compromise simulation complete!"
    echo "  📊 System now exhibits realistic enterprise attack patterns"
    echo ""
}

# Function to collect forensic evidence
collect_evidence() {
    echo "[PHASE 3] Collecting forensic evidence..."
    
    # Create evidence directory with proper permissions
    mkdir -p "$EVIDENCE_DIR"
    
    # Mount evidence directory into a forensic analysis container
    docker run --rm -v "$EVIDENCE_DIR:/forensics/evidence" \
        -v "$LAB_DIR:/scripts" \
        --name forensic-collector \
        ubuntu:22.04 \
        /scripts/forensic_collector.sh "$CONTAINER_NAME"
    
    echo "  Evidence collection complete!"
    echo ""
}

# Function to analyze evidence
analyze_evidence() {
    echo "[PHASE 4] Analyzing collected evidence..."
    
    # Find the latest case directory
    LATEST_CASE=$(ls -1t "$EVIDENCE_DIR" | head -1)
    CASE_PATH="$EVIDENCE_DIR/$LATEST_CASE"
    
    if [ -d "$CASE_PATH" ]; then
        echo "  Analyzing case: $LATEST_CASE"
        "$LAB_DIR/evidence_analyzer.sh" "$CASE_PATH"
        "$LAB_DIR/timeline_analyzer.sh" "$CASE_PATH"
        echo "  Analysis complete!"
    else
        echo "  ERROR: No case directory found for analysis"
        exit 1
    fi
    echo ""
}

# Function to generate report
generate_report() {
    echo "[PHASE 5] Generating forensic report..."
    
    # Find the latest case directory
    LATEST_CASE=$(ls -1t "$EVIDENCE_DIR" | head -1)
    CASE_PATH="$EVIDENCE_DIR/$LATEST_CASE"
    
    if [ -d "$CASE_PATH" ]; then
        mkdir -p "$REPORTS_DIR"
        "$LAB_DIR/report_generator.sh" "$CASE_PATH" "$LATEST_CASE"
        echo "  Report generation complete!"
    else
        echo "  ERROR: No case directory found for reporting"
        exit 1
    fi
    echo ""
}

# Function to display results
display_results() {
    echo "[PHASE 6] Investigation Results Summary"
    echo "======================================"
    
    # Find the latest case directory
    LATEST_CASE=$(ls -1t "$EVIDENCE_DIR" | head -1)
    CASE_PATH="$EVIDENCE_DIR/$LATEST_CASE"
    
    if [ -f "$CASE_PATH/indicators_of_compromise.txt" ]; then
        echo ""
        echo "INDICATORS OF COMPROMISE DETECTED:"
        echo "--------------------------------"
        ioc_count=$(grep -c "IOC:" "$CASE_PATH/indicators_of_compromise.txt" 2>/dev/null || echo "0")
        echo "Total IoCs found: $ioc_count"
        
        if [ "$ioc_count" -gt 0 ]; then
            echo ""
            echo "Sample IoCs:"
            grep "IOC:" "$CASE_PATH/indicators_of_compromise.txt" | head -5
        fi
    fi
    
    echo ""
    echo "INVESTIGATION COMPLETE!"
    echo "======================"
    echo "Case ID: $LATEST_CASE"
    echo "Evidence Location: $CASE_PATH"
    echo "Report Location: $REPORTS_DIR/forensic_report_${LATEST_CASE}.md"
    echo ""
    echo "Files generated:"
    echo "  - Evidence collection: $(ls -1 "$CASE_PATH" | wc -l) files"
    echo "  - Analysis results: $CASE_PATH/analysis_results.txt"
    echo "  - IoC report: $CASE_PATH/indicators_of_compromise.txt"
    echo "  - Timeline: $CASE_PATH/timeline_analysis.txt"
    echo "  - Final report: $REPORTS_DIR/forensic_report_${LATEST_CASE}.md"
    echo ""
}

# Function to cleanup
cleanup() {
    echo "[CLEANUP] Stopping lab environment..."
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
    echo "Lab environment stopped."
}

# Main execution flow
main() {
    echo "Starting digital forensics investigation..."
    echo ""
    
    # Check prerequisites
    check_docker
    
    # Set up trap for cleanup on exit
    trap cleanup EXIT
    
    # Execute investigation phases
    setup_lab_environment
    simulate_compromise
    collect_evidence
    analyze_evidence
    generate_report
    display_results
    
    echo "Investigation workflow complete!"
    echo ""
    echo "To view the results:"
    echo "  - Evidence: ls -la $EVIDENCE_DIR"
    echo "  - Reports: ls -la $REPORTS_DIR"
    echo ""
    echo "To restart the investigation:"
    echo "  ./master_investigation.sh"
    echo ""
}

# Handle command line arguments
case "${1:-run}" in
    "run")
        main
        ;;
    "setup")
        check_docker
        setup_lab_environment
        ;;
    "compromise")
        simulate_compromise
        ;;
    "collect")
        collect_evidence
        ;;
    "analyze")
        analyze_evidence
        ;;
    "report")
        generate_report
        ;;
    "cleanup")
        cleanup
        ;;
    "help")
        echo "Digital Forensics Investigation Script"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  run        - Execute complete investigation (default)"
        echo "  setup      - Setup lab environment only"
        echo "  compromise - Simulate compromise only"
        echo "  collect    - Collect evidence only"
        echo "  analyze    - Analyze evidence only"
        echo "  report     - Generate report only"
        echo "  cleanup    - Cleanup lab environment"
        echo "  help       - Show this help message"
        echo ""
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac