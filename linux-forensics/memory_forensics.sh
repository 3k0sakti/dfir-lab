#!/bin/bash

# Memory Forensics Script
# Analyzes memory dumps and volatile data for Linux containers

CONTAINER_NAME="$1"
OUTPUT_DIR="$2"

if [ -z "$CONTAINER_NAME" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <container_name> <output_directory>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "=== Memory Forensics Analysis ==="
echo "Container: $CONTAINER_NAME"
echo "Output: $OUTPUT_DIR"
echo "==============================="

echo "[+] Collecting memory artifacts..."

# 1. Process memory maps
echo "  [1] Collecting process memory maps..."
docker exec "$CONTAINER_NAME" bash -c '
for pid in $(ps -eo pid --no-headers); do
    if [ -r "/proc/$pid/maps" ]; then
        echo "=== PID $pid ===" >> /tmp/process_maps.txt
        cat "/proc/$pid/maps" >> /tmp/process_maps.txt 2>/dev/null || true
        echo "" >> /tmp/process_maps.txt
    fi
done
'
docker cp "$CONTAINER_NAME:/tmp/process_maps.txt" "$OUTPUT_DIR/process_memory_maps.txt"

# 2. Process command lines
echo "  [2] Collecting process command lines..."
docker exec "$CONTAINER_NAME" bash -c '
for pid in $(ps -eo pid --no-headers); do
    if [ -r "/proc/$pid/cmdline" ]; then
        echo "PID $pid: $(cat /proc/$pid/cmdline | tr "\0" " ")" >> /tmp/cmdlines.txt 2>/dev/null || true
    fi
done
'
docker cp "$CONTAINER_NAME:/tmp/cmdlines.txt" "$OUTPUT_DIR/process_cmdlines.txt"

# 3. Environment variables
echo "  [3] Collecting environment variables..."
docker exec "$CONTAINER_NAME" bash -c '
for pid in $(ps -eo pid --no-headers); do
    if [ -r "/proc/$pid/environ" ]; then
        echo "=== PID $pid Environment ===" >> /tmp/environments.txt
        cat "/proc/$pid/environ" | tr "\0" "\n" >> /tmp/environments.txt 2>/dev/null || true
        echo "" >> /tmp/environments.txt
    fi
done
'
docker cp "$CONTAINER_NAME:/tmp/environments.txt" "$OUTPUT_DIR/process_environments.txt"

# 4. Open file descriptors
echo "  [4] Collecting file descriptors..."
docker exec "$CONTAINER_NAME" bash -c '
for pid in $(ps -eo pid --no-headers); do
    if [ -d "/proc/$pid/fd" ]; then
        echo "=== PID $pid File Descriptors ===" >> /tmp/file_descriptors.txt
        ls -la "/proc/$pid/fd/" >> /tmp/file_descriptors.txt 2>/dev/null || true
        echo "" >> /tmp/file_descriptors.txt
    fi
done
'
docker cp "$CONTAINER_NAME:/tmp/file_descriptors.txt" "$OUTPUT_DIR/process_file_descriptors.txt"

# 5. Memory statistics
echo "  [5] Collecting memory statistics..."
docker exec "$CONTAINER_NAME" cat /proc/meminfo > "$OUTPUT_DIR/memory_info.txt"
docker exec "$CONTAINER_NAME" cat /proc/slabinfo > "$OUTPUT_DIR/slab_info.txt" 2>/dev/null || echo "Slab info not accessible"

# 6. Kernel ring buffer
echo "  [6] Collecting kernel messages..."
docker exec "$CONTAINER_NAME" dmesg > "$OUTPUT_DIR/kernel_messages.txt" 2>/dev/null || echo "dmesg not accessible"

# 7. Network memory statistics
echo "  [7] Collecting network memory info..."
docker exec "$CONTAINER_NAME" cat /proc/net/sockstat > "$OUTPUT_DIR/socket_stats.txt" 2>/dev/null || echo "Socket stats not accessible"

echo "[+] Memory forensics collection complete!"
echo "Artifacts saved in: $OUTPUT_DIR"

# Analysis
echo ""
echo "[+] Performing basic memory analysis..."

ANALYSIS_FILE="$OUTPUT_DIR/memory_analysis.txt"
echo "MEMORY FORENSICS ANALYSIS" > "$ANALYSIS_FILE"
echo "=========================" >> "$ANALYSIS_FILE"
echo "Analysis Date: $(date)" >> "$ANALYSIS_FILE"
echo "" >> "$ANALYSIS_FILE"

# Analyze suspicious processes
if [ -f "$OUTPUT_DIR/process_cmdlines.txt" ]; then
    echo "SUSPICIOUS PROCESS ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "---------------------------" >> "$ANALYSIS_FILE"
    
    suspicious_procs=$(grep -iE "(nc|netcat|wget|curl|python.*http|bash.*tmp|sh.*tmp)" "$OUTPUT_DIR/process_cmdlines.txt" 2>/dev/null || true)
    if [ ! -z "$suspicious_procs" ]; then
        echo "SUSPICIOUS PROCESSES FOUND:" >> "$ANALYSIS_FILE"
        echo "$suspicious_procs" >> "$ANALYSIS_FILE"
    else
        echo "No obviously suspicious processes detected." >> "$ANALYSIS_FILE"
    fi
    echo "" >> "$ANALYSIS_FILE"
fi

# Analyze file descriptors for suspicious files
if [ -f "$OUTPUT_DIR/process_file_descriptors.txt" ]; then
    echo "FILE DESCRIPTOR ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "------------------------" >> "$ANALYSIS_FILE"
    
    suspicious_fds=$(grep -iE "(tmp|dev/tcp|dev/udp|socket)" "$OUTPUT_DIR/process_file_descriptors.txt" 2>/dev/null || true)
    if [ ! -z "$suspicious_fds" ]; then
        echo "POTENTIALLY SUSPICIOUS FILE DESCRIPTORS:" >> "$ANALYSIS_FILE"
        echo "$suspicious_fds" >> "$ANALYSIS_FILE"
    else
        echo "No obviously suspicious file descriptors detected." >> "$ANALYSIS_FILE"
    fi
    echo "" >> "$ANALYSIS_FILE"
fi

echo "Memory analysis complete: $ANALYSIS_FILE"