#!/bin/bash

# Network Forensics Script
# Analyzes network artifacts and connections

CONTAINER_NAME="$1"
OUTPUT_DIR="$2"

if [ -z "$CONTAINER_NAME" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <container_name> <output_directory>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "=== Network Forensics Analysis ==="
echo "Container: $CONTAINER_NAME"
echo "Output: $OUTPUT_DIR"
echo "================================="

echo "[+] Collecting network artifacts..."

# 1. Active connections
echo "  [1] Collecting active connections..."
docker exec "$CONTAINER_NAME" netstat -tulpn > "$OUTPUT_DIR/netstat_connections.txt" 2>/dev/null || echo "netstat not available"
docker exec "$CONTAINER_NAME" ss -tulpn > "$OUTPUT_DIR/ss_connections.txt" 2>/dev/null || echo "ss not available"

# 2. Routing table
echo "  [2] Collecting routing information..."
docker exec "$CONTAINER_NAME" route -n > "$OUTPUT_DIR/routing_table.txt" 2>/dev/null || echo "route command not available"
docker exec "$CONTAINER_NAME" ip route > "$OUTPUT_DIR/ip_routes.txt" 2>/dev/null || echo "ip route not available"

# 3. ARP table
echo "  [3] Collecting ARP table..."
docker exec "$CONTAINER_NAME" arp -a > "$OUTPUT_DIR/arp_table.txt" 2>/dev/null || echo "arp command not available"
docker exec "$CONTAINER_NAME" ip neigh > "$OUTPUT_DIR/ip_neighbors.txt" 2>/dev/null || echo "ip neigh not available"

# 4. Network interfaces
echo "  [4] Collecting network interface information..."
docker exec "$CONTAINER_NAME" ifconfig > "$OUTPUT_DIR/ifconfig.txt" 2>/dev/null || echo "ifconfig not available"
docker exec "$CONTAINER_NAME" ip addr > "$OUTPUT_DIR/ip_addresses.txt" 2>/dev/null || echo "ip addr not available"

# 5. Network statistics
echo "  [5] Collecting network statistics..."
docker exec "$CONTAINER_NAME" cat /proc/net/dev > "$OUTPUT_DIR/network_device_stats.txt" 2>/dev/null || echo "Network stats not accessible"
docker exec "$CONTAINER_NAME" cat /proc/net/tcp > "$OUTPUT_DIR/tcp_connections.txt" 2>/dev/null || echo "TCP stats not accessible"
docker exec "$CONTAINER_NAME" cat /proc/net/udp > "$OUTPUT_DIR/udp_connections.txt" 2>/dev/null || echo "UDP stats not accessible"

# 6. Network configuration files
echo "  [6] Collecting network configuration..."
docker exec "$CONTAINER_NAME" cat /etc/hosts > "$OUTPUT_DIR/hosts_file.txt" 2>/dev/null || echo "Hosts file not accessible"
docker exec "$CONTAINER_NAME" cat /etc/resolv.conf > "$OUTPUT_DIR/dns_config.txt" 2>/dev/null || echo "DNS config not accessible"
docker exec "$CONTAINER_NAME" cat /etc/hostname > "$OUTPUT_DIR/hostname.txt" 2>/dev/null || echo "Hostname not accessible"

# 7. Firewall rules (if available)
echo "  [7] Collecting firewall information..."
docker exec "$CONTAINER_NAME" iptables -L -n > "$OUTPUT_DIR/iptables_rules.txt" 2>/dev/null || echo "iptables not available"

echo "[+] Network forensics collection complete!"

# Analysis
echo ""
echo "[+] Performing network analysis..."

ANALYSIS_FILE="$OUTPUT_DIR/network_analysis.txt"
echo "NETWORK FORENSICS ANALYSIS" > "$ANALYSIS_FILE"
echo "==========================" >> "$ANALYSIS_FILE"
echo "Analysis Date: $(date)" >> "$ANALYSIS_FILE"
echo "" >> "$ANALYSIS_FILE"

# Analyze suspicious connections
if [ -f "$OUTPUT_DIR/netstat_connections.txt" ]; then
    echo "CONNECTION ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "-------------------" >> "$ANALYSIS_FILE"
    
    # Look for suspicious ports
    suspicious_ports=$(grep -E ":(4444|1337|31337|8080|9999|6666|7777)" "$OUTPUT_DIR/netstat_connections.txt" 2>/dev/null || true)
    if [ ! -z "$suspicious_ports" ]; then
        echo "SUSPICIOUS PORTS DETECTED:" >> "$ANALYSIS_FILE"
        echo "$suspicious_ports" >> "$ANALYSIS_FILE"
    else
        echo "No obviously suspicious ports detected." >> "$ANALYSIS_FILE"
    fi
    echo "" >> "$ANALYSIS_FILE"
    
    # Count total connections
    total_connections=$(grep -c "tcp\|udp" "$OUTPUT_DIR/netstat_connections.txt" 2>/dev/null || echo "0")
    echo "Total active connections: $total_connections" >> "$ANALYSIS_FILE"
    echo "" >> "$ANALYSIS_FILE"
fi

# Analyze hosts file
if [ -f "$OUTPUT_DIR/hosts_file.txt" ]; then
    echo "HOSTS FILE ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "-------------------" >> "$ANALYSIS_FILE"
    
    # Look for non-standard entries
    custom_hosts=$(grep -vE "^(127\.0\.0\.1|::1|#|$)" "$OUTPUT_DIR/hosts_file.txt" 2>/dev/null || true)
    if [ ! -z "$custom_hosts" ]; then
        echo "CUSTOM HOST ENTRIES DETECTED:" >> "$ANALYSIS_FILE"
        echo "$custom_hosts" >> "$ANALYSIS_FILE"
    else
        echo "No custom host entries detected." >> "$ANALYSIS_FILE"
    fi
    echo "" >> "$ANALYSIS_FILE"
fi

# Analyze TCP connections from /proc/net/tcp
if [ -f "$OUTPUT_DIR/tcp_connections.txt" ]; then
    echo "RAW TCP CONNECTION ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "---------------------------" >> "$ANALYSIS_FILE"
    
    # Count established connections
    established_count=$(grep -c "01" "$OUTPUT_DIR/tcp_connections.txt" 2>/dev/null || echo "0")
    echo "Established TCP connections: $established_count" >> "$ANALYSIS_FILE"
    
    # Look for listening sockets
    listening_count=$(grep -c "0A" "$OUTPUT_DIR/tcp_connections.txt" 2>/dev/null || echo "0")
    echo "Listening TCP sockets: $listening_count" >> "$ANALYSIS_FILE"
    echo "" >> "$ANALYSIS_FILE"
fi

echo "Network analysis complete: $ANALYSIS_FILE"