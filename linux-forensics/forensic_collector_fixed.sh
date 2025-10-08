#!/bin/bash

# Digital Forensics Evidence Collection Script (Host-based)
# Collects evidence from compromised Docker container

CONTAINER_NAME="${1:-compromised-ubuntu}"
CASE_ID="CASE_$(date +%Y%m%d_%H%M%S)"
EVIDENCE_DIR="./evidence"
LOG_FILE="$EVIDENCE_DIR/$CASE_ID/collection.log"

# Create evidence directory
mkdir -p "$EVIDENCE_DIR/$CASE_ID"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=== Digital Forensics Investigation ==="
log "Case ID: $CASE_ID"
log "Target Container: $CONTAINER_NAME"
log "Investigation Start: $(date)"
log "========================================="

cd "$EVIDENCE_DIR/$CASE_ID"

log "[+] Phase 1: Volatile Data Collection"

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    log "[ERROR] Container $CONTAINER_NAME is not running"
    exit 1
fi

# 1. Container metadata (from host)
log "  [1.1] Collecting container metadata..."
docker inspect "$CONTAINER_NAME" > container_metadata.json 2>/dev/null || log "[ERROR] Failed to collect container metadata"

# 2. Running processes
log "  [1.2] Collecting process information..."
docker exec "$CONTAINER_NAME" ps aux > running_processes.txt 2>/dev/null || log "[ERROR] Failed to collect processes"
docker exec "$CONTAINER_NAME" ps -ef > process_tree.txt 2>/dev/null || log "[ERROR] Failed to collect process tree"

# 3. Network connections
log "  [1.3] Collecting network information..."
docker exec "$CONTAINER_NAME" netstat -tulpn > network_connections.txt 2>/dev/null || log "[ERROR] Failed to collect network connections"
docker exec "$CONTAINER_NAME" ss -tulpn > socket_connections.txt 2>/dev/null || log "[ERROR] Failed to collect socket connections"

# 4. Memory information
log "  [1.4] Collecting memory information..."
docker exec "$CONTAINER_NAME" cat /proc/meminfo > memory_info.txt 2>/dev/null || log "[ERROR] Failed to collect memory info"
docker exec "$CONTAINER_NAME" cat /proc/cpuinfo > cpu_info.txt 2>/dev/null || log "[ERROR] Failed to collect CPU info"

# 5. Environment variables
log "  [1.5] Collecting environment information..."
docker exec "$CONTAINER_NAME" env > environment_variables.txt 2>/dev/null || log "[ERROR] Failed to collect environment"

log "[+] Phase 2: System Configuration Collection"

# 6. User accounts
log "  [2.1] Collecting user account information..."
docker exec "$CONTAINER_NAME" cat /etc/passwd > passwd_file.txt 2>/dev/null || log "[ERROR] Failed to collect passwd"
docker exec "$CONTAINER_NAME" cat /etc/shadow > shadow_file.txt 2>/dev/null || log "[ERROR] Failed to collect shadow"
docker exec "$CONTAINER_NAME" cat /etc/group > group_file.txt 2>/dev/null || log "[ERROR] Failed to collect group"

# 7. System configuration
log "  [2.2] Collecting system configuration..."
docker exec "$CONTAINER_NAME" cat /etc/hosts > hosts_file.txt 2>/dev/null || log "[ERROR] Failed to collect hosts"
docker exec "$CONTAINER_NAME" cat /etc/hostname > hostname_file.txt 2>/dev/null || log "[ERROR] Failed to collect hostname"
docker exec "$CONTAINER_NAME" cat /etc/resolv.conf > dns_config.txt 2>/dev/null || log "[ERROR] Failed to collect DNS config"

# 8. SSH configuration
log "  [2.3] Collecting SSH configuration..."
docker exec "$CONTAINER_NAME" cat /etc/ssh/sshd_config > sshd_config.txt 2>/dev/null || log "[ERROR] Failed to collect SSH config"

log "[+] Phase 3: Log File Collection"

# 9. System logs
log "  [3.1] Collecting system logs..."
docker exec "$CONTAINER_NAME" cat /var/log/auth.log > auth_log.txt 2>/dev/null || log "[WARNING] Auth log not found"
docker exec "$CONTAINER_NAME" cat /var/log/syslog > syslog.txt 2>/dev/null || log "[WARNING] Syslog not found"
docker exec "$CONTAINER_NAME" dmesg > dmesg.txt 2>/dev/null || log "[ERROR] Failed to collect dmesg"

# 10. Web server logs
log "  [3.2] Collecting web server logs..."
docker exec "$CONTAINER_NAME" cat /var/log/nginx/access.log > nginx_access.log 2>/dev/null || log "[WARNING] Nginx access log not found"
docker exec "$CONTAINER_NAME" cat /var/log/nginx/error.log > nginx_error.log 2>/dev/null || log "[WARNING] Nginx error log not found"

log "[+] Phase 4: File System Analysis"

# 11. Recently modified files
log "  [4.1] Collecting recently modified files..."
docker exec "$CONTAINER_NAME" find / -type f -mtime -1 2>/dev/null | head -100 > recent_files.txt || log "[ERROR] Failed to find recent files"

# 12. Hidden files and directories
log "  [4.2] Collecting hidden files..."
docker exec "$CONTAINER_NAME" find /tmp -name ".*" -type f 2>/dev/null > hidden_files_tmp.txt || log "[ERROR] Failed to find hidden files in /tmp"
docker exec "$CONTAINER_NAME" find /home -name ".*" -type f 2>/dev/null > hidden_files_home.txt || log "[ERROR] Failed to find hidden files in /home"

# 13. SUID/SGID files
log "  [4.3] Collecting SUID/SGID files..."
docker exec "$CONTAINER_NAME" find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null > suid_sgid_files.txt || log "[ERROR] Failed to find SUID/SGID files"

# 14. Suspicious binaries
log "  [4.4] Collecting suspicious binaries..."
docker exec "$CONTAINER_NAME" ls -la /usr/bin/system_update 2>/dev/null > suspicious_binaries.txt || log "[WARNING] Suspicious binary not found"

log "[+] Phase 5: User Activity Collection"

# 15. Command history
log "  [5.1] Collecting command history..."
docker exec "$CONTAINER_NAME" cat /root/.bash_history > root_bash_history.txt 2>/dev/null || log "[WARNING] Root bash history not found"
docker exec "$CONTAINER_NAME" cat /home/webadmin/.bash_history > webadmin_bash_history.txt 2>/dev/null || log "[WARNING] Webadmin bash history not found"

# 16. SSH keys
log "  [5.2] Collecting SSH keys..."
docker exec "$CONTAINER_NAME" find /home -name "authorized_keys" -exec cat {} \; > ssh_authorized_keys.txt 2>/dev/null || log "[WARNING] No SSH authorized keys found"
docker exec "$CONTAINER_NAME" find /root -name "authorized_keys" -exec cat {} \; >> ssh_authorized_keys.txt 2>/dev/null || log "[WARNING] No root SSH authorized keys found"

# 17. Cron jobs
log "  [5.3] Collecting cron jobs..."
docker exec "$CONTAINER_NAME" cat /etc/crontab > crontab.txt 2>/dev/null || log "[ERROR] Failed to collect crontab"
docker exec "$CONTAINER_NAME" ls -la /etc/cron.d/ > cron_d_files.txt 2>/dev/null || log "[WARNING] No cron.d files found"

log "[+] Phase 6: Web Application Analysis"

# 18. Web files
log "  [6.1] Collecting web application files..."
docker exec "$CONTAINER_NAME" find /var/www/html -type f -name "*.php" -exec ls -la {} \; > web_php_files.txt 2>/dev/null || log "[WARNING] No PHP files found"
docker exec "$CONTAINER_NAME" find /var/www/html -name ".*" -type f > hidden_web_files.txt 2>/dev/null || log "[WARNING] No hidden web files found"

# 19. Web shells detection
log "  [6.2] Detecting potential web shells..."
docker exec "$CONTAINER_NAME" find /var/www/html -name "*.php" -exec grep -l "system\|exec\|shell_exec\|passthru" {} \; > potential_webshells.txt 2>/dev/null || log "[WARNING] No potential web shells found"

log "[+] Phase 7: Malware Analysis"

# 20. Suspicious processes
log "  [7.1] Analyzing suspicious processes..."
docker exec "$CONTAINER_NAME" ps aux | grep -E "(nc|netcat|wget|curl|python.*http)" > suspicious_processes.txt 2>/dev/null || log "[WARNING] No suspicious processes found"

# 21. Network listeners
log "  [7.2] Analyzing network listeners..."
docker exec "$CONTAINER_NAME" netstat -tulpn | grep -E ":(4444|1337|31337|8080)" > suspicious_listeners.txt 2>/dev/null || log "[WARNING] No suspicious listeners found"

log "[+] Evidence Collection Complete!"
log "========================================="
log "Total files collected: $(find . -type f | wc -l)"
log "Evidence directory: $EVIDENCE_DIR/$CASE_ID"
log "Investigation End: $(date)"

# Generate summary
echo "Evidence Collection Summary" > collection_summary.txt
echo "===========================" >> collection_summary.txt
echo "Case ID: $CASE_ID" >> collection_summary.txt
echo "Container: $CONTAINER_NAME" >> collection_summary.txt
echo "Collection Time: $(date)" >> collection_summary.txt
echo "Files Collected: $(find . -type f | wc -l)" >> collection_summary.txt
echo "" >> collection_summary.txt
echo "Files:" >> collection_summary.txt
ls -la >> collection_summary.txt

echo ""
echo "Evidence collection completed successfully!"
echo "Evidence stored in: $EVIDENCE_DIR/$CASE_ID"
echo "Review collection_summary.txt for details"