#!/bin/bash

# Digital Forensics Investigation Script
# For Ubuntu Container Analysis

set -e

EVIDENCE_DIR="/forensics/evidence"
CASE_ID="CASE_$(date +%Y%m%d_%H%M%S)"
CONTAINER_NAME="$1"

if [ -z "$CONTAINER_NAME" ]; then
    echo "Usage: $0 <container_name>"
    exit 1
fi

echo "=== Digital Forensics Investigation ==="
echo "Case ID: $CASE_ID"
echo "Target Container: $CONTAINER_NAME"
echo "Investigation Start: $(date)"
echo "========================================="

# Create case directory
mkdir -p "$EVIDENCE_DIR/$CASE_ID"
cd "$EVIDENCE_DIR/$CASE_ID"

echo "[+] Phase 1: Volatile Data Collection"

# 1. Container metadata
echo "  [1.1] Collecting container metadata..."
docker inspect "$CONTAINER_NAME" > container_metadata.json

# 2. Running processes
echo "  [1.2] Collecting process information..."
docker exec "$CONTAINER_NAME" ps aux > running_processes.txt
docker exec "$CONTAINER_NAME" ps -ef > process_tree.txt

# 3. Network connections
echo "  [1.3] Collecting network information..."
docker exec "$CONTAINER_NAME" netstat -tulpn > network_connections.txt
docker exec "$CONTAINER_NAME" ss -tulpn > socket_statistics.txt

# 4. Open files
echo "  [1.4] Collecting open files..."
docker exec "$CONTAINER_NAME" lsof > open_files.txt 2>/dev/null || echo "lsof not available"

# 5. Memory information
echo "  [1.5] Collecting memory information..."
docker exec "$CONTAINER_NAME" cat /proc/meminfo > memory_info.txt
docker exec "$CONTAINER_NAME" cat /proc/modules > loaded_modules.txt

echo "[+] Phase 2: System Configuration Analysis"

# 6. User accounts
echo "  [2.1] Analyzing user accounts..."
docker exec "$CONTAINER_NAME" cat /etc/passwd > passwd_file.txt
docker exec "$CONTAINER_NAME" cat /etc/shadow > shadow_file.txt 2>/dev/null || echo "Shadow file access denied"
docker exec "$CONTAINER_NAME" cat /etc/group > group_file.txt

# 7. Sudo configuration
echo "  [2.2] Checking sudo configuration..."
docker exec "$CONTAINER_NAME" cat /etc/sudoers > sudoers_file.txt 2>/dev/null || echo "Sudoers access denied"

# 8. SSH configuration
echo "  [2.3] Analyzing SSH configuration..."
docker exec "$CONTAINER_NAME" cat /etc/ssh/sshd_config > sshd_config.txt 2>/dev/null || echo "SSH config not found"

# 9. Cron jobs
echo "  [2.4] Collecting scheduled tasks..."
docker exec "$CONTAINER_NAME" cat /etc/crontab > system_crontab.txt 2>/dev/null || echo "Crontab not found"
docker exec "$CONTAINER_NAME" ls -la /etc/cron.d/ > cron_d_listing.txt 2>/dev/null || echo "Cron.d not found"

echo "[+] Phase 3: Log File Analysis"

# 10. System logs
echo "  [3.1] Collecting system logs..."
docker exec "$CONTAINER_NAME" cat /var/log/syslog > syslog.txt 2>/dev/null || echo "Syslog not found"
docker exec "$CONTAINER_NAME" cat /var/log/auth.log > auth_log.txt 2>/dev/null || echo "Auth log not found"
docker exec "$CONTAINER_NAME" cat /var/log/kern.log > kernel_log.txt 2>/dev/null || echo "Kernel log not found"

# 11. Web server logs
echo "  [3.2] Collecting web server logs..."
docker exec "$CONTAINER_NAME" cat /var/log/nginx/access.log > nginx_access.log 2>/dev/null || echo "Nginx access log not found"
docker exec "$CONTAINER_NAME" cat /var/log/nginx/error.log > nginx_error.log 2>/dev/null || echo "Nginx error log not found"

echo "[+] Phase 4: File System Analysis"

# 12. File system structure
echo "  [4.1] Analyzing file system structure..."
docker exec "$CONTAINER_NAME" find / -type f -name ".*" 2>/dev/null > hidden_files.txt || echo "Hidden files search completed with errors"
docker exec "$CONTAINER_NAME" find /tmp -type f 2>/dev/null > tmp_files.txt || echo "Tmp files search completed"

# 13. Recently modified files
echo "  [4.2] Finding recently modified files..."
docker exec "$CONTAINER_NAME" find / -type f -mtime -1 2>/dev/null > recent_files_1day.txt || echo "Recent files search completed"
docker exec "$CONTAINER_NAME" find / -type f -mtime -7 2>/dev/null > recent_files_7days.txt || echo "Weekly files search completed"

# 14. SUID/SGID files
echo "  [4.3] Collecting SUID/SGID files..."
docker exec "$CONTAINER_NAME" find / -type f -perm -4000 2>/dev/null > suid_files.txt || echo "SUID search completed"
docker exec "$CONTAINER_NAME" find / -type f -perm -2000 2>/dev/null > sgid_files.txt || echo "SGID search completed"

echo "[+] Phase 5: User Activity Analysis"

# 15. Command history
echo "  [5.1] Collecting command history..."
docker exec "$CONTAINER_NAME" cat /root/.bash_history > root_bash_history.txt 2>/dev/null || echo "Root history not found"
docker exec "$CONTAINER_NAME" cat /home/webadmin/.bash_history > webadmin_bash_history.txt 2>/dev/null || echo "Webadmin history not found"

# 16. SSH keys
echo "  [5.2] Collecting SSH keys..."
docker exec "$CONTAINER_NAME" find /home -name ".ssh" -type d 2>/dev/null > ssh_directories.txt || echo "SSH directory search completed"
docker exec "$CONTAINER_NAME" find / -name "authorized_keys" 2>/dev/null > authorized_keys_files.txt || echo "Authorized keys search completed"

echo "[+] Phase 6: Network and Communication Analysis"

# 17. Host file analysis
echo "  [6.1] Analyzing hosts file..."
docker exec "$CONTAINER_NAME" cat /etc/hosts > hosts_file.txt

# 18. DNS configuration
echo "  [6.2] Collecting DNS configuration..."
docker exec "$CONTAINER_NAME" cat /etc/resolv.conf > resolv_conf.txt

echo "[+] Phase 7: Web Application Analysis"

# 19. Web files
echo "  [7.1] Analyzing web files..."
docker exec "$CONTAINER_NAME" find /var/www -type f -name "*.php" 2>/dev/null > php_files.txt || echo "PHP files search completed"
docker exec "$CONTAINER_NAME" ls -la /var/www/html/ > web_directory_listing.txt 2>/dev/null || echo "Web directory listing completed"

echo "[+] Investigation Complete!"
echo "Evidence collected in: $EVIDENCE_DIR/$CASE_ID"
echo "Case ID: $CASE_ID"
echo "========================================="

# Create investigation summary
cat << EOF > investigation_summary.txt
Digital Forensics Investigation Summary
======================================
Case ID: $CASE_ID
Target: Container $CONTAINER_NAME
Investigation Date: $(date)
Investigator: Digital Forensics Expert

Files Collected:
- Volatile data (processes, network, memory)
- System configuration files
- Log files (system, auth, web server)
- File system artifacts
- User activity traces
- Network configuration
- Web application files

Next Steps:
1. Analyze collected evidence
2. Identify Indicators of Compromise (IoCs)
3. Create timeline of events
4. Generate formal report
EOF

echo "Summary created: investigation_summary.txt"