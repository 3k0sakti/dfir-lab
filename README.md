# Digital Forensics Investigation Lab

A comprehensive digital forensics investigation lab for analyzing compromised Ubuntu containers using Docker. This lab simulates real-world incident response scenarios and teaches hands-on digital forensics techniques.

## 🎯 Learning Objectives

- Understand digital forensics methodology and best practices
- Learn to identify Indicators of Compromise (IoCs) in Linux systems
- Practice evidence collection and preservation techniques
- Develop skills in log analysis and timeline reconstruction
- Experience the complete forensic investigation workflow
- Learn to document findings in professional forensic reports

## 🏗️ Lab Architecture

```
forensics/lab/
├── Dockerfile.compromised     # Ubuntu container with pre-configured services
├── start-services.sh         # Container startup script
├── compromise.sh             # Compromise simulation script
├── forensic_collector.sh     # Evidence collection script
├── evidence_analyzer.sh      # IoC analysis script
├── timeline_analyzer.sh      # Timeline reconstruction script
├── memory_forensics.sh       # Memory artifact analysis
├── network_forensics.sh      # Network artifact analysis
├── report_generator.sh       # Forensic report generator
├── master_investigation.sh   # Main orchestration script
└── README.md                # This file

evidence/                     # Collected forensic evidence
reports/                     # Generated forensic reports
```

## 🚀 Quick Start

### Prerequisites

- Docker installed and running
- macOS/Linux/WSL environment
- Bash shell
- At least 2GB free disk space

### Run Complete Investigation

```bash
# Navigate to the lab directory
cd /Users/ekosakti/Code/forensics/lab

# Make scripts executable
chmod +x *.sh

# Run the complete investigation with all scenarios
./master_investigation.sh
```

This will:
1. Build and start a compromised Ubuntu container
2. Simulate multiple advanced attack scenarios including:
   - APT (Advanced Persistent Threat) campaign
   - Ransomware attack with double extortion
   - Insider threat with data theft and sabotage
   - Web application compromise
   - Cryptocurrency mining
3. Collect comprehensive forensic evidence
4. Analyze findings for IoCs using MITRE ATT&CK framework
5. Generate a professional forensic report

### Quick Scenario Selection

```bash
# Interactive scenario selector
./scenario_selector.sh

# Run specific scenario
./scenario_selector.sh apt          # APT simulation
./scenario_selector.sh ransomware   # Ransomware attack
./scenario_selector.sh insider      # Insider threat
./scenario_selector.sh webapp       # Web application attack
./scenario_selector.sh combined     # All scenarios
```

## 🎯 Real-World Attack Scenarios

The lab now includes sophisticated, realistic attack scenarios based on actual threat intelligence:

### 1. APT (Advanced Persistent Threat) Campaign
**Scenario**: Nation-state style attack by "Silent Dragon" group
- **Initial Access**: Spear phishing with malicious attachments
- **Persistence**: SSH keys, systemd services, cron jobs
- **Lateral Movement**: WMI execution, credential dumping
- **Data Exfiltration**: DNS tunneling, encrypted channels
- **TTPs**: T1566.001, T1543.002, T1021.001, T1048.003

### 2. Ransomware Attack Simulation
**Scenario**: "CryptoVault" ransomware by DarkMoney Gang
- **Initial Access**: RDP brute force attack
- **Privilege Escalation**: SUID exploitation, sudo abuse
- **Data Theft**: Double extortion before encryption
- **Impact**: File encryption, shadow copy deletion
- **TTPs**: T1110.001, T1486, T1490, T1041

### 3. Insider Threat Simulation
**Scenario**: Database administrator with legitimate access abuse
- **Activities**: After-hours data theft, financial fraud
- **Methods**: USB exfiltration, email data sharing
- **Sabotage**: Database manipulation, log tampering
- **Anti-Forensics**: Evidence destruction, timestomping
- **TTPs**: T1078, T1052.001, T1565, T1070

### 4. Web Application Attack
**Scenario**: Multi-stage web application compromise
- **Exploitation**: SQL injection, XSS, file upload bypass
- **Persistence**: Web shells, configuration backdoors
- **Data Access**: Database dumping, API exploitation
- **Exfiltration**: HTTP POST, stolen session tokens
- **TTPs**: T1190, T1505.003, T1041, T1552.001

### 5. MITRE ATT&CK Framework Implementation
**Comprehensive TTP Coverage**:
- **18 different techniques** across 8 major tactics
- **Real attack chain simulation** from initial access to impact
- **Forensic artifact generation** for each technique
- **Complete attack lifecycle** modeling

```bash
# Run specific attack framework
./scenarios/mitre_attack_framework.sh full

# Execute individual techniques
./scenarios/mitre_attack_framework.sh technique T1566.001
```

### Step 1: Environment Setup

```bash
# Build the compromised container
./master_investigation.sh setup
```

**What happens:**
- Creates Ubuntu 22.04 container with SSH, Nginx, and common services
- Sets up legitimate user accounts (webadmin, dbuser)
- Configures logging and cron services
- Exposes ports 2222 (SSH) and 8080 (HTTP)

### Step 2: Compromise Simulation

```bash
# Simulate system compromise
./master_investigation.sh compromise
```

**Attack vectors simulated:**
- **Privilege Escalation**: Creates backdoor user with sudo access
- **Persistence**: Installs malicious cron job
- **Malware**: Drops fake system updater binary
- **Data Exfiltration**: Creates hidden directories with sensitive data
- **Web Shell**: Installs PHP-based command execution backdoor
- **Anti-Forensics**: Modifies bash history to hide tracks
- **System Tampering**: Modifies /etc/passwd and /etc/hosts

### Step 3: Evidence Collection

```bash
# Collect forensic evidence
./master_investigation.sh collect
```

**Evidence collected:**
- **Volatile Data**: Running processes, network connections, memory info
- **System Config**: User accounts, sudo config, SSH settings
- **Logs**: System logs, authentication logs, web server logs
- **File System**: Recent files, hidden files, SUID/SGID files
- **User Activity**: Command history, SSH keys
- **Network**: Host file, DNS config, routing tables

### Step 4: Evidence Analysis

```bash
# Analyze collected evidence
./master_investigation.sh analyze
```

**Analysis performed:**
- **User Account Analysis**: Detects unauthorized accounts
- **Process Analysis**: Identifies suspicious running processes
- **Network Analysis**: Finds unusual network connections
- **File System Analysis**: Locates malicious files and directories
- **Log Analysis**: Correlates events across multiple log sources
- **Timeline Reconstruction**: Creates chronological event sequence

### Step 5: Report Generation

```bash
# Generate forensic report
./master_investigation.sh report
```

**Report includes:**
- Executive summary of findings
- Technical analysis details
- Indicators of Compromise (IoCs)
- Attack timeline reconstruction
- Recommendations for remediation
- Evidence preservation documentation

## 🔍 Manual Investigation Techniques

### Memory Forensics

```bash
# Analyze memory artifacts
./memory_forensics.sh compromised-ubuntu ./evidence/memory/

# Key artifacts examined:
# - Process memory maps
# - Command line arguments
# - Environment variables
# - Open file descriptors
# - Kernel ring buffer
```

### Network Forensics

```bash
# Analyze network artifacts
./network_forensics.sh compromised-ubuntu ./evidence/network/

# Key artifacts examined:
# - Active network connections
# - Listening services
# - Routing tables
# - ARP tables
# - DNS configuration
# - Firewall rules
```

### Live Analysis Commands

```bash
# Connect to running container for live analysis
docker exec -it compromised-ubuntu bash

# Examine running processes
ps aux | grep -E "(nc|wget|curl|python)"

# Check network connections
netstat -tulpn | grep -E ":(4444|1337|31337)"

# Look for suspicious files
find /tmp -type f -name ".*" -o -name "*update*"

# Check recent file modifications
find / -type f -mtime -1 2>/dev/null | head -20

# Examine user accounts
grep -E "(backdoor|hack)" /etc/passwd

# Check cron jobs
cat /etc/crontab | grep -v "^#"

# Analyze command history
tail -20 /root/.bash_history
tail -20 /home/webadmin/.bash_history
```

## 🎯 Key Indicators of Compromise (IoCs)

The lab is designed to generate the following IoCs:

### User Account IoCs
- Unauthorized user: `backdoor_user`
- UID 0 account with suspicious name
- Accounts with NOPASSWD sudo access

### Process IoCs
- Suspicious binary: `/usr/bin/system_update`
- Netcat listeners on unusual ports
- Processes running from /tmp directory

### File System IoCs
- Hidden directory: `/tmp/.hidden/`
- Web shell: `/var/www/html/admin_panel.php`
- Modified system files: `/etc/passwd`, `/etc/hosts`

### Network IoCs
- Listening on port 4444 (common backdoor port)
- Custom DNS entries in /etc/hosts
- Unusual outbound connections

### Persistence IoCs
- Malicious cron job executing system_update
- SSH key modifications
- Service configuration changes

## 📊 Understanding the Results

### Evidence Analysis Output

The `evidence_analyzer.sh` script produces several key files:

1. **analysis_results.txt**: Detailed technical analysis
2. **indicators_of_compromise.txt**: List of detected IoCs
3. **timeline_analysis.txt**: Chronological event reconstruction

### Typical IoC Output Example

```
IOC: Suspicious user accounts detected
backdoor_user:x:1001:1001::/home/backdoor_user:/bin/bash

IOC: Suspicious processes detected
/usr/bin/system_update

IOC: Potential web shells detected
/var/www/html/admin_panel.php

IOC: Suspicious cron jobs detected
*/10 * * * * root /usr/bin/system_update >/dev/null 2>&1
```

## 🛠️ Advanced Analysis Techniques

### Hash Analysis

```bash
# Calculate file hashes for integrity
find evidence/ -type f -exec sha256sum {} \; > evidence_hashes.txt

# Verify evidence integrity
sha256sum -c evidence_hashes.txt
```

### Log Correlation

```bash
# Correlate authentication events with process creation
grep "sudo" evidence/auth_log.txt | while read line; do
    timestamp=$(echo "$line" | awk '{print $1, $2, $3}')
    echo "Auth event: $timestamp"
    grep "$timestamp" evidence/syslog.txt | head -3
done
```

### File Carving

```bash
# Extract strings from suspicious binaries
docker exec compromised-ubuntu strings /usr/bin/system_update > system_update_strings.txt

# Look for embedded IP addresses or domains
grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" system_update_strings.txt
```

## 🔒 Forensic Best Practices Demonstrated

### Evidence Preservation
- **Read-only access**: Evidence collection without modification
- **Hash verification**: Cryptographic integrity validation
- **Chain of custody**: Documented evidence handling
- **Timestamping**: Accurate temporal correlation

### Analysis Methodology
- **Systematic approach**: Following established forensic procedures
- **Documentation**: Comprehensive logging of all actions
- **Reproducibility**: Ability to repeat analysis steps
- **Correlation**: Cross-referencing multiple evidence sources

## 📈 Learning Progression

### Beginner Level
1. Run the complete automated investigation
2. Review generated reports and IoCs
3. Understand the evidence collection process
4. Learn to identify common attack patterns

### Intermediate Level
1. Run individual investigation phases
2. Modify compromise scenarios
3. Practice manual evidence analysis
4. Create custom analysis scripts

### Advanced Level
1. Develop new compromise scenarios
2. Integrate additional forensic tools
3. Implement memory dump analysis
4. Create timeline analysis tools

## 🔧 Customization Options

### Adding New Compromise Scenarios

Edit `compromise.sh` to include additional attack vectors:

```bash
# Add rootkit simulation
echo 'alias ls="ls --hide=malware"' >> /root/.bashrc

# Add data encryption (ransomware simulation)
mkdir -p /tmp/encrypted
echo "Files encrypted by AttackerGroup" > /tmp/encrypted/ransom_note.txt

# Add keylogger simulation
cat << 'EOF' > /usr/bin/keylogger
#!/bin/bash
while true; do
    cat /dev/input/event* >> /tmp/.keylog 2>/dev/null &
    sleep 60
done
EOF
chmod +x /usr/bin/keylogger
```

### Adding Custom Analysis Rules

Extend `evidence_analyzer.sh` with new detection rules:

```bash
# Detect potential crypto mining
crypto_procs=$(grep -iE "(xmrig|cpuminer|cgminer)" running_processes.txt 2>/dev/null || true)
if [ ! -z "$crypto_procs" ]; then
    echo "IOC: Crypto mining processes detected" >> "$IOC_FILE"
    echo "$crypto_procs" >> "$IOC_FILE"
fi

# Detect unusual network traffic patterns
high_bandwidth=$(awk '$2 > 1000000 {print $1, $2}' network_device_stats.txt 2>/dev/null || true)
if [ ! -z "$high_bandwidth" ]; then
    echo "IOC: High bandwidth usage detected" >> "$IOC_FILE"
    echo "$high_bandwidth" >> "$IOC_FILE"
fi
```

## 🚨 Important Security Notes

⚠️ **Warning**: This lab contains simulated malware and attack tools. 

### Safety Precautions:
- **Isolated Environment**: Only run in containerized environments
- **No Production Use**: Never run on production systems
- **Network Isolation**: Consider running without network access
- **Clean Up**: Always run cleanup commands after investigation

### Ethical Considerations:
- Use only for educational purposes
- Do not apply techniques to systems you don't own
- Follow responsible disclosure for any real vulnerabilities found
- Respect privacy and legal boundaries

## 📚 Additional Resources

### Recommended Reading
- "File System Forensic Analysis" by Brian Carrier
- "The Art of Memory Forensics" by Michael Ligh et al.
- "Digital Forensics and Incident Response" by Gerard Johansen

### Professional Tools
- **Autopsy**: Open-source digital forensics platform
- **Volatility**: Memory forensics framework
- **Sleuth Kit**: File system analysis tools
- **YARA**: Malware identification and classification

### Online Resources
- SANS Digital Forensics courses
- NIST Computer Forensics guidelines
- OWASP Incident Response methodologies

## 🤝 Contributing

To enhance this lab:

1. **Add new compromise scenarios**
2. **Improve analysis algorithms**
3. **Create additional forensic tools**
4. **Enhance report generation**
5. **Add integration with professional tools**

## 📞 Support

For questions or issues:
- Review the generated log files in the evidence directory
- Check Docker logs: `docker logs compromised-ubuntu`
- Verify file permissions: `ls -la *.sh`
- Ensure Docker has sufficient resources allocated

## 🏆 Learning Outcomes

After completing this lab, you should be able to:

✅ **Understand digital forensics methodology**
✅ **Identify common attack patterns and IoCs**
✅ **Collect and preserve digital evidence**
✅ **Analyze system artifacts for signs of compromise**
✅ **Create professional forensic reports**
✅ **Apply forensic techniques to real-world scenarios**

---

**Remember**: Digital forensics is both an art and a science. This lab provides the foundation, but real-world investigations require experience, intuition, and continuous learning. Practice regularly and stay updated with the latest attack techniques and forensic methodologies.

Happy investigating! 🔍