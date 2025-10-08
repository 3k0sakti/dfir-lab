#!/bin/bash

# Evidence Analysis Script
# Analyzes collected forensic evidence and identifies IoCs

set -e

EVIDENCE_DIR="$1"

if [ -z "$EVIDENCE_DIR" ]; then
    echo "Usage: $0 <evidence_directory>"
    exit 1
fi

if [ ! -d "$EVIDENCE_DIR" ]; then
    echo "Evidence directory not found: $EVIDENCE_DIR"
    exit 1
fi

cd "$EVIDENCE_DIR"

echo "=== Forensic Evidence Analysis ==="
echo "Evidence Directory: $EVIDENCE_DIR"
echo "Analysis Start: $(date)"
echo "=================================="

# Create analysis results file
ANALYSIS_FILE="analysis_results.txt"
IOC_FILE="indicators_of_compromise.txt"

echo "FORENSIC ANALYSIS RESULTS" > "$ANALYSIS_FILE"
echo "=========================" >> "$ANALYSIS_FILE"
echo "Analysis Date: $(date)" >> "$ANALYSIS_FILE"
echo "" >> "$ANALYSIS_FILE"

echo "INDICATORS OF COMPROMISE (IoCs)" > "$IOC_FILE"
echo "===============================" >> "$IOC_FILE"
echo "Analysis Date: $(date)" >> "$IOC_FILE"
echo "" >> "$IOC_FILE"

echo "[+] Phase 1: User Account Analysis"

if [ -f "passwd_file.txt" ]; then
    echo "  [1.1] Analyzing user accounts..."
    echo "USER ACCOUNT ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "---------------------" >> "$ANALYSIS_FILE"
    
    # Check for suspicious users
    suspicious_users=$(grep -E "(backdoor|hack|admin|test|temp)" passwd_file.txt 2>/dev/null || true)
    if [ ! -z "$suspicious_users" ]; then
        echo "SUSPICIOUS USERS FOUND:" >> "$ANALYSIS_FILE"
        echo "$suspicious_users" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
        
        echo "IOC: Suspicious user accounts detected" >> "$IOC_FILE"
        echo "$suspicious_users" >> "$IOC_FILE"
        echo "" >> "$IOC_FILE"
    fi
    
    # Check for UID 0 accounts (root privileges)
    root_accounts=$(awk -F: '$3 == 0 {print $1}' passwd_file.txt)
    echo "ACCOUNTS WITH ROOT PRIVILEGES (UID 0):" >> "$ANALYSIS_FILE"
    echo "$root_accounts" >> "$ANALYSIS_FILE"
    echo "" >> "$ANALYSIS_FILE"
fi

echo "[+] Phase 2: Process Analysis"

if [ -f "running_processes.txt" ]; then
    echo "  [2.1] Analyzing running processes..."
    echo "PROCESS ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "----------------" >> "$ANALYSIS_FILE"
    
    # Look for suspicious processes
    suspicious_procs=$(grep -iE "(nc|netcat|wget|curl|python|perl|bash.*tmp|sh.*tmp)" running_processes.txt 2>/dev/null || true)
    if [ ! -z "$suspicious_procs" ]; then
        echo "SUSPICIOUS PROCESSES:" >> "$ANALYSIS_FILE"
        echo "$suspicious_procs" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
        
        echo "IOC: Suspicious processes detected" >> "$IOC_FILE"
        echo "$suspicious_procs" >> "$IOC_FILE"
        echo "" >> "$IOC_FILE"
    fi
fi

echo "[+] Phase 3: Network Analysis"

if [ -f "network_connections.txt" ]; then
    echo "  [3.1] Analyzing network connections..."
    echo "NETWORK CONNECTIONS ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "----------------------------" >> "$ANALYSIS_FILE"
    
    # Look for unusual ports
    unusual_ports=$(grep -E ":(4444|1337|31337|8080|9999)" network_connections.txt 2>/dev/null || true)
    if [ ! -z "$unusual_ports" ]; then
        echo "UNUSUAL NETWORK PORTS:" >> "$ANALYSIS_FILE"
        echo "$unusual_ports" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
        
        echo "IOC: Unusual network ports detected" >> "$IOC_FILE"
        echo "$unusual_ports" >> "$IOC_FILE"
        echo "" >> "$IOC_FILE"
    fi
fi

echo "[+] Phase 4: File System Analysis"

if [ -f "hidden_files.txt" ]; then
    echo "  [4.1] Analyzing hidden files..."
    echo "HIDDEN FILES ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "---------------------" >> "$ANALYSIS_FILE"
    
    # Look for suspicious hidden files
    suspicious_hidden=$(grep -iE "(backdoor|hack|malware|payload|shell)" hidden_files.txt 2>/dev/null || true)
    if [ ! -z "$suspicious_hidden" ]; then
        echo "SUSPICIOUS HIDDEN FILES:" >> "$ANALYSIS_FILE"
        echo "$suspicious_hidden" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
        
        echo "IOC: Suspicious hidden files detected" >> "$IOC_FILE"
        echo "$suspicious_hidden" >> "$IOC_FILE"
        echo "" >> "$IOC_FILE"
    fi
fi

if [ -f "tmp_files.txt" ]; then
    echo "  [4.2] Analyzing temporary files..."
    echo "TEMPORARY FILES ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "------------------------" >> "$ANALYSIS_FILE"
    
    # Look for suspicious files in /tmp
    suspicious_tmp=$(grep -iE "(system_update|backdoor|payload|\.hidden)" tmp_files.txt 2>/dev/null || true)
    if [ ! -z "$suspicious_tmp" ]; then
        echo "SUSPICIOUS TEMPORARY FILES:" >> "$ANALYSIS_FILE"
        echo "$suspicious_tmp" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
        
        echo "IOC: Suspicious temporary files detected" >> "$IOC_FILE"
        echo "$suspicious_tmp" >> "$IOC_FILE"
        echo "" >> "$IOC_FILE"
    fi
fi

echo "[+] Phase 5: Web Application Analysis"

if [ -f "php_files.txt" ]; then
    echo "  [5.1] Analyzing web files..."
    echo "WEB APPLICATION ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "------------------------" >> "$ANALYSIS_FILE"
    
    # Look for potential web shells
    webshells=$(grep -iE "(admin_panel|shell|cmd|eval|exec)" php_files.txt 2>/dev/null || true)
    if [ ! -z "$webshells" ]; then
        echo "POTENTIAL WEB SHELLS:" >> "$ANALYSIS_FILE"
        echo "$webshells" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
        
        echo "IOC: Potential web shells detected" >> "$IOC_FILE"
        echo "$webshells" >> "$IOC_FILE"
        echo "" >> "$IOC_FILE"
    fi
fi

echo "[+] Phase 6: Log Analysis"

if [ -f "auth_log.txt" ]; then
    echo "  [6.1] Analyzing authentication logs..."
    echo "AUTHENTICATION LOG ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "---------------------------" >> "$ANALYSIS_FILE"
    
    # Look for failed login attempts
    failed_logins=$(grep -i "failed" auth_log.txt 2>/dev/null | head -10 || true)
    if [ ! -z "$failed_logins" ]; then
        echo "FAILED LOGIN ATTEMPTS (sample):" >> "$ANALYSIS_FILE"
        echo "$failed_logins" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
    fi
    
    # Look for privilege escalation
    priv_esc=$(grep -i "sudo" auth_log.txt 2>/dev/null | head -10 || true)
    if [ ! -z "$priv_esc" ]; then
        echo "SUDO USAGE:" >> "$ANALYSIS_FILE"
        echo "$priv_esc" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
    fi
fi

echo "[+] Phase 7: Command History Analysis"

if [ -f "root_bash_history.txt" ]; then
    echo "  [7.1] Analyzing root command history..."
    echo "ROOT COMMAND HISTORY ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "-----------------------------" >> "$ANALYSIS_FILE"
    
    # Look for suspicious commands
    suspicious_cmds=$(grep -iE "(wget|curl|nc|netcat|python.*http|chmod.*x|rm.*log)" root_bash_history.txt 2>/dev/null || true)
    if [ ! -z "$suspicious_cmds" ]; then
        echo "SUSPICIOUS COMMANDS IN ROOT HISTORY:" >> "$ANALYSIS_FILE"
        echo "$suspicious_cmds" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
        
        echo "IOC: Suspicious commands in root history" >> "$IOC_FILE"
        echo "$suspicious_cmds" >> "$IOC_FILE"
        echo "" >> "$IOC_FILE"
    fi
fi

if [ -f "webadmin_bash_history.txt" ]; then
    echo "  [7.2] Analyzing webadmin command history..."
    echo "WEBADMIN COMMAND HISTORY ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "---------------------------------" >> "$ANALYSIS_FILE"
    
    # Look for suspicious commands
    suspicious_web_cmds=$(grep -iE "(wget|curl|payload|exfil|history.*c)" webadmin_bash_history.txt 2>/dev/null || true)
    if [ ! -z "$suspicious_web_cmds" ]; then
        echo "SUSPICIOUS COMMANDS IN WEBADMIN HISTORY:" >> "$ANALYSIS_FILE"
        echo "$suspicious_web_cmds" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
        
        echo "IOC: Suspicious commands in webadmin history" >> "$IOC_FILE"
        echo "$suspicious_web_cmds" >> "$IOC_FILE"
        echo "" >> "$IOC_FILE"
    fi
fi

echo "[+] Phase 8: System Configuration Analysis"

if [ -f "system_crontab.txt" ]; then
    echo "  [8.1] Analyzing cron jobs..."
    echo "CRON JOBS ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "------------------" >> "$ANALYSIS_FILE"
    
    # Look for suspicious cron jobs
    suspicious_cron=$(grep -iE "(system_update|backdoor|nc|netcat|wget|curl|health-monitor)" system_crontab.txt 2>/dev/null || true)
    if [ ! -z "$suspicious_cron" ]; then
        echo "SUSPICIOUS CRON JOBS:" >> "$ANALYSIS_FILE"
        echo "$suspicious_cron" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
        
        echo "IOC: Suspicious cron jobs detected" >> "$IOC_FILE"
        echo "$suspicious_cron" >> "$IOC_FILE"
        echo "" >> "$IOC_FILE"
    fi
fi

if [ -f "hosts_file.txt" ]; then
    echo "  [8.2] Analyzing hosts file..."
    echo "HOSTS FILE ANALYSIS:" >> "$ANALYSIS_FILE"
    echo "-------------------" >> "$ANALYSIS_FILE"
    
    # Look for suspicious host entries
    suspicious_hosts=$(grep -vE "^(127.0.0.1|::1|#)" hosts_file.txt 2>/dev/null || true)
    if [ ! -z "$suspicious_hosts" ]; then
        echo "CUSTOM HOST ENTRIES:" >> "$ANALYSIS_FILE"
        echo "$suspicious_hosts" >> "$ANALYSIS_FILE"
        echo "" >> "$ANALYSIS_FILE"
        
        echo "IOC: Custom host entries detected" >> "$IOC_FILE"
        echo "$suspicious_hosts" >> "$IOC_FILE"
        echo "" >> "$IOC_FILE"
    fi
fi

echo "[+] Phase 9: Advanced Threat Detection"

# APT Detection
echo "  [9.1] Analyzing APT indicators..."
echo "APT THREAT ANALYSIS:" >> "$ANALYSIS_FILE"
echo "-------------------" >> "$ANALYSIS_FILE"

# Look for APT-style artifacts
apt_indicators=$(grep -riE "(silent dragon|operation shadow|system-analytics|update-manager)" . 2>/dev/null || true)
if [ ! -z "$apt_indicators" ]; then
    echo "APT CAMPAIGN INDICATORS:" >> "$ANALYSIS_FILE"
    echo "$apt_indicators" >> "$ANALYSIS_FILE"
    echo "" >> "$ANALYSIS_FILE"
    
    echo "IOC: APT campaign artifacts detected" >> "$IOC_FILE"
    echo "$apt_indicators" >> "$IOC_FILE"
    echo "" >> "$IOC_FILE"
fi

# Ransomware Detection
echo "  [9.2] Analyzing ransomware indicators..."
echo "RANSOMWARE ANALYSIS:" >> "$ANALYSIS_FILE"
echo "------------------" >> "$ANALYSIS_FILE"

ransomware_indicators=$(grep -riE "(cryptovault|darkmoney|decrypt|ransom|\.locked|bitcoin)" . 2>/dev/null || true)
if [ ! -z "$ransomware_indicators" ]; then
    echo "RANSOMWARE INDICATORS:" >> "$ANALYSIS_FILE"
    echo "$ransomware_indicators" >> "$ANALYSIS_FILE"
    echo "" >> "$ANALYSIS_FILE"
    
    echo "IOC: Ransomware activity detected" >> "$IOC_FILE"
    echo "$ransomware_indicators" >> "$IOC_FILE"
    echo "" >> "$IOC_FILE"
fi

# Insider Threat Detection
echo "  [9.3] Analyzing insider threat indicators..."
echo "INSIDER THREAT ANALYSIS:" >> "$ANALYSIS_FILE"
echo "------------------------" >> "$ANALYSIS_FILE"

insider_indicators=$(grep -riE "(after.hours|usb|exfiltrat|competitor|fraud)" . 2>/dev/null || true)
if [ ! -z "$insider_indicators" ]; then
    echo "INSIDER THREAT INDICATORS:" >> "$ANALYSIS_FILE"
    echo "$insider_indicators" >> "$ANALYSIS_FILE"
    echo "" >> "$ANALYSIS_FILE"
    
    echo "IOC: Insider threat activity detected" >> "$IOC_FILE"
    echo "$insider_indicators" >> "$IOC_FILE"
    echo "" >> "$IOC_FILE"
fi

# Web Attack Detection
echo "  [9.4] Analyzing web application attacks..."
echo "WEB APPLICATION ATTACK ANALYSIS:" >> "$ANALYSIS_FILE"
echo "-------------------------------" >> "$ANALYSIS_FILE"

web_attack_indicators=$(grep -riE "(sql injection|xss|shell\.php|\.htaccess.*php|uploads.*php)" . 2>/dev/null || true)
if [ ! -z "$web_attack_indicators" ]; then
    echo "WEB ATTACK INDICATORS:" >> "$ANALYSIS_FILE"
    echo "$web_attack_indicators" >> "$ANALYSIS_FILE"
    echo "" >> "$ANALYSIS_FILE"
    
    echo "IOC: Web application attack detected" >> "$IOC_FILE"
    echo "$web_attack_indicators" >> "$IOC_FILE"
    echo "" >> "$IOC_FILE"
fi

echo "[+] Phase 10: Cryptocurrency Mining Detection"

# Crypto Mining Detection
echo "  [10.1] Analyzing cryptocurrency mining indicators..."
echo "CRYPTOCURRENCY MINING ANALYSIS:" >> "$ANALYSIS_FILE"
echo "------------------------------" >> "$ANALYSIS_FILE"

crypto_indicators=$(grep -riE "(xmrig|cpuminer|cgminer|mining|pool|optimizer|miner)" . 2>/dev/null || true)
if [ ! -z "$crypto_indicators" ]; then
    echo "CRYPTO MINING INDICATORS:" >> "$ANALYSIS_FILE"
    echo "$crypto_indicators" >> "$ANALYSIS_FILE"
    echo "" >> "$ANALYSIS_FILE"
    
    echo "IOC: Cryptocurrency mining activity detected" >> "$IOC_FILE"
    echo "$crypto_indicators" >> "$IOC_FILE"
    echo "" >> "$IOC_FILE"
fi

echo "[+] Analysis Complete!"
echo ""
echo "Results saved to:"
echo "  - $ANALYSIS_FILE"
echo "  - $IOC_FILE"
echo ""

# Display summary of IoCs found
ioc_count=$(grep -c "IOC:" "$IOC_FILE" 2>/dev/null || echo "0")
echo "Total Indicators of Compromise found: $ioc_count"

if [ "$ioc_count" -gt 0 ]; then
    echo ""
    echo "CRITICAL: System shows signs of compromise!"
    echo "Review the IoC file for detailed findings."
else
    echo ""
    echo "No obvious indicators of compromise detected."
    echo "However, perform additional analysis as needed."
fi

echo "=================================="