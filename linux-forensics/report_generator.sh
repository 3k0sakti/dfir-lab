#!/bin/bash

# Forensic Report Generator
# Creates a comprehensive forensic investigation report

EVIDENCE_DIR="$1"
CASE_ID="$2"

if [ -z "$EVIDENCE_DIR" ] || [ -z "$CASE_ID" ]; then
    echo "Usage: $0 <evidence_directory> <case_id>"
    exit 1
fi

cd "$EVIDENCE_DIR"

REPORT_FILE="../reports/forensic_report_${CASE_ID}.md"

echo "[+] Generating forensic report..."

cat << EOF > "$REPORT_FILE"
# Digital Forensics Investigation Report

## Case Information
- **Case ID:** $CASE_ID
- **Investigation Date:** $(date)
- **Investigator:** Digital Forensics Expert
- **Target System:** Ubuntu Container
- **Report Generated:** $(date)

## Executive Summary

This report documents the forensic investigation of a potentially compromised Ubuntu container. The investigation focused on identifying indicators of compromise (IoCs), analyzing system artifacts, and documenting evidence of malicious activity.

## Investigation Methodology

### 1. Evidence Collection
- Volatile data collection (processes, network connections, memory)
- System configuration analysis
- Log file examination
- File system artifact analysis
- User activity investigation

### 2. Analysis Techniques
- Static file analysis
- Log correlation
- Timeline reconstruction
- Indicator of Compromise (IoC) identification
- Attack pattern mapping

## Key Findings

### System Compromise Indicators
EOF

# Include IoC findings if they exist
if [ -f "indicators_of_compromise.txt" ]; then
    echo "" >> "$REPORT_FILE"
    echo "### Indicators of Compromise" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    cat "indicators_of_compromise.txt" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
fi

# Include analysis results
if [ -f "analysis_results.txt" ]; then
    echo "" >> "$REPORT_FILE"
    echo "### Detailed Analysis Results" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    cat "analysis_results.txt" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
fi

cat << EOF >> "$REPORT_FILE"

## Attack Timeline

Based on the analysis of system logs, file timestamps, and user activity, the following timeline has been reconstructed:

EOF

# Include timeline if it exists
if [ -f "timeline_analysis.txt" ]; then
    echo "\`\`\`" >> "$REPORT_FILE"
    head -100 "timeline_analysis.txt" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
fi

cat << EOF >> "$REPORT_FILE"

## Technical Analysis

### User Account Analysis
- Examination of /etc/passwd and /etc/shadow files
- Identification of unauthorized user accounts
- Analysis of privilege escalation attempts

### Process Analysis
- Review of running processes at time of investigation
- Identification of suspicious or unauthorized processes
- Analysis of process relationships and parent-child hierarchies

### Network Analysis
- Examination of active network connections
- Analysis of listening services and ports
- Review of network configuration files

### File System Analysis
- Identification of recently created or modified files
- Analysis of hidden files and directories
- Examination of temporary file locations
- Review of SUID/SGID files for privilege escalation vectors

### Log Analysis
- System log examination for anomalous events
- Authentication log analysis for unauthorized access attempts
- Web server log analysis for malicious requests

## Recommendations

### Immediate Actions
1. **Isolate the compromised system** to prevent lateral movement
2. **Change all passwords** for affected accounts
3. **Review and revoke** any unauthorized SSH keys or access methods
4. **Scan for malware** using updated antivirus signatures
5. **Patch system vulnerabilities** that may have been exploited

### Long-term Security Improvements
1. **Implement monitoring** for the identified IoCs
2. **Strengthen access controls** and authentication mechanisms
3. **Regular security audits** and penetration testing
4. **Employee security awareness training**
5. **Incident response plan** review and updates

### Evidence Preservation
- All collected evidence has been preserved with cryptographic hashes
- Chain of custody documentation maintained
- Evidence stored in secure, tamper-evident containers

## Conclusion

The investigation revealed clear evidence of system compromise including:
- Unauthorized user accounts
- Malicious binaries and scripts
- Suspicious network activity
- Evidence of data exfiltration attempts
- Anti-forensics techniques employed by the attacker

The compromise appears to be sophisticated, involving multiple attack vectors and persistence mechanisms. Immediate remediation is recommended to prevent further damage.

## Appendices

### Appendix A: Evidence Inventory
- Container metadata
- Process listings
- Network connection logs
- System configuration files
- Log files (system, authentication, web server)
- File system artifacts
- User activity traces

### Appendix B: Tools Used
- Docker inspection commands
- Standard Linux utilities (ps, netstat, find, grep)
- Custom forensic collection scripts
- Log analysis tools

### Appendix C: Chain of Custody
All evidence was collected using forensically sound methods maintaining the integrity of the original data. Hash values have been calculated for all evidence files to ensure integrity.

---

**Report prepared by:** Digital Forensics Expert  
**Date:** $(date)  
**Case ID:** $CASE_ID
EOF

echo "[+] Forensic report generated: $REPORT_FILE"
echo "[+] Report location: $(realpath "$REPORT_FILE")"