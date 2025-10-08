# 🚀 QUICK START GUIDE - Digital Forensics Lab

## ⚡ SETUP CEPAT (5 MENIT)

```bash
# 1. Persiapan
cd /Users/ekosakti/Code/forensics/lab
chmod +x *.sh

# 2. Pilih scenario (pilih salah satu):
./scenario_selector.sh apt          # APT investigation
./scenario_selector.sh ransomware   # Ransomware investigation  
./scenario_selector.sh combined     # Semua scenario (6+ jam)

# 3. Collect evidence
./forensic_collector_fixed.sh compromised-ubuntu

# 4. Analyze evidence
./evidence_analyzer.sh ./evidence/CASE_*

# 5. Lihat hasil
cd evidence/CASE_*
cat indicators_of_compromise.txt
```

---

## 🎯 SCENARIO TUJUAN PEMBELAJARAN

### 🟢 LEVEL PEMULA: Basic Investigation
**Durasi**: 2-3 jam  
**Tujuan**: 
- ✅ Memahami Linux system forensics
- ✅ Belajar evidence collection
- ✅ Mengenal Docker forensics

**Command**:
```bash
./scenario_selector.sh basic
```

**Yang Dipelajari**:
- Basic Linux commands untuk forensics
- Evidence preservation techniques
- File system analysis
- Log file examination

---

### 🟡 LEVEL MENENGAH: Specialized Attacks

#### 🕵️ APT Investigation
**Durasi**: 3-4 jam  
**Tujuan**: Menganalisis serangan nation-state  

```bash
./scenario_selector.sh apt
```

**Fokus Learning**:
- **Persistence**: SSH keys, systemd services, cron jobs
- **C2 Communications**: update.system-analytics.com
- **Spear Phishing**: Email artifacts dan attachments
- **MITRE ATT&CK**: T1566.001, T1543.002, T1053.003

**Expected IoCs**:
- Silent Dragon APT group
- Operation Shadow Harvest
- SSH backdoor keys di authorized_keys
- Malicious systemd service: update-manager

#### 🔒 Ransomware Investigation  
**Durasi**: 3-4 jam  
**Tujuan**: Menganalisis crypto-ransomware dan mining

```bash
./scenario_selector.sh ransomware
```

**Fokus Learning**:
- **File Encryption**: *.locked files
- **Double Extortion**: Data theft before encryption
- **Cryptocurrency Mining**: XMRig processes
- **Anti-Forensics**: Shadow copy deletion

**Expected IoCs**:
- CryptoVault ransomware family
- DarkMoney Gang threat actor
- Bitcoin wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
- DECRYPT_INSTRUCTIONS.txt ransom note

#### 👤 Insider Threat Investigation
**Durasi**: 3-4 jam  
**Tujuan**: Mendeteksi abuse legitimate access

```bash
./scenario_selector.sh insider
```

**Fokus Learning**:
- **Behavioral Analysis**: After-hours access patterns
- **Data Exfiltration**: USB, email, database dumps
- **Privilege Abuse**: Database administrator activities
- **Anti-Forensics**: Evidence destruction

**Expected IoCs**:
- dbuser suspicious activities
- Financial data in /tmp/stolen/
- USB mount artifacts
- After-hours database access

#### 🌐 Web Application Attack
**Durasi**: 3-4 jam  
**Tujuan**: Menganalisis OWASP Top 10 exploits

```bash
./scenario_selector.sh webapp
```

**Fokus Learning**:
- **Web Shells**: PHP backdoors in web directories
- **SQL Injection**: Database compromise via web
- **File Upload Vulns**: Malicious file uploads
- **Session Hijacking**: Cookie manipulation

**Expected IoCs**:
- Web shells di /var/www/html/
- SQL injection dalam nginx logs
- File upload bypass artifacts
- Stolen session tokens

---

### 🔴 LEVEL LANJUT: Advanced Multi-Vector

#### 🚨 Combined Investigation
**Durasi**: 6-8 jam  
**Tujuan**: Menangani enterprise-level compromise

```bash
./scenario_selector.sh combined
# ATAU
./master_investigation.sh
```

**Yang Disimulasikan**:
- ✅ APT campaign (Silent Dragon)
- ✅ Ransomware attack (CryptoVault)  
- ✅ Insider threat (dbuser)
- ✅ Web application compromise
- ✅ Cryptocurrency mining

**Skills yang Dikembangkan**:
- Multi-vector attack correlation
- Timeline reconstruction
- Professional report writing
- Incident response coordination

---

## 📊 EVIDENCE ANALYSIS WORKFLOW

### 1️⃣ Automated Collection
```bash
# Collect semua evidence dari container
./forensic_collector_fixed.sh [container_name]

# Output: ./evidence/CASE_YYYYMMDD_HHMMSS/
```

### 2️⃣ Automated Analysis  
```bash
# Analyze evidence untuk IoCs
./evidence_analyzer.sh ./evidence/CASE_*

# Review results:
cat evidence/CASE_*/indicators_of_compromise.txt
cat evidence/CASE_*/analysis_results.txt
```

### 3️⃣ Manual Deep Dive
```bash
cd evidence/CASE_*

# User analysis
cat passwd_file.txt | grep -v "nologin"
cat shadow_file.txt | grep -v "!"

# Process analysis  
cat running_processes.txt | grep -v "kthreadd\|ksoftirqd"
cat network_connections.txt | grep "LISTEN"

# File system analysis
cat recent_files.txt | head -20
cat hidden_files_tmp.txt
cat suid_sgid_files.txt

# Web analysis (jika ada)
cat potential_webshells.txt
cat nginx_access.log | tail -50
```

### 4️⃣ Timeline Reconstruction
```bash
# Generate timeline (jika tersedia)
./timeline_analyzer.sh ./evidence/CASE_*

# Manual timeline dari logs
grep "Oct  8" evidence/CASE_*/auth_log.txt | sort
```

---

## 🔍 KEY INDICATORS OF COMPROMISE (IoCs)

### 👤 User Account IoCs
- **Unauthorized users**: backdoor_user, apt_user
- **UID 0 accounts**: Non-root users dengan UID 0
- **Password changes**: Recent passwd/shadow modifications

### 🔄 Process IoCs  
- **Suspicious binaries**: /usr/bin/system_update
- **Network tools**: nc, netcat pada port 4444
- **Crypto miners**: xmrig, cpuminer processes
- **Web shells**: PHP processes dari web directories

### 🌐 Network IoCs
- **C2 Communications**: update.system-analytics.com
- **Suspicious ports**: 4444, 1337, 31337
- **Mining pools**: stratum+tcp connections
- **Exfiltration**: Large outbound transfers

### 📁 File System IoCs
- **Web shells**: /var/www/html/admin_panel.php
- **Hidden directories**: /tmp/.hidden/, /tmp/.apt/
- **Encrypted files**: *.locked, *.encrypted
- **Ransom notes**: DECRYPT_INSTRUCTIONS.txt

### 📜 Log IoCs
- **Brute force**: Multiple SSH failures
- **SQL injection**: UNION SELECT dalam web logs
- **Privilege escalation**: sudo usage spikes
- **After-hours access**: Login outside business hours

---

## 🛠️ TROUBLESHOOTING CEPAT

### Port Conflict
```bash
# Error: port already allocated
docker ps
docker stop [container_id]
docker rm [container_id]
```

### Permission Issues
```bash
chmod +x *.sh
sudo chown -R $USER:$USER evidence/
```

### Container Issues
```bash
# Rebuild jika error
docker build --no-cache -f Dockerfile.compromised -t compromised-ubuntu .

# Check Docker status
docker --version
docker info
```

### Evidence Issues
```bash
# Check evidence collection
ls -la evidence/CASE_*/
wc -l evidence/CASE_*/*.txt

# Re-run collection
./forensic_collector_fixed.sh compromised-ubuntu
```

---

## 📚 LEARNING PATH RECOMMENDATIONS

### Week 1: Foundations
- [x] Basic scenario
- [x] Evidence collection practice
- [x] Linux forensics fundamentals

### Week 2: Attack Analysis  
- [x] APT investigation
- [x] Ransomware analysis
- [x] MITRE ATT&CK mapping

### Week 3: Advanced Threats
- [x] Insider threat detection
- [x] Web application attacks
- [x] Timeline reconstruction

### Week 4: Enterprise Response
- [x] Combined multi-vector attacks
- [x] Professional reporting
- [x] Incident response coordination

---

## 🎯 SUCCESS METRICS

### Beginner Level ✅
- Can collect evidence systematically
- Understands basic Linux forensics
- Identifies common IoCs

### Intermediate Level ✅  
- Maps attacks to MITRE ATT&CK
- Reconstructs attack timelines
- Correlates multiple evidence sources

### Advanced Level ✅
- Handles multi-vector attacks
- Writes professional reports
- Develops custom IoCs

---

**🔍 Ready to start? Pick your scenario:**

```bash
# Quick start - APT investigation
./scenario_selector.sh apt

# Full experience - all scenarios  
./scenario_selector.sh combined

# See all options
./scenario_selector.sh
```

**Happy Investigating! 🚀**