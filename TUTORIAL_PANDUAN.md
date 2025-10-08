# 🔍 PANDUAN DIGITAL FORENSICS LAB - LANGKAH DEMI LANGKAH

## 📋 DAFTAR ISI
1. [Persiapan Awal](#persiapan-awal)
2. [Skenario Pembelajaran](#skenario-pembelajaran)
3. [Modul 1: Basic Investigation](#modul-1-basic-investigation)
4. [Modul 2: APT Investigation](#modul-2-apt-investigation)
5. [Modul 3: Ransomware Investigation](#modul-3-ransomware-investigation)
6. [Modul 4: Insider Threat Investigation](#modul-4-insider-threat-investigation)
7. [Modul 5: Web Application Attack Investigation](#modul-5-web-application-attack-investigation)
8. [Modul 6: Advanced Multi-Attack Investigation](#modul-6-advanced-multi-attack-investigation)
9. [Analisis dan Pelaporan](#analisis-dan-pelaporan)
10. [Tips dan Best Practices](#tips-dan-best-practices)

---

## 🎯 PERSIAPAN AWAL

### Prerequisites
- Docker Desktop terinstall dan berjalan
- Minimal 4GB RAM dan 10GB disk space
- Terminal/Command line access
- Text editor untuk review file evidence

### Setup Environment
```bash
# 1. Clone/Navigate ke direktori lab
cd /Users/ekosakti/Code/forensics/lab

# 2. Berikan permission execute ke semua script
chmod +x *.sh

# 3. Buat direktori untuk evidence dan reports
mkdir -p evidence reports

# 4. Verifikasi Docker berjalan
docker --version
docker ps
```

---

## 🎓 SKENARIO PEMBELAJARAN

### Level Pemula (Beginner)
- **Tujuan**: Memahami dasar-dasar forensik digital
- **Target**: Mahasiswa, IT staff baru
- **Durasi**: 2-3 jam

### Level Menengah (Intermediate)  
- **Tujuan**: Menguasai teknik investigasi advanced
- **Target**: Security analyst, IT investigator
- **Durasi**: 4-6 jam

### Level Lanjut (Advanced)
- **Tujuan**: Menangani multiple attack vectors
- **Target**: Incident responder, forensic analyst
- **Durasi**: 6-8 jam

---

## 📚 MODUL 1: BASIC INVESTIGATION

### 🎯 Tujuan Pembelajaran
- Memahami proses evidence collection
- Belajar mengidentifikasi IoCs dasar
- Mengenal tools forensik Linux

### 🛠️ Langkah-Langkah

#### Step 1: Setup Basic Environment
```bash
# Jalankan container dasar tanpa compromise
docker build -f Dockerfile.compromised -t forensics-basic .
docker run -d -p 2222:22 -p 8080:80 --name basic-system forensics-basic
```

#### Step 2: Exploration & Baseline
```bash
# Akses sistem untuk memahami kondisi normal
ssh webadmin@localhost -p 2222
# Password: webpass123

# Explore sistem normal
ps aux
netstat -tulpn
ls -la /home/webadmin/
cat /etc/passwd
exit
```

#### Step 3: Evidence Collection Manual
```bash
# Collect evidence menggunakan Docker commands
mkdir -p evidence/BASIC_$(date +%Y%m%d_%H%M%S)
cd evidence/BASIC_$(date +%Y%m%d_%H%M%S)

# Basic system info
docker exec basic-system ps aux > processes.txt
docker exec basic-system netstat -tulpn > network.txt
docker exec basic-system cat /etc/passwd > users.txt
docker exec basic-system ls -la /home/ > home_dirs.txt
```

#### Step 4: Analysis Dasar
```bash
# Analisis manual hasil collection
echo "=== BASIC ANALYSIS ===" > basic_analysis.txt
echo "Users in system:" >> basic_analysis.txt
cat users.txt >> basic_analysis.txt
echo -e "\nRunning processes:" >> basic_analysis.txt
cat processes.txt >> basic_analysis.txt
```

#### 📊 Hasil Yang Diharapkan
- Pemahaman struktur sistem Linux
- Kemampuan basic evidence collection
- Pengenalan format log dan konfigurasi

#### 🎓 Learning Objectives Achieved
✅ Understand basic Linux forensics  
✅ Learn evidence preservation  
✅ Practice manual investigation  

---

## 🕵️ MODUL 2: APT INVESTIGATION

### 🎯 Tujuan Pembelajaran
- Mengidentifikasi serangan APT (Advanced Persistent Threat)
- Memahami TTPs (Tactics, Techniques, Procedures)
- Belajar timeline reconstruction

### 🛠️ Langkah-Langkah

#### Step 1: Deploy APT Scenario
```bash
# Cleanup container sebelumnya
docker stop basic-system 2>/dev/null || true
docker rm basic-system 2>/dev/null || true

# Jalankan APT simulation
./scenario_selector.sh apt
```

#### Step 2: Live Investigation
```bash
# Akses sistem yang dikompromikan
docker exec -it compromised-ubuntu bash

# Cari tanda-tanda APT
find /tmp -name ".*" -type f 2>/dev/null
ps aux | grep -E "(python|curl|wget)"
netstat -tulpn | grep -v ":22\|:80"
ls -la /home/*/.*
cat /etc/crontab

# Keluar dari container
exit
```

#### Step 3: Forensic Collection
```bash
# Gunakan forensic collector yang sudah diperbaiki
./forensic_collector_fixed.sh compromised-ubuntu
```

#### Step 4: APT Analysis
```bash
# Jalankan analisis khusus APT
./evidence_analyzer.sh ./evidence/CASE_*

# Review hasil analisis
cd evidence/CASE_*
cat indicators_of_compromise.txt
grep -i "apt\|spear\|phish" analysis_results.txt
```

#### Step 5: APT Artifact Examination
```bash
# Periksa artifact APT secara detail
cat container_metadata.json | grep -A5 -B5 "update-manager"
cat running_processes.txt | grep -E "(system_update|python)"
cat network_connections.txt | grep -E "4444|1337"
cat sshd_config.txt | grep -E "PermitRoot"
```

#### 📊 Hasil Yang Diharapkan
- **Persistence Mechanisms**: SSH keys, systemd services, cron jobs
- **C2 Communications**: Network connections to suspicious domains
- **Living off the Land**: Legitimate tools used maliciously
- **Data Exfiltration**: Evidence of data staging and transfer

#### 🎓 Learning Objectives Achieved
✅ Identify APT attack patterns  
✅ Understand persistence mechanisms  
✅ Trace attack timeline  
✅ Map to MITRE ATT&CK framework  

---

## 🔒 MODUL 3: RANSOMWARE INVESTIGATION

### 🎯 Tujuan Pembelajaran
- Menganalisis serangan ransomware
- Memahami double extortion tactics
- Mendeteksi cryptocurrency mining

### 🛠️ Langkah-Langkah

#### Step 1: Deploy Ransomware Scenario
```bash
# Cleanup environment
docker stop compromised-ubuntu 2>/dev/null || true
docker rm compromised-ubuntu 2>/dev/null || true

# Jalankan ransomware simulation
./scenario_selector.sh ransomware
```

#### Step 2: Ransomware Investigation
```bash
# Masuk ke sistem untuk investigasi
docker exec -it compromised-ubuntu bash

# Cari tanda-tanda ransomware
find / -name "*DECRYPT*" -o -name "*RANSOM*" 2>/dev/null
find / -name "*.locked" -o -name "*.encrypted" 2>/dev/null
ps aux | grep -i "crypto\|xmrig\|miner"
cat /etc/crontab | grep -E "(crypto|mining|update)"

# Periksa desktop environment
ls -la /home/*/Desktop/ 2>/dev/null || true
cat /home/*/Desktop/*DECRYPT* 2>/dev/null || true

exit
```

#### Step 3: Evidence Collection & Analysis
```bash
# Collect evidence
./forensic_collector_fixed.sh compromised-ubuntu

# Analyze ransomware indicators
./evidence_analyzer.sh ./evidence/CASE_*

# Fokus pada ransomware artifacts
cd evidence/CASE_*
grep -i "ransom\|crypto\|encrypt\|mining" analysis_results.txt
grep -i "darkmo\|cryptovault" *.txt
```

#### Step 4: Cryptocurrency Analysis
```bash
# Analisis cryptocurrency mining
cat running_processes.txt | grep -i "xmr\|mining\|crypto"
cat network_connections.txt | grep -E "pool\|mining"
grep -r "bc1q" . 2>/dev/null || true  # Bitcoin addresses
```

#### 📊 Hasil Yang Diharapkan
- **Ransom Notes**: DECRYPT_INSTRUCTIONS.txt
- **Encrypted Files**: *.locked, *.encrypted extensions  
- **Cryptocurrency Miners**: XMRig or similar processes
- **Shadow Copy Deletion**: Evidence of backup destruction
- **Network Communications**: Mining pool connections

#### 🎓 Learning Objectives Achieved
✅ Understand ransomware attack chains  
✅ Identify double extortion tactics  
✅ Detect cryptocurrency mining  
✅ Analyze file encryption patterns  

---

## 👤 MODUL 4: INSIDER THREAT INVESTIGATION

### 🎯 Tujuan Pembelajaran
- Mendeteksi insider threat patterns
- Menganalisis abuse of legitimate access
- Memahami data exfiltration methods

### 🛠️ Langkah-Langkah

#### Step 1: Deploy Insider Threat Scenario
```bash
# Setup insider threat simulation
docker stop compromised-ubuntu 2>/dev/null || true
docker rm compromised-ubuntu 2>/dev/null || true

./scenario_selector.sh insider
```

#### Step 2: Behavioral Analysis
```bash
# Investigasi pola perilaku mencurigakan
docker exec -it compromised-ubuntu bash

# Analisis aktivitas user
cat /home/dbuser/.bash_history 2>/dev/null || true
find /home/dbuser -name "*.txt" -o -name "*.sql" 2>/dev/null
ls -la /media/usb* 2>/dev/null || true
cat /var/log/auth.log | grep dbuser 2>/dev/null || true

# Cari evidence data theft
find /tmp -name "*customer*" -o -name "*financial*" 2>/dev/null
find / -name "*EXFILTRATED*" -o -name "*STOLEN*" 2>/dev/null

exit
```

#### Step 3: Timeline Analysis
```bash
# Collect evidence dengan fokus timeline
./forensic_collector_fixed.sh compromised-ubuntu

# Generate timeline
cd evidence/CASE_*
./../../timeline_analyzer.sh .
```

#### Step 4: Insider Threat Pattern Analysis
```bash
# Analisis khusus insider threat
cat webadmin_bash_history.txt | grep -E "(cp|mv|rsync|scp)"
cat auth_log.txt | grep -E "after.*hours|weekend|holiday"
grep -i "usb\|mount\|email" *.txt
cat running_processes.txt | grep -E "zip|tar|compress"
```

#### 📊 Hasil Yang Diharapkan
- **After-Hours Activity**: Login patterns outside business hours
- **Data Collection**: Large file operations, database dumps
- **USB Activity**: Evidence of removable media usage
- **Email Exfiltration**: SMTP connections, email artifacts
- **Anti-Forensics**: Log deletion, timestamp manipulation

#### 🎓 Learning Objectives Achieved
✅ Detect insider threat indicators  
✅ Analyze user behavior patterns  
✅ Understand data exfiltration methods  
✅ Practice timeline reconstruction  

---

## 🌐 MODUL 5: WEB APPLICATION ATTACK INVESTIGATION

### 🎯 Tujuan Pembelajaran
- Menganalisis web application attacks
- Mendeteksi web shells dan backdoors
- Memahami OWASP Top 10 exploits

### 🛠️ Langkah-Langkah

#### Step 1: Deploy Web Attack Scenario
```bash
# Setup web application attack
docker stop compromised-ubuntu 2>/dev/null || true
docker rm compromised-ubuntu 2>/dev/null || true

./scenario_selector.sh webapp
```

#### Step 2: Web Shell Detection
```bash
# Investigasi web shells
docker exec -it compromised-ubuntu bash

# Cari web shells
find /var/www/html -name "*.php" -exec grep -l "system\|exec\|shell_exec" {} \;
find /var/www/html -name ".*" -type f
ls -la /var/www/html/uploads/ 2>/dev/null || true
cat /var/www/html/*.php | grep -A5 -B5 "eval\|base64_decode"

# Periksa log web server
tail -50 /var/log/nginx/access.log 2>/dev/null || true
grep -E "POST.*\.php|sql|union|select" /var/log/nginx/access.log 2>/dev/null || true

exit
```

#### Step 3: SQL Injection Analysis
```bash
# Collect evidence
./forensic_collector_fixed.sh compromised-ubuntu

# Analisis SQL injection
cd evidence/CASE_*
grep -i "sql\|union\|select\|inject" nginx_access.log 2>/dev/null || true
cat potential_webshells.txt
grep -E "(eval|base64|system)" web_php_files.txt 2>/dev/null || true
```

#### Step 4: Database Compromise Analysis
```bash
# Periksa database compromise
docker exec compromised-ubuntu find /var/lib/mysql -name "*.sql" 2>/dev/null || true
docker exec compromised-ubuntu find /tmp -name "*dump*" -o -name "*backup*" 2>/dev/null || true
grep -i "database\|mysql\|dump" evidence/CASE_*/analysis_results.txt
```

#### 📊 Hasil Yang Diharapkan
- **Web Shells**: PHP shells in web directories
- **SQL Injection**: Evidence in web logs
- **File Upload Vulnerabilities**: Malicious files in upload directories
- **Session Hijacking**: Cookie manipulation evidence
- **Database Dumps**: Extracted database files

#### 🎓 Learning Objectives Achieved
✅ Identify web application vulnerabilities  
✅ Detect web shells and backdoors  
✅ Analyze SQL injection attacks  
✅ Understand OWASP Top 10 exploits  

---

## 🎯 MODUL 6: ADVANCED MULTI-ATTACK INVESTIGATION

### 🎯 Tujuan Pembelajaran
- Menangani multiple simultaneous attacks
- Mengkorelasikan berbagai attack vectors
- Melakukan comprehensive incident response

### 🛠️ Langkah-Langkah

#### Step 1: Deploy Full Attack Scenario
```bash
# Jalankan semua skenario sekaligus
docker stop compromised-ubuntu 2>/dev/null || true
docker rm compromised-ubuntu 2>/dev/null || true

./scenario_selector.sh combined
# ATAU
./master_investigation.sh
```

#### Step 2: Multi-Vector Investigation
```bash
# Investigasi komprehensif
docker exec -it compromised-ubuntu bash

# APT indicators
find /tmp -name ".*" -type f
cat /etc/crontab | grep -v "^#"

# Ransomware indicators  
find / -name "*DECRYPT*" -o -name "*.locked" 2>/dev/null

# Web attack indicators
find /var/www/html -name "*.php" -exec grep -l "eval\|system" {} \;

# Insider threat indicators
cat /home/dbuser/.bash_history 2>/dev/null | tail -20

# Network analysis
netstat -tulpn | grep -v ":22\|:80"
ps aux | grep -E "(python|nc|wget|curl)"

exit
```

#### Step 3: Comprehensive Evidence Collection
```bash
# Full forensic collection
./forensic_collector_fixed.sh compromised-ubuntu

# Advanced analysis
./evidence_analyzer.sh ./evidence/CASE_*
```

#### Step 4: Attack Correlation & Timeline
```bash
# Buat timeline lengkap
cd evidence/CASE_*
./../../timeline_analyzer.sh .

# Korelasi attack vectors
echo "=== ATTACK CORRELATION ANALYSIS ===" > correlation_analysis.txt
echo "1. APT Campaign Indicators:" >> correlation_analysis.txt
grep -i "apt\|spear\|silent.dragon" *.txt >> correlation_analysis.txt

echo -e "\n2. Ransomware Indicators:" >> correlation_analysis.txt  
grep -i "ransom\|crypto\|darkmoney" *.txt >> correlation_analysis.txt

echo -e "\n3. Insider Threat Indicators:" >> correlation_analysis.txt
grep -i "dbuser\|after.hour\|exfiltrat" *.txt >> correlation_analysis.txt

echo -e "\n4. Web Attack Indicators:" >> correlation_analysis.txt
grep -i "web.shell\|sql\|inject" *.txt >> correlation_analysis.txt

cat correlation_analysis.txt
```

#### Step 5: Professional Reporting
```bash
# Generate laporan profesional
./report_generator.sh ./evidence/CASE_*

# Review laporan
ls -la ../reports/
cat ../reports/FORENSIC_REPORT_CASE_*.txt
```

#### 📊 Hasil Yang Diharapkan
- **Attack Timeline**: Kronologi lengkap semua serangan
- **Attack Correlation**: Hubungan antar attack vectors
- **Impact Assessment**: Evaluasi kerusakan sistem
- **IOC Mapping**: Pemetaan ke MITRE ATT&CK framework
- **Professional Report**: Laporan investigasi lengkap

#### 🎓 Learning Objectives Achieved
✅ Handle complex multi-vector attacks  
✅ Correlate different attack techniques  
✅ Create professional forensic reports  
✅ Understand complete incident response  

---

## 📊 ANALISIS DAN PELAPORAN

### Evidence Analysis Workflow
```bash
# 1. Automated Analysis
./evidence_analyzer.sh [evidence_directory]

# 2. Manual Review
cd evidence/CASE_*
cat indicators_of_compromise.txt
cat analysis_results.txt

# 3. Timeline Creation
./timeline_analyzer.sh .

# 4. Report Generation  
./report_generator.sh .
```

### Key Analysis Areas

#### 1. **User Account Analysis**
- Unauthorized accounts
- Privilege escalation
- Password changes

#### 2. **Process Analysis**  
- Suspicious processes
- Unusual parent-child relationships
- Memory resident malware

#### 3. **Network Analysis**
- Unusual connections
- C2 communications
- Data exfiltration channels

#### 4. **File System Analysis**
- Modified system files
- Hidden files/directories
- Recently created files

#### 5. **Log Analysis**
- Authentication events
- System events
- Application logs

---

## 💡 TIPS DAN BEST PRACTICES

### 🔧 Technical Tips

#### Efficient Evidence Collection
```bash
# Selalu backup container sebelum investigasi
docker commit compromised-ubuntu compromised-backup

# Gunakan timestamp untuk evidence preservation
CASE_ID="CASE_$(date +%Y%m%d_%H%M%S)"

# Hash verification untuk integrity
find evidence/ -type f -exec sha256sum {} \; > evidence_hashes.txt
```

#### Advanced Analysis Techniques
```bash
# String analysis untuk malware
docker exec container_name strings /path/to/suspicious_binary

# Memory dump analysis (simulasi)
docker exec container_name cat /proc/*/maps > memory_maps.txt

# Network packet capture (jika tersedia)
docker exec container_name tcpdump -i any -w capture.pcap
```

### 📋 Investigation Checklist

#### ✅ Pre-Investigation
- [ ] Document sistem dalam kondisi normal
- [ ] Backup container/system state
- [ ] Setup evidence directory
- [ ] Prepare analysis tools

#### ✅ During Investigation
- [ ] Maintain chain of custody
- [ ] Document semua actions
- [ ] Preserve volatile data first
- [ ] Take screenshots/notes

#### ✅ Post-Investigation
- [ ] Verify evidence integrity
- [ ] Create timeline
- [ ] Generate IoC list
- [ ] Write professional report

### 🎯 Learning Path Progression

#### Beginner → Intermediate
1. Master basic Linux commands
2. Understand log analysis
3. Learn Docker forensics
4. Practice evidence collection

#### Intermediate → Advanced  
1. Study MITRE ATT&CK framework
2. Learn advanced persistence techniques
3. Practice timeline reconstruction
4. Master correlation analysis

#### Advanced → Expert
1. Develop custom analysis tools
2. Create new attack scenarios
3. Contribute to threat intelligence
4. Teach others

---

## 🚨 SAFETY & LEGAL CONSIDERATIONS

### ⚠️ Warning
Lab ini berisi simulasi malware dan teknik attack:
- **HANYA** gunakan di environment terisolasi
- **JANGAN** jalankan di sistem production
- **PATUHI** hukum dan regulasi setempat
- **GUNAKAN** hanya untuk tujuan edukasi

### 🔒 Security Measures
```bash
# Isolasi network (optional)
docker network create --driver bridge isolated_network
docker run --network isolated_network ...

# Cleanup setelah selesai
docker stop compromised-ubuntu
docker rm compromised-ubuntu
docker rmi compromised-ubuntu:latest
```

---

## 📞 TROUBLESHOOTING

### Common Issues

#### Docker Port Conflicts
```bash
# Error: port already allocated
docker ps  # Cek container yang running
docker stop [container_id]
docker rm [container_id]
```

#### Permission Issues
```bash
# Fix script permissions
chmod +x *.sh

# Fix evidence directory
sudo chown -R $USER:$USER evidence/
```

#### Container Not Starting
```bash
# Check Docker status
docker --version
docker info

# Rebuild container
docker build --no-cache -f Dockerfile.compromised -t compromised-ubuntu .
```

---

## 🎓 LEARNING OUTCOMES

Setelah menyelesaikan semua modul, Anda akan mampu:

### Technical Skills
✅ **Forensic Methodology**: Menguasai prosedur investigasi digital  
✅ **Evidence Collection**: Mengumpulkan dan preservasi evidence  
✅ **Malware Analysis**: Mengidentifikasi dan menganalisis malware  
✅ **Network Forensics**: Menganalisis traffic dan komunikasi network  
✅ **Timeline Reconstruction**: Membuat kronologi serangan  
✅ **Report Writing**: Menulis laporan investigasi profesional  

### Attack Understanding
✅ **APT Campaigns**: Memahami serangan nation-state  
✅ **Ransomware**: Menganalisis file encryption attacks  
✅ **Insider Threats**: Mendeteksi abuse internal  
✅ **Web Attacks**: Mengidentifikasi OWASP Top 10 exploits  
✅ **Multi-Vector**: Menangani serangan kompleks  

### Industry Knowledge
✅ **MITRE ATT&CK**: Mapping TTPs ke framework  
✅ **IOC Development**: Membuat indicators of compromise  
✅ **Threat Intelligence**: Memahami threat landscape  
✅ **Incident Response**: Melakukan IR lengkap  

---

**Happy Investigating! 🔍**

*"In digital forensics, every bit tells a story. Your job is to listen."*