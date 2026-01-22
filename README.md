# vulnerable-web-application-task
VulnBank is an intentionally vulnerable banking web application designed for security testing and educational purposes. It contains multiple OWASP Top 10 vulnerabilities to demonstrate common web application security flaws.
Vulnerable Web Application (VulnBank) - Security Assessment Report

Application Details
Name: VulnBank
Technology Stack: PHP, MySQL, Apache
Location: /var/www/html/vulnbank/
Purpose: Security training and vulnerability demonstration

Identified Vulnerabilities (OWASP Top 10)
1. SQL Injection
Location: Login page (login.php)
Vulnerability:
Username field accepts SQL injection payloads
Demonstrated with payload: ' OR '1'='1
Bypasses authentication without valid credentials

Proof:
bash
# Using sqlmap for detection
sqlmap -u "http://localhost/vulnbank/login.php" --data="username=test&password=test" --batch
Severity: Critical
Impact: Complete authentication bypass, data extraction, potential RCE

Fix:
php
// Use prepared statements
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
2. Broken Access Control
Location: Admin panel and protected pages
Vulnerability:
Unauthenticated access to /admin/ directory
Direct access to profile.php without authentication (HTTP 200)
Sensitive data exposure in admin panel

Proof:
bash
curl -s "http://localhost/vulnbank/admin/" | grep -q "users|password" && echo "Sensitive data exposed"
Severity: High
Impact: Unauthorized data access, privilege escalation

Fix:
php
// Implement proper session validation
session_start();
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: login.php");
    exit();
}
3. Server-Side Request Forgery (SSRF)
Location: ssrf.php file
Vulnerability:
Unrestricted URL parameter allows internal network scanning
Can access internal services and files

Proof:
bash
curl "http://localhost/vulnbank/ssrf.php?url=http://localhost"
Severity: High
Impact: Internal network enumeration, service disruption

Fix:
php
// Validate and restrict URLs
$allowed_domains = ['example.com', 'trusted-site.com'];
$url = parse_url($_GET['url']);
if (!in_array($url['host'], $allowed_domains)) {
    die("Access denied");
}
4. Local File Inclusion (LFI)
Location: 1fi.php file
Vulnerability:
Arbitrary file reading through page parameter
Access to sensitive system files (/etc/passwd)

Proof:
bash
curl "http://localhost/vulnbank/1fi.php?page=/etc/passwd"
Severity: High
Impact: Information disclosure, source code leakage

Fix:
php
// Whitelist allowed files
$allowed_files = ['home.php', 'about.php', 'contact.php'];
if (!in_array($_GET['page'], $allowed_files)) {
    die("Invalid page requested");
}
5. Cross-Site Request Forgery (CSRF)
Location: change_password.php
Vulnerability:
Missing CSRF tokens
State-changing actions can be forged

Proof:
bash
# Check for CSRF tokens
curl -s "http://localhost/vulnbank/change_password.php" | grep -i "csrf|token"
Severity: Medium
Impact: Unauthorized account modifications

Fix:
php
// Generate and validate CSRF tokens
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF validation failed");
    }
}
Additional Security Issues Found
Information Disclosure
Config file exposure: config.php accessible via web
Database backup: database.sql publicly accessible
PHPInfo: test.php exposes system information

Security Header Misconfigurations
Missing X-Frame-Options header
Missing X-Content-Type-Options heade
Missing HttpOnly flag on session cookies

Vulnerability Assessment Tools Results
1. Nmap Scan Results
bash
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH (protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.65
3306/tcp open  mysql      MySQL 5.5.5-10.3.39-MariaDB
Findings:

MySQL running with default credentials
SSH service exposed
Apache version disclosure

2. Nikto Scan Results
bash
- Cookie PHPSESSID created without httponly flag
- Missing security headers (X-Frame-Options, X-Content-Type-Options)
- Config.php accessible
- Database.sql backup file found
- Test.php exposing phpinfo()
Total Issues: 13 security items reported

Remediation Recommendations
Immediate Actions (Critical)
Implement Input Validation:
Use parameterized queries for all database operations
Validate and sanitize all user inputs
Implement proper authentication and authorization

Secure File Access:
Move configuration files outside web root
Restrict file inclusion to whitelisted files only
Implement proper file permissions

Access Control:
Implement role-based access control (RBAC)
Validate sessions on every protected page
Implement proper logout functionality
Security Hardening
Configure Security Headers:

apache
# .htaccess or Apache config
Header set X-Frame-Options "DENY"
Header set X-Content-Type-Options "nosniff"
Header set X-XSS-Protection "1; mode=block"
Header set Strict-Transport-Security "max-age=31536000"
Session Security:

php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
Error Handling:

php
// Disable error display in production
ini_set('display_errors', 0);
ini_set('log_errors', 1);
Database Security
Use least privilege principle for database users
Implement database encryption
Regular backups with proper access controls
Use strong, unique passwords

Testing Methodology
Steps Performed:
Reconnaissance: Nmap scanning for open ports and services
Vulnerability Scanning: Nikto for web application vulnerabilities

Manual Testing:
SQL injection testing with sqlmap
Authentication bypass attempts
File inclusion testing
CSRF validation checks
Code Review: Analysis of PHP files for security flaws

Tools Used:
Nmap: Network reconnaissance
Nikto: Web vulnerability scanner
sqlmap: Automated SQL injection tool
curl: Manual HTTP request testing
Custom scripts: Automated vulnerability checks

Conclusion
VulnBank successfully demonstrates five critical OWASP Top 10 vulnerabilities, making it an excellent resource for security training and awareness. The application serves as a practical example of how seemingly minor coding oversights can lead to significant security breaches.

Key Takeaways:
Never trust user input
Implement defense in depth
Regular security assessments are crucial
Security is not a feature but a fundamental requirement
