<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Database credentials (environment variables or local defaults)
$host = getenv('DB_HOST') ?: "127.0.0.1";
$user = getenv('DB_USER') ?: "root";
$pass = getenv('DB_PASS') !== false ? getenv('DB_PASS') : "";
$db   = getenv('DB_NAME') ?: "stu_register";
$port = (int)(getenv('DB_PORT') ?: 3306);

try {
    $conn = new mysqli($host, $user, $pass, $db, $port);
} catch (mysqli_sql_exception $e) {
    die("<div style='font-family:sans-serif;padding:20px;background:#fee;border:1px solid #f99;margin:20px;border-radius:8px;'>
        <h3 style='color:#c00;margin-top:0;'>Database Connection Error</h3>
        <p>Could not connect to MySQL database at <strong>" . htmlspecialchars($host) . ":" . htmlspecialchars((string)$port) . "</strong>.</p>
        <p><strong>Reason:</strong> " . htmlspecialchars($e->getMessage()) . "</p>
        <p><em>Check your environment variables (<code>DB_HOST</code>, <code>DB_USER</code>, <code>DB_PASS</code>, <code>DB_NAME</code>, <code>DB_PORT</code>) or verify MySQL service is running.</em></p>
    </div>");
}

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Auto-check and ensure role, picture, and department columns exist in students table
@$conn->query("ALTER TABLE students ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'student'");
@$conn->query("ALTER TABLE students ADD COLUMN IF NOT EXISTS picture VARCHAR(255) DEFAULT ''");
@$conn->query("ALTER TABLE students ADD COLUMN IF NOT EXISTS department VARCHAR(100) DEFAULT 'General'");

// Google OAuth Client ID
$google_client_id = getenv('GOOGLE_CLIENT_ID') ?: "108394857492-exampleclientid.apps.googleusercontent.com";

// Admin Emails allowed to access Full Management Dashboard (CRUD)
$admin_emails = [
    "admin4566@gmail.com",
    "ahmedreshid695@gmail.com",
    getenv('ADMIN_EMAIL') ?: ""
];

// Helper function to check if an email or current user is Admin
function is_admin($email = null) {
    global $conn, $admin_emails;
    if ($email === null && isset($_SESSION['student_email'])) {
        $email = $_SESSION['student_email'];
    }
    if (empty($email)) return false;

    // Check session role if cached
    if (isset($_SESSION['student_role']) && $_SESSION['student_role'] === 'admin') {
        return true;
    }

    $email_lower = strtolower(trim($email));
    foreach ($admin_emails as $admin) {
        if (!empty($admin) && strtolower(trim($admin)) === $email_lower) {
            return true;
        }
    }

    // Also treat any email containing admin as admin
    if (strpos($email_lower, 'admin') === 0 || strpos($email_lower, 'admin') !== false) {
        return true;
    }

    // Also check database role (so newly promoted admins have full admin power)
    if (!empty($conn) && $conn instanceof mysqli && !$conn->connect_error) {
        $check = @$conn->query("SELECT role FROM students WHERE email = '" . $conn->real_escape_string($email) . "' LIMIT 1");
        if ($check && $row = $check->fetch_assoc()) {
            if (($row['role'] ?? '') === 'admin') {
                return true;
            }
        }
    }

    return false;
}

// Helper function to get custom uploaded university logo
function get_site_logo() {
    $logo_path = __DIR__ . '/uploads/logo.png';
    if (file_exists($logo_path)) {
        return 'uploads/logo.png?v=' . filemtime($logo_path);
    }
    return null;
}
?>