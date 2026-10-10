<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Database credentials (environment variables or local defaults)
$host = getenv('DB_HOST') ?: "localhost";
$user = getenv('DB_USER') ?: "root";
$pass = getenv('DB_PASS') !== false ? getenv('DB_PASS') : "";
$db   = getenv('DB_NAME') ?: "stu_register";
$port = (int)(getenv('DB_PORT') ?: 3306);

$conn = new mysqli($host, $user, $pass, $db, $port);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Google OAuth Client ID
$google_client_id = getenv('GOOGLE_CLIENT_ID') ?: "108394857492-exampleclientid.apps.googleusercontent.com";

// Admin Email for registration notifications
$admin_email = getenv('ADMIN_EMAIL') ?: "ahmedreshid695@gmail.com";
?>