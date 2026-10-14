<?php
$host = getenv('DB_HOST') ?: "127.0.0.1";
$user = getenv('DB_USER') ?: "root";
$pass = getenv('DB_PASS') !== false ? getenv('DB_PASS') : "";
$db   = getenv('DB_NAME') ?: "stu_register";
$port = (int)(getenv('DB_PORT') ?: 3306);

try {
    $conn = new mysqli($host, $user, $pass, $db, $port);
} catch (mysqli_sql_exception $e) {
    die("Connection failed: " . $e->getMessage());
}
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
echo "Connected successfully";
?>