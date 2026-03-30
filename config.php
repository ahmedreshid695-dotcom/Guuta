<?php
session_start(); // Start session

// Database connection
$host = "localhost";
$user = "root";
$pass = "";
$db   = "stu_register";

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>