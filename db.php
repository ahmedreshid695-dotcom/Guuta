<?php
$conn = new mysqli("localhost", "root", "", "stu_register");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
echo "Connected successfully";
?>