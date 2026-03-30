<?php
include 'config.php';

if(!isset($_SESSION['student_name'])){
    header("Location: login.php");
    exit();
}
?>

<!DOCTYPE html>
<html>
<head>
<style>
body{text-align:center;font-family:Arial;background:#f2f2f2;}
.box{width:350px;margin:50px auto;padding:20px;background:white;border-radius:10px;box-shadow:0 0 10px gray;}
a{display:block;margin-top:10px;}
</style>
</head>
<body>

<div class="box">
<h2>Welcome <?php echo $_SESSION['student_name']; ?></h2>
<p>Email: <?php echo $_SESSION['student_email']; ?></p>
<p>This is your student dashboard.</p>
<a href="logout.php">Logout</a>
</div>

</body>
</html>