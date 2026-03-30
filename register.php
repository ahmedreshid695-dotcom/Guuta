<?php
include 'config.php';

if(isset($_POST['register'])){
    $name = $_POST['name'];
    $email = $_POST['email'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    // Check duplicate email
    $stmt = $conn->prepare("SELECT id FROM students WHERE email=?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if($stmt->num_rows > 0){
        $error = "Email already registered!";
    } else {
        $stmt->close();
        $stmt = $conn->prepare("INSERT INTO students (name, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $name, $email, $password);
        if($stmt->execute()){
            $success = "Student registered successfully!";
        } else {
            $error = "Error: " . $stmt->error;
        }
    }

    $stmt->close();
}
?>

<!DOCTYPE html>
<html>
<head>
<style>
body{font-family:Arial;background:#f2f2f2;text-align:center;}
.box{width:350px;margin:50px auto;padding:20px;background:white;border-radius:10px;box-shadow:0 0 10px gray;}
input{width:90%;padding:10px;margin:10px 0;}
button{padding:10px;background:blue;color:white;border:none;border-radius:5px;}
.success{color:green;}
.error{color:red;}
</style>
</head>
<body>

<div class="box">
<h2>Student Registration</h2>
<?php if(isset($success)) echo "<p class='success'>$success</p>"; ?>
<?php if(isset($error)) echo "<p class='error'>$error</p>"; ?>
<form method="POST">
<input type="text" name="name" placeholder="Full Name" required>
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="password" placeholder="Password" required>
<button name="register">Register</button>
</form>
<a href="login.php">Go to Login</a>
</div>

</body>
</html>