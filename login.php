<?php
include 'config.php';

if(isset($_POST['login'])){
    $email = $_POST['email'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT id, name, email, password FROM students WHERE email=?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($id, $name, $email_db, $hash);

    if($stmt->num_rows > 0){
        $stmt->fetch();
        if(password_verify($password, $hash)){
            $_SESSION['student_name'] = $name;
            $_SESSION['student_email'] = $email_db;
            header("Location: dashboard.php");
            exit();
        } else {
            $error = "Wrong password!";
        }
    } else {
        $error = "User not found!";
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
button{padding:10px;background:green;color:white;border:none;border-radius:5px;}
.error{color:red;}
</style>
</head>
<body>

<div class="box">
<h2>Student Login</h2>
<?php if(isset($error)) echo "<p class='error'>$error</p>"; ?>
<form method="POST">
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="password" placeholder="Password" required>
<button name="login">Login</button>
</form>
<a href="register.php">Create Account</a>
</div>

</body>
</html>