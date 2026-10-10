<?php
include 'config.php';

if(isset($_POST['login'])){
    $email = $_POST['email'];
    $password = $_POST['password'];

    if(!preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $email)){
        $error = "Email Google (@gmail.com) qofatu heyyamama! (Only @gmail.com is allowed!)";
    } else {
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
<input type="email" name="email" placeholder="Email (@gmail.com)" pattern=".+@gmail\.com$" title="Email Google (@gmail.com) qofa galchaa" required>
<input type="password" name="password" placeholder="Password" required>
<button name="login">Login</button>
</form>
<div style="margin: 18px 0; display: flex; align-items: center; text-align: center;">
    <hr style="flex:1; border:0; border-top:1px solid #ddd;">
    <span style="padding: 0 10px; color:#777; font-size:12px; font-weight:bold;">YOO KAN (OR)</span>
    <hr style="flex:1; border:0; border-top:1px solid #ddd;">
</div>

<!-- Google Sign-In Button -->
<div style="display: flex; justify-content: center; margin: 15px 0;">
    <div id="g_id_onload"
         data-client_id="<?php echo htmlspecialchars($google_client_id); ?>"
         data-context="signin"
         data-ux_mode="popup"
         data-callback="handleGoogleCredentialResponse"
         data-auto_prompt="false">
    </div>
    <div class="g_id_signin"
         data-type="standard"
         data-shape="rectangular"
         data-theme="outline"
         data-text="signin_with"
         data-size="large"
         data-logo_alignment="left">
    </div>
</div>

<div style="margin-top: 15px;">
    <a href="register.php">Create Account</a> | <a href="forgot_password.php">Forgot Password?</a>
</div>
</div>

<script src="https://accounts.google.com/gsi/client" async defer></script>
<script>
function handleGoogleCredentialResponse(response) {
    fetch('google_login.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ credential: response.credential })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            window.location.href = data.redirect || 'dashboard.php';
        } else {
            alert('Google login dogoggore: ' + (data.message || 'Error occurred'));
        }
    })
    .catch(err => {
        console.error(err);
        alert('Server waliin wal qunnamuu hin dandeenye.');
    });
}
</script>
</body>
</html>