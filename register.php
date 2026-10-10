<?php
include 'config.php';

if(isset($_POST['register'])){
    $name = $_POST['name'];
    $email = $_POST['email'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    // Check if email is Google email (@gmail.com)
    if(!preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $email)){
        $error = "Email Google (@gmail.com) qofatu heyyamama! (Only @gmail.com is allowed!)";
    } else {
        // Check duplicate email
        $stmt = $conn->prepare("SELECT id FROM students WHERE email=?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if($stmt->num_rows > 0){
            $error = "Email kun duraan galmaa'ee jira! (Email already registered!)";
        } else {
            $stmt->close();
            $stmt = $conn->prepare("INSERT INTO students (name, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $name, $email, $password);
            if($stmt->execute()){
                $success = "Student registered successfully! Gara Login deemaa.";
                require_once 'notify.php';
                notify_admin_new_registration($name, $email, "Form Galmee (Manual)");
            } else {
                $error = "Error: " . $stmt->error;
            }
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
<input type="email" name="email" placeholder="Email (@gmail.com)" pattern=".+@gmail\.com$" title="Email Google (@gmail.com) qofa galchaa" required>
<input type="password" name="password" placeholder="Password" required minlength="6">
<button name="register">Register</button>
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
         data-context="signup"
         data-ux_mode="popup"
         data-callback="handleGoogleCredentialResponse"
         data-auto_prompt="false">
    </div>
    <div class="g_id_signin"
         data-type="standard"
         data-shape="rectangular"
         data-theme="outline"
         data-text="signup_with"
         data-size="large"
         data-logo_alignment="left">
    </div>
</div>

<div style="margin-top: 15px;">
    <a href="login.php">Go to Login</a>
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