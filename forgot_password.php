<?php
include 'config.php';

$error = "";
$success = "";

if (isset($_POST['reset_password'])) {
    $email = trim($_POST['email'] ?? '');
    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if (empty($email) || empty($new_password) || empty($confirm_password)) {
        $error = "Hundaa guutuu qabdu! (Please fill all fields!)";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Email sirrii miti! (Invalid email address!)";
    } elseif (strlen($new_password) < 6) {
        $error = "Password-n yoo xiqqaate qubee/lakkoofsa 6 ta'uu qaba! (Password must be at least 6 characters!)";
    } elseif ($new_password !== $confirm_password) {
        $error = "Password-n wal hin simne! (Passwords do not match!)";
    } else {
        // Check if email exists
        $stmt = $conn->prepare("SELECT id FROM students WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 0) {
            $error = "Email kun hin galmoofne! (Email not found!)";
        } else {
            $stmt->close();

            // Hash the new password
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

            // Update the password in database
            $update_stmt = $conn->prepare("UPDATE students SET password = ? WHERE email = ?");
            $update_stmt->bind_param("ss", $hashed_password, $email);

            if ($update_stmt->execute()) {
                $success = "Password haaraan milkaa'inaan jijjiirameera! (Password successfully reset!)";
            } else {
                $error = "Dogoggorri uumameera: " . $update_stmt->error;
            }
            $update_stmt->close();
        }

        if (isset($stmt) && $stmt instanceof mysqli_stmt && $stmt->num_rows > 0) {
            // Already closed above
        }
    }
}
?>

<!DOCTYPE html>
<html lang="om">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot / Reset Password</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f2f2f2;
            text-align: center;
            margin: 0;
            padding: 20px;
        }
        .box {
            width: 360px;
            margin: 50px auto;
            padding: 25px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        h2 {
            margin-top: 0;
            color: #333;
        }
        p.subtitle {
            color: #666;
            font-size: 14px;
            margin-bottom: 20px;
        }
        input {
            width: 90%;
            padding: 11px;
            margin: 8px 0;
            border: 1px solid #ccc;
            border-radius: 5px;
            box-sizing: border-box;
            font-size: 14px;
        }
        input:focus {
            outline: none;
            border-color: #28a745;
        }
        button {
            width: 90%;
            padding: 12px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 15px;
            cursor: pointer;
            font-weight: bold;
            margin-top: 10px;
        }
        button:hover {
            background: #0056b3;
        }
        .error {
            color: #dc3545;
            background: #f8d7da;
            padding: 10px;
            border-radius: 5px;
            font-size: 14px;
            margin-bottom: 15px;
        }
        .success {
            color: #155724;
            background: #d4edda;
            padding: 10px;
            border-radius: 5px;
            font-size: 14px;
            margin-bottom: 15px;
        }
        .links {
            margin-top: 20px;
            font-size: 14px;
        }
        .links a {
            color: #007bff;
            text-decoration: none;
        }
        .links a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>

<div class="box">
    <h2>Reset Password</h2>
    <p class="subtitle">Email kee galchiitii password haaraa filadhu</p>

    <?php if(!empty($error)): ?>
        <div class="error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>

    <?php if(!empty($success)): ?>
        <div class="success">
            <?php echo htmlspecialchars($success); ?>
            <br><br>
            <a href="login.php" style="color: #155724; font-weight: bold; text-decoration: underline;">Gara Login Deemi (Go to Login)</a>
        </div>
    <?php else: ?>
        <form method="POST" action="forgot_password.php">
            <input type="email" name="email" placeholder="Email kee (Your registered email)" required value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
            <input type="password" name="new_password" placeholder="Password Haaraa (New Password)" required minlength="6">
            <input type="password" name="confirm_password" placeholder="Password Mirkaneessi (Confirm Password)" required minlength="6">
            <button type="submit" name="reset_password">Jijjiiri (Reset Password)</button>
        </form>
    <?php endif; ?>

    <div class="links">
        <a href="login.php">Gara Login (Back to Login)</a> | 
        <a href="register.php">Account Haaraa (Register)</a>
    </div>
</div>

</body>
</html>
