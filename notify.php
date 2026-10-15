<?php
// Admin registration notification helper

function notify_admin_new_registration($name, $email, $method = "Manual Form") {
    global $conn, $admin_email;

    $recipient = !empty($admin_email) ? $admin_email : "ahmedreshid695@gmail.com";
    $time = date("Y-m-d H:i:s");
    $subject = "New Student Registration: " . $name;

    // HTML Email Template
    $message = "
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset='UTF-8'>
        <title>New Student Registration</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }
            .container { background-color: #ffffff; padding: 25px; border-radius: 8px; max-width: 520px; margin: auto; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
            .header { border-bottom: 2px solid #28a745; padding-bottom: 12px; margin-bottom: 20px; }
            .header h2 { margin: 0; color: #28a745; font-size: 20px; }
            .content p { font-size: 15px; color: #333; line-height: 1.6; }
            .info-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            .info-table td { padding: 8px 12px; border-bottom: 1px solid #eee; font-size: 14px; }
            .info-table td.label { font-weight: bold; color: #555; width: 35%; }
            .footer { margin-top: 25px; font-size: 12px; color: #888; text-align: center; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h2>🎉 New Student Registration</h2>
            </div>
            <div class='content'>
                <p>Hello Admin, a new student has successfully registered on the portal:</p>
                <table class='info-table'>
                    <tr>
                        <td class='label'>Full Name:</td>
                        <td><strong>" . htmlspecialchars($name) . "</strong></td>
                    </tr>
                    <tr>
                        <td class='label'>Student Email:</td>
                        <td>" . htmlspecialchars($email) . "</td>
                    </tr>
                    <tr>
                        <td class='label'>Registration Method:</td>
                        <td>" . htmlspecialchars($method) . "</td>
                    </tr>
                    <tr>
                        <td class='label'>Date &amp; Time:</td>
                        <td>" . $time . "</td>
                    </tr>
                </table>
            </div>
            <div class='footer'>
                This is an automated notification from the Alnasrii University Student Portal system.
            </div>
        </div>
    </body>
    </html>
    ";

    // Headers
    $headers  = "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    $headers .= "From: Alnasrii University Portal <no-reply@guuta-portal.com>\r\n";
    $headers .= "Reply-To: " . $email . "\r\n";

    // 1. Send Email
    $mail_sent = @mail($recipient, $subject, $message, $headers);

    // 2. Save to local notifications log (always reliable, even without local SMTP)
    $log_line = "[" . $time . "] NEW REGISTRATION -> Name: $name | Email: $email | Method: $method | Sent to: $recipient | Status: " . ($mail_sent ? "SUCCESS" : "SENT_ATTEMPT") . PHP_EOL;
    @file_put_contents(__DIR__ . '/notifications.log', $log_line, FILE_APPEND);

    // 3. Optional: save to database if notifications table exists
    if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
        $db_title = "New Student: " . $name;
        $db_msg = "Student $name ($email) has registered via $method.";
        @$conn->query("CREATE TABLE IF NOT EXISTS notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            student_email VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        $stmt = $conn->prepare("INSERT INTO notifications (title, message, student_email) VALUES (?, ?, ?)");
        if ($stmt) {
            $stmt->bind_param("sss", $db_title, $db_msg, $email);
            $stmt->execute();
            $stmt->close();
        }
    }

    return $mail_sent;
}
?>
