<?php
include 'config.php';

$error = "";
$success = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_password'])) {
    $email = trim($_POST['email'] ?? '');
    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if (empty($email) || empty($new_password) || empty($confirm_password)) {
        $error = "Hundaa guutuu qabdu! (Please fill all fields!)";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Email sirrii galchaa! (Invalid email address)";
    } elseif (!preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $email)) {
        $error = "Email Google (@gmail.com) qofatu heyyamama! (Only @gmail.com is allowed!)";
    } elseif (strlen($new_password) < 6) {
        $error = "Password-n yoo xiqqaate qubee/lakkoofsa 6 ta'uu qaba! (Password must be at least 6 characters!)";
    } elseif ($new_password !== $confirm_password) {
        $error = "Password-n wal hin simne! (Passwords do not match!)";
    } else {
        // Check if email exists
        $stmt = $conn->prepare("SELECT id FROM students WHERE email = ?");
        if ($stmt) {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows === 0) {
                $error = "Email kun hin galmoofne! (Email not found!)";
            } else {
                $stmt->close();
                $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                $update_stmt = $conn->prepare("UPDATE students SET password = ? WHERE email = ?");
                if ($update_stmt) {
                    $update_stmt->bind_param("ss", $hashed_password, $email);
                    if ($update_stmt->execute()) {
                        $success = "Password haaraan milkaa'inaan jijjiirameera! (Password successfully updated!)";
                    } else {
                        $error = "Dogoggorri uumameera: " . $update_stmt->error;
                    }
                    $update_stmt->close();
                } else {
                    $error = "Database error: " . $conn->error;
                }
            }
        } else {
            $error = "Database query error: " . $conn->error;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Alnasrii University - Reset Password</title>

  <!-- Google Fonts: Inter -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">

  <!-- Tailwind CSS -->
  <script src="https://cdn.tailwindcss.com"></script>

  <style>
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
    .card-bg {
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
      background-color: #064e3b;
      transition: background-image 0.4s ease-in-out;
    }
  </style>
</head>
<body class="min-h-screen bg-slate-900 flex items-center justify-center p-4 selection:bg-green-500 selection:text-white">

  <!-- Decorative background lights -->
  <div class="fixed inset-0 overflow-hidden pointer-events-none">
    <div class="absolute -top-40 -left-40 w-96 h-96 bg-green-600/20 rounded-full blur-3xl"></div>
    <div class="absolute -bottom-40 -right-40 w-96 h-96 bg-emerald-500/20 rounded-full blur-3xl"></div>
  </div>

  <div class="relative w-full max-w-md my-8">

    <!-- Card -->
    <div id="cardBg" class="card-bg relative w-full rounded-2xl shadow-2xl overflow-hidden border border-white/10">

      <div class="absolute inset-0 bg-gradient-to-b from-green-800/90 via-green-900/95 to-slate-950/95"></div>

      <div class="relative z-10 p-6 sm:p-8">

        <!-- Header -->
        <div class="text-center mb-6">
          <div class="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-white/10 border border-white/20 mb-3 shadow-inner backdrop-blur-md">
            <span class="text-2xl">🔑</span>
          </div>
          <h1 class="text-3xl font-extrabold text-white tracking-tight mb-1">Reset Password</h1>
          <p class="text-green-200 text-sm font-medium">Alnasrii University Security Center</p>
        </div>

        <!-- Alert Banners -->
        <?php if(!empty($error)): ?>
          <div class="mb-5 p-3 rounded-lg bg-red-500/25 border border-red-400/50 text-red-100 text-xs flex items-center gap-2">
            <svg class="w-4 h-4 flex-shrink-0 text-red-300" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>
            <span><?php echo htmlspecialchars($error); ?></span>
          </div>
        <?php endif; ?>

        <?php if(!empty($success)): ?>
          <div class="mb-5 p-4 rounded-xl bg-emerald-500/25 border border-emerald-400/50 text-emerald-100 text-xs text-center space-y-3">
            <p class="font-semibold text-sm"><?php echo htmlspecialchars($success); ?></p>
            <a href="login.php" class="inline-block bg-white text-green-800 font-bold px-4 py-2 rounded-lg hover:bg-green-50 transition shadow text-xs">
              Gara Login Deemi (Sign In Now) &rarr;
            </a>
          </div>
        <?php else: ?>
          <form method="POST" action="forgot_password.php" class="space-y-4">

            <!-- Registered Email -->
            <div>
              <label for="email" class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Registered Email</label>
              <input
                id="email" name="email" type="email"
                value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>"
                placeholder="student@gmail.com"
                class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 focus:bg-white transition shadow-sm"
                required
              />
            </div>

            <!-- New Password -->
            <div>
              <label for="new_password" class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">New Password</label>
              <div class="relative">
                <input
                  id="new_password" name="new_password" type="password"
                  placeholder="At least 6 characters"
                  class="w-full px-4 py-2.5 pr-14 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 focus:bg-white transition shadow-sm"
                  required minlength="6"
                />
                <button type="button" data-toggle="new_password"
                  class="absolute right-2.5 top-1/2 -translate-y-1/2 px-2 py-1 text-gray-500 hover:text-gray-800 text-xs font-semibold rounded cursor-pointer select-none transition">
                  Show
                </button>
              </div>
            </div>

            <!-- Confirm Password -->
            <div>
              <label for="confirm_password" class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Confirm New Password</label>
              <div class="relative">
                <input
                  id="confirm_password" name="confirm_password" type="password"
                  placeholder="Repeat new password"
                  class="w-full px-4 py-2.5 pr-14 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 focus:bg-white transition shadow-sm"
                  required minlength="6"
                />
                <button type="button" data-toggle="confirm_password"
                  class="absolute right-2.5 top-1/2 -translate-y-1/2 px-2 py-1 text-gray-500 hover:text-gray-800 text-xs font-semibold rounded cursor-pointer select-none transition">
                  Show
                </button>
              </div>
            </div>

            <button
              type="submit" name="reset_password"
              class="w-full mt-2 bg-white text-green-800 font-bold py-3 rounded-lg shadow-lg hover:bg-green-50 active:scale-[0.99] transition-all duration-200 text-sm tracking-wide"
            >
              Reset My Password
            </button>
          </form>
        <?php endif; ?>

        <!-- Footer Links -->
        <div class="mt-6 pt-5 border-t border-white/20 flex items-center justify-between text-xs text-white/90">
          <a href="login.php" class="hover:text-green-200 underline font-medium">
            &larr; Back to Login
          </a>
          <a href="register.php" class="hover:text-green-200 underline font-semibold">
            Create Account
          </a>
        </div>

      </div>
    </div>
  </div>

  <script>
    // Restore shared background photo if stored
    window.addEventListener('DOMContentLoaded', () => {
      const savedBg = localStorage.getItem('alnasrii_bg_data');
      if (savedBg) {
        document.getElementById('cardBg').style.backgroundImage = "url('" + savedBg + "')";
      }
    });

    // Toggle password visibility
    document.querySelectorAll('[data-toggle]').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-toggle');
        const input = document.getElementById(targetId);
        if (!input) return;
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        btn.textContent = isPassword ? 'Hide' : 'Show';
      });
    });
  </script>
</body>
</html>
