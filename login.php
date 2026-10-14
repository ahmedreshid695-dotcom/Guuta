<?php
include 'config.php';

// Redirect if already logged in
if (isset($_SESSION['student_name'])) {
    header("Location: index.php");
    exit();
}

$error = "";
$registered_notice = isset($_GET['registered']) && $_GET['registered'] == '1';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && (isset($_POST['login']) || isset($_POST['email']))) {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($email) || empty($password)) {
        $error = "Email fi password galchuun barbaachisaadha! (Please enter both email and password)";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Email sirrii galchaa! (Invalid email format)";
    } elseif (!preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $email)) {
        $error = "Email Google (@gmail.com) qofatu heyyamama! (Only @gmail.com is allowed)";
    } else {
        $stmt = $conn->prepare("SELECT id, name, email, password FROM students WHERE email = ?");
        if ($stmt) {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($id, $name, $email_db, $hash);

            if ($stmt->num_rows > 0) {
                $stmt->fetch();
                if (password_verify($password, $hash)) {
                    if (!is_admin($email_db)) {
                        $error = "Dhiifama! Fuulli Sign In kun Administrator qofaaf heyyamama. Barattoonni fuula duraa irratti galmaa'uu qofa danda'u. (Sign In is restricted to Administrators only.)";
                    } else {
                        $_SESSION['student_id'] = $id;
                        $_SESSION['student_name'] = $name;
                        $_SESSION['student_email'] = $email_db;
                        $_SESSION['student_role'] = 'admin';
                        header("Location: index.php");
                        exit();
                    }
                } else {
                    $error = "Password dogoggora! Irra deebi'aa yaalaa. (Wrong password!)";
                }
            } else {
                $error = "Account-n email kanaan galmaa'e hin argamne! (User not found!)";
            }
            $stmt->close();
        } else {
            $error = "Database query error: " . $conn->error;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Alnasrii University - Student Login</title>

  <!-- Google Fonts: Inter -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">

  <!-- Tailwind CSS (CDN) -->
  <script src="https://cdn.tailwindcss.com"></script>

  <style>
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      margin: 0;
    }

    .card-bg {
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
      background-color: #064e3b;
      transition: background-image 0.4s ease-in-out;
    }

    @keyframes slideDown {
      from { opacity: 0; transform: translateY(-10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .animate-slide-down {
      animation: slideDown 0.3s ease-out forwards;
    }
  </style>
</head>
<body class="min-h-screen bg-slate-900 flex items-center justify-center p-4 selection:bg-green-500 selection:text-white">

  <!-- Decorative background ambient lights -->
  <div class="fixed inset-0 overflow-hidden pointer-events-none">
    <div class="absolute -top-40 -left-40 w-96 h-96 bg-green-600/20 rounded-full blur-3xl"></div>
    <div class="absolute -bottom-40 -right-40 w-96 h-96 bg-emerald-500/20 rounded-full blur-3xl"></div>
  </div>

  <div class="relative w-full max-w-md my-8">

    <!-- Card with dynamic background photo -->
    <div id="cardBg" class="card-bg relative w-full rounded-2xl shadow-2xl overflow-hidden border border-white/10 transition-all duration-300">

      <!-- Green overlay layer -->
      <div class="absolute inset-0 bg-gradient-to-b from-green-800/90 via-green-900/95 to-slate-950/95"></div>

      <!-- Content -->
      <div class="relative z-10 p-6 sm:p-8">

        <!-- Header -->
        <div class="text-center mb-6">
          <div class="site-logo-badge inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-white/10 border border-white/20 mb-3 shadow-inner backdrop-blur-md overflow-hidden">
            <?php $site_logo = get_site_logo(); if($site_logo): ?>
              <img src="<?php echo $site_logo; ?>" alt="Logo" class="w-full h-full object-cover site-logo-img" />
            <?php else: ?>
              <span class="text-2xl site-logo-fallback">🎓</span>
            <?php endif; ?>
          </div>
          <h1 class="text-3xl font-extrabold text-white tracking-tight mb-1">Alnasrii University</h1>
          <p class="text-amber-300 text-xs font-semibold uppercase tracking-wider mb-2">🔒 Administrator Sign In</p>
          <div class="p-2 rounded-xl bg-amber-500/15 border border-amber-500/30 text-amber-200 text-[11px] flex items-center justify-center gap-2">
            <span>⚠️</span>
            <span>Fuulli kun Administrator qofaafi. Barattoonni fuula duraa irratti galmaa'u qofa danda'u.</span>
          </div>
        </div>

        <!-- Registration Success Flash Notice -->
        <?php if($registered_notice): ?>
          <div class="mb-5 p-3 rounded-lg bg-emerald-500/25 border border-emerald-400/50 text-emerald-100 text-xs flex items-center gap-2 animate-slide-down">
            <svg class="w-4 h-4 flex-shrink-0 text-emerald-300" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>
            <span>Galmeen milkaa'eera! Amma email fi password keessaniin seenaa. (Registration successful, please sign in)</span>
          </div>
        <?php endif; ?>

        <!-- Error Banner -->
        <?php if(!empty($error)): ?>
          <div class="mb-5 p-3 rounded-lg bg-red-500/25 border border-red-400/50 text-red-100 text-xs flex items-center gap-2 animate-slide-down">
            <svg class="w-4 h-4 flex-shrink-0 text-red-300" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>
            <span><?php echo htmlspecialchars($error); ?></span>
          </div>
        <?php endif; ?>

        <!-- Form -->
        <form method="POST" action="login.php" class="space-y-4" id="loginForm">

          <!-- Email -->
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label for="email" class="text-white text-xs font-semibold uppercase tracking-wider">Email Address</label>
              <span class="text-[11px] text-green-200/90 font-mono">(@gmail.com)</span>
            </div>
            <input
              id="email" name="email" type="email"
              value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>"
              placeholder="student@gmail.com"
              class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 focus:bg-white transition shadow-sm"
              required
            />
          </div>

          <!-- Password -->
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label for="password" class="text-white text-xs font-semibold uppercase tracking-wider">Password</label>
            </div>
            <div class="relative">
              <input
                id="password" name="password" type="password"
                placeholder="Enter your password"
                class="w-full px-4 py-2.5 pr-14 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 focus:bg-white transition shadow-sm"
                required
              />
              <button type="button" data-toggle="password"
                class="absolute right-2.5 top-1/2 -translate-y-1/2 px-2 py-1 text-gray-500 hover:text-gray-800 text-xs font-semibold rounded cursor-pointer select-none transition">
                Show
              </button>
            </div>
          </div>

          <!-- Remember Me + Forgot Password -->
          <div class="flex items-center justify-between text-xs pt-1">
            <label class="flex items-center gap-2 text-white/95 cursor-pointer select-none">
              <input type="checkbox" id="rememberMe"
                class="w-4 h-4 rounded text-green-600 focus:ring-green-400 accent-green-400 cursor-pointer" />
              <span>Remember me</span>
            </label>
            <a href="forgot_password.php" class="text-green-200 hover:text-white font-medium underline underline-offset-2 transition">
              Forgot password?
            </a>
          </div>

          <!-- Submit Button -->
          <button
            type="submit" name="login" id="submitBtn"
            class="w-full mt-2 bg-white text-green-800 font-bold py-3 rounded-lg shadow-lg hover:bg-green-50 active:scale-[0.99] transition-all duration-200 flex items-center justify-center gap-2 text-sm tracking-wide"
          >
            <span>Sign In to Account</span>
          </button>
        </form>

        <!-- Footer -->
        <div class="mt-6 pt-5 border-t border-white/20 space-y-4">

          <p class="text-center text-white/90 text-xs">
            Don't have an account?
            <a href="index.php" class="text-white font-bold underline underline-offset-2 hover:text-green-200 transition ml-1">Create Account</a>
          </p>

          <div class="flex items-center gap-3">
            <div class="flex-1 h-px bg-white/20"></div>
            <span class="text-white/70 text-[11px] uppercase tracking-wider font-semibold">or continue with</span>
            <div class="flex-1 h-px bg-white/20"></div>
          </div>

          <!-- Google + GitHub Buttons -->
          <div class="grid grid-cols-2 gap-3">

            <!-- Google Button -->
            <button type="button" id="googleCustomBtn"
              class="flex items-center justify-center gap-2 bg-white text-gray-700 font-semibold py-2.5 px-3 rounded-lg shadow hover:bg-gray-100 active:scale-[0.98] transition text-xs">
              <svg class="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
              </svg>
              <span>Google</span>
            </button>

            <!-- GitHub Button -->
            <button type="button" id="githubCustomBtn"
              class="flex items-center justify-center gap-2 bg-slate-900/90 hover:bg-slate-900 text-white font-semibold py-2.5 px-3 rounded-lg shadow border border-white/10 active:scale-[0.98] transition text-xs">
              <svg class="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 .5C5.37.5 0 5.87 0 12.5c0 5.3 3.44 9.8 8.21 11.39.6.11.82-.26.82-.58 0-.29-.01-1.05-.02-2.06-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.73.08-.73 1.21.09 1.84 1.24 1.84 1.24 1.07 1.83 2.81 1.3 3.5.99.11-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.12-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.28-1.55 3.29-1.23 3.29-1.23.66 1.66.25 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.81 5.62-5.49 5.92.43.37.81 1.1.81 2.22 0 1.61-.01 2.9-.01 3.29 0 .32.21.7.83.58A12.01 12.01 0 0 0 24 12.5C24 5.87 18.63.5 12 .5z"/>
              </svg>
              <span>GitHub</span>
            </button>
          </div>

          <!-- Hidden container for Google Identity Services -->
          <div id="g_id_onload"
               data-client_id="<?php echo htmlspecialchars($google_client_id); ?>"
               data-context="signin"
               data-ux_mode="popup"
               data-callback="handleGoogleCredentialResponse"
               data-auto_prompt="false"
               style="display:none;">
          </div>

        </div>

      </div>
    </div>
  </div>

  <script src="https://accounts.google.com/gsi/client" async defer></script>
  <script>
    const cardBg = document.getElementById('cardBg');
    const emailInput = document.getElementById('email');
    const rememberMeCheckbox = document.getElementById('rememberMe');
    const loginForm = document.getElementById('loginForm');

    // Restore background & remembered email & logo
    window.addEventListener('DOMContentLoaded', () => {
      const savedBgData = localStorage.getItem('alnasrii_bg_data');
      if (savedBgData) {
        cardBg.style.backgroundImage = "url('" + savedBgData + "')";
      }

      // Restore custom logo
      const savedLogo = localStorage.getItem('alnasrii_logo_data');
      if (savedLogo) {
        document.querySelectorAll('.site-logo-badge').forEach(el => {
          let img = el.querySelector('img.site-logo-img');
          let fallback = el.querySelector('.site-logo-fallback');
          if (!img) {
            img = document.createElement('img');
            img.className = 'w-full h-full object-cover site-logo-img';
            img.alt = 'Logo';
            el.appendChild(img);
          }
          img.src = savedLogo;
          img.classList.remove('hidden');
          if (fallback) fallback.classList.add('hidden');
        });
      }

      const rememberedEmail = localStorage.getItem('alnasrii_remembered_email');
      if (rememberedEmail && emailInput && !emailInput.value) {
        emailInput.value = rememberedEmail;
        if (rememberMeCheckbox) rememberMeCheckbox.checked = true;
      }
    });

    // Handle remember me on submit
    loginForm.addEventListener('submit', () => {
      if (rememberMeCheckbox.checked) {
        localStorage.setItem('alnasrii_remembered_email', emailInput.value.trim());
      } else {
        localStorage.removeItem('alnasrii_remembered_email');
      }
    });

    // Password Toggle
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

    // Google Sign-In
    function handleGoogleCredentialResponse(response) {
      if (!response.credential) return;

      fetch('google_login.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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

    document.getElementById('googleCustomBtn').addEventListener('click', () => {
      if (window.google && google.accounts && google.accounts.id) {
        google.accounts.id.prompt();
      } else {
        alert('Google Sign-In is loading or blocked by your browser extensions.');
      }
    });

    document.getElementById('githubCustomBtn').addEventListener('click', () => {
      alert("GitHub Sign-In: Alnasrii University GitHub OAuth tajaajilli yeroo dhiyootti ni eegala. Yeroof Google ykn Form fayyadamaa.");
    });
  </script>
</body>
</html>