<?php
include 'config.php';

// Handle AJAX or Standard POST submission
$is_ajax = (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') 
        || (isset($_SERVER['CONTENT_TYPE']) && strpos($_SERVER['CONTENT_TYPE'], 'application/json') !== false)
        || (isset($_POST['is_ajax']) && $_POST['is_ajax'] === '1');

$error = "";
$success = "";
$error_field = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST' && (isset($_POST['fullName']) || isset($_POST['name']) || isset($_POST['register']))) {
    $fullName = trim($_POST['fullName'] ?? $_POST['name'] ?? '');
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirmPassword'] ?? '';

    // Validation
    if (empty($fullName)) {
        $error = "Maqaa guutuu galchuun barbaachisaadha! (Full name is required)";
        $error_field = "fullName";
    } elseif (mb_strlen($fullName) < 3) {
        $error = "Maqaan yoo xiqqaate qubee 3 ta'uu qaba! (Full name must be at least 3 characters)";
        $error_field = "fullName";
    } elseif (empty($email)) {
        $error = "Email galchuun barbaachisaadha! (Email is required)";
        $error_field = "email";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Email sirrii galchaa! (Please enter a valid email address)";
        $error_field = "email";
    } elseif (!preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $email)) {
        $error = "Email Google (@gmail.com) qofatu heyyamama! (Only @gmail.com is allowed)";
        $error_field = "email";
    } elseif (empty($password)) {
        $error = "Password galchuun barbaachisaadha! (Password is required)";
        $error_field = "password";
    } elseif (strlen($password) < 6) {
        $error = "Password-n yoo xiqqaate qubee/lakkoofsa 6 ta'uu qaba! (Password must be at least 6 characters)";
        $error_field = "password";
    } elseif (!empty($confirmPassword) && $password !== $confirmPassword) {
        $error = "Password-n wal hin simne! (Passwords do not match)";
        $error_field = "confirmPassword";
    } else {
        // Check duplicate email
        $stmt = $conn->prepare("SELECT id FROM students WHERE email = ?");
        if ($stmt) {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                $error = "Email kun duraan galmaa'ee jira! Gara Login deemaa. (Email already registered!)";
                $error_field = "email";
            } else {
                $stmt->close();
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                $insert_stmt = $conn->prepare("INSERT INTO students (name, email, password) VALUES (?, ?, ?)");
                if ($insert_stmt) {
                    $insert_stmt->bind_param("sss", $fullName, $email, $hashed_password);
                    if ($insert_stmt->execute()) {
                        $success = "Registration successful! Welcome to Alnasrii University 🎓";
                        
                        // Send notification to admin
                        if (file_exists('notify.php')) {
                            require_once 'notify.php';
                            if (function_exists('notify_admin_new_registration')) {
                                @notify_admin_new_registration($fullName, $email, "Alnasrii Form Galmee");
                            }
                        }
                    } else {
                        $error = "Dogoggorri galmee uumame: " . $insert_stmt->error;
                    }
                    $insert_stmt->close();
                } else {
                    $error = "Database error: " . $conn->error;
                }
            }
        } else {
            $error = "Database query failed: " . $conn->error;
        }
    }

    if ($is_ajax) {
        header('Content-Type: application/json');
        if (!empty($error)) {
            echo json_encode(['success' => false, 'message' => $error, 'field' => $error_field]);
        } else {
            echo json_encode([
                'success' => true, 
                'message' => $success, 
                'redirect' => 'login.php?registered=1'
            ]);
        }
        exit();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Alnasrii University - Registration</title>

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

    /* Background photo container - default fallback color */
    .card-bg {
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
      background-color: #064e3b;
      transition: background-image 0.4s ease-in-out;
    }

    /* Subtle animation for toast notifications */
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

      <!-- Green overlay with optimized opacity for photo transparency -->
      <div id="overlayLayer" class="absolute inset-0 bg-gradient-to-b from-green-800/90 via-green-900/95 to-slate-950/95 transition-opacity duration-300"></div>

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
          <p class="text-green-200 text-sm font-medium">Create your official student account</p>
        </div>


        <!-- Server-side alert fallback if rendered via normal POST -->
        <?php if(!empty($error)): ?>
          <div id="serverError" class="mb-5 p-3 rounded-lg bg-red-500/20 border border-red-400/40 text-red-100 text-xs flex items-center gap-2 animate-slide-down">
            <svg class="w-4 h-4 flex-shrink-0 text-red-300" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>
            <span><?php echo htmlspecialchars($error); ?></span>
          </div>
        <?php endif; ?>

        <?php if(!empty($success)): ?>
          <div id="serverSuccess" class="mb-5 p-3 rounded-lg bg-green-500/20 border border-green-400/40 text-green-100 text-xs flex items-center gap-2 animate-slide-down">
            <svg class="w-4 h-4 flex-shrink-0 text-green-300" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>
            <span><?php echo htmlspecialchars($success); ?></span>
          </div>
        <?php endif; ?>

        <!-- Form -->
        <form id="registrationForm" method="POST" action="register.php" class="space-y-4" novalidate>
          <input type="hidden" name="register" value="1">
          <input type="hidden" name="is_ajax" id="isAjaxInput" value="1">

          <!-- Full Name -->
          <div>
            <label for="fullName" class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Full Name</label>
            <input
              id="fullName" name="fullName" type="text"
              value="<?php echo isset($_POST['fullName']) ? htmlspecialchars($_POST['fullName']) : ''; ?>"
              placeholder="e.g. Guuta Ahmed"
              class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 focus:bg-white transition shadow-sm"
              required
            />
            <p class="text-red-300 text-xs mt-1.5 font-medium hidden" data-error="fullName"></p>
          </div>

          <!-- Email Address -->
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label for="email" class="text-white text-xs font-semibold uppercase tracking-wider">Email Address</label>
              <span class="text-[11px] text-green-200/90 font-mono">(@gmail.com only)</span>
            </div>
            <input
              id="email" name="email" type="email"
              value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>"
              placeholder="student@gmail.com"
              class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 focus:bg-white transition shadow-sm"
              required
            />
            <p class="text-red-300 text-xs mt-1.5 font-medium hidden" data-error="email"></p>
          </div>

          <!-- Password -->
          <div>
            <label for="password" class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Password</label>
            <div class="relative">
              <input
                id="password" name="password" type="password"
                placeholder="Minimum 6 characters"
                class="w-full px-4 py-2.5 pr-14 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 focus:bg-white transition shadow-sm"
                required
              />
              <button type="button" data-toggle="password"
                class="absolute right-2.5 top-1/2 -translate-y-1/2 px-2 py-1 text-gray-500 hover:text-gray-800 text-xs font-semibold rounded cursor-pointer select-none transition">
                Show
              </button>
            </div>
            <p class="text-red-300 text-xs mt-1.5 font-medium hidden" data-error="password"></p>
          </div>

          <!-- Confirm Password -->
          <div>
            <label for="confirmPassword" class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Confirm Password</label>
            <div class="relative">
              <input
                id="confirmPassword" name="confirmPassword" type="password"
                placeholder="Repeat your password"
                class="w-full px-4 py-2.5 pr-14 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 focus:bg-white transition shadow-sm"
                required
              />
              <button type="button" data-toggle="confirmPassword"
                class="absolute right-2.5 top-1/2 -translate-y-1/2 px-2 py-1 text-gray-500 hover:text-gray-800 text-xs font-semibold rounded cursor-pointer select-none transition">
                Show
              </button>
            </div>
            <p class="text-red-300 text-xs mt-1.5 font-medium hidden" data-error="confirmPassword"></p>
          </div>

          <!-- Remember Me + Forgot Password -->
          <div class="flex items-center justify-between text-xs pt-1">
            <label class="flex items-center gap-2 text-white/95 cursor-pointer select-none">
              <input type="checkbox" id="rememberMe" name="rememberMe"
                class="w-4 h-4 rounded text-green-600 focus:ring-green-400 accent-green-400 cursor-pointer" />
              <span>Remember me</span>
            </label>
            <a href="forgot_password.php" class="text-green-200 hover:text-white font-medium underline underline-offset-2 transition">
              Forgot password?
            </a>
          </div>

          <!-- Submit Button -->
          <button
            type="submit" id="submitBtn"
            class="w-full mt-2 bg-white text-green-800 font-bold py-3 rounded-lg shadow-lg hover:bg-green-50 active:scale-[0.99] transition-all duration-200 disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-2 text-sm tracking-wide"
          >
            <span id="btnSpinner" class="hidden">
              <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-green-800" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
              </svg>
            </span>
            <span id="btnText">Create Account</span>
          </button>

          <!-- Dynamic AJAX Success Message -->
          <div id="successMessage" class="hidden bg-emerald-500/25 border border-emerald-400/50 text-emerald-100 text-xs text-center py-2.5 px-3 rounded-lg font-medium animate-slide-down"></div>
        </form>

        <!-- Footer -->
        <div class="mt-6 pt-5 border-t border-white/20 space-y-4">

          <p class="text-center text-white/90 text-xs">
            Already have an account?
            <a href="login.php" class="text-white font-bold underline underline-offset-2 hover:text-green-200 transition ml-1">Sign In</a>
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
               data-context="signup"
               data-ux_mode="popup"
               data-callback="handleGoogleCredentialResponse"
               data-auto_prompt="false"
               style="display:none;">
          </div>
          <div id="hiddenGoogleBtn" style="display:none;"></div>

        </div>

      </div>
    </div>
  </div>

  <!-- Google Identity Client -->
  <script src="https://accounts.google.com/gsi/client" async defer></script>

  <!-- JavaScript logic -->
  <script>
    const form = document.getElementById('registrationForm');
    const submitBtn = document.getElementById('submitBtn');
    const btnSpinner = document.getElementById('btnSpinner');
    const btnText = document.getElementById('btnText');
    const successMessage = document.getElementById('successMessage');
    const cardBg = document.getElementById('cardBg');
    const bgUpload = document.getElementById('bgUpload');
    const resetBgBtn = document.getElementById('resetBgBtn');
    const bgPhotoName = document.getElementById('bgPhotoName');

    // ===== Restore Saved Background & Remembered Email on Load =====
    window.addEventListener('DOMContentLoaded', () => {
      // 1. Restore background photo
      const savedBgData = localStorage.getItem('alnasrii_bg_data');
      const savedBgName = localStorage.getItem('alnasrii_bg_name');
      if (savedBgData) {
        cardBg.style.backgroundImage = "url('" + savedBgData + "')";
        if (resetBgBtn) resetBgBtn.classList.remove('hidden');
        if (bgPhotoName && savedBgName) {
          bgPhotoName.textContent = "Photo: " + savedBgName;
          bgPhotoName.classList.remove('hidden');
        }
      }

      // 2. Restore remembered email
      const rememberedEmail = localStorage.getItem('alnasrii_remembered_email');
      const emailInput = document.getElementById('email');
      const rememberMeCheckbox = document.getElementById('rememberMe');
      if (rememberedEmail && emailInput && !emailInput.value) {
        emailInput.value = rememberedEmail;
        if (rememberMeCheckbox) rememberMeCheckbox.checked = true;
      }
    });

    // ===== Dynamic Background Photo Upload =====
    bgUpload.addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (event) => {
        const dataUrl = event.target.result;
        cardBg.style.backgroundImage = "url('" + dataUrl + "')";
        try {
          localStorage.setItem('alnasrii_bg_data', dataUrl);
          localStorage.setItem('alnasrii_bg_name', file.name);
        } catch (err) {
          console.warn('LocalStorage limit reached for photo cache:', err);
        }

        if (resetBgBtn) resetBgBtn.classList.remove('hidden');
        if (bgPhotoName) {
          bgPhotoName.textContent = "Photo: " + file.name;
          bgPhotoName.classList.remove('hidden');
        }
      };
      reader.readAsDataURL(file);
    });

    // ===== Reset Background to Default =====
    if (resetBgBtn) {
      resetBgBtn.addEventListener('click', () => {
        cardBg.style.backgroundImage = 'none';
        localStorage.removeItem('alnasrii_bg_data');
        localStorage.removeItem('alnasrii_bg_name');
        bgUpload.value = '';
        resetBgBtn.classList.add('hidden');
        if (bgPhotoName) {
          bgPhotoName.textContent = '';
          bgPhotoName.classList.add('hidden');
        }
      });
    }

    // ===== Show / Hide Password Toggle =====
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

    // ===== Error Presentation Helpers =====
    function showError(field, message) {
      const el = document.querySelector(`[data-error="${field}"]`);
      const input = document.getElementById(field);
      if (el) {
        el.textContent = message;
        el.classList.remove('hidden');
      }
      if (input) {
        input.classList.add('ring-2', 'ring-red-500');
        input.classList.remove('focus:ring-green-400');
      }
    }

    function clearErrors() {
      document.querySelectorAll('[data-error]').forEach(el => {
        el.textContent = '';
        el.classList.add('hidden');
      });
      document.querySelectorAll('input').forEach(i => {
        i.classList.remove('ring-2', 'ring-red-500');
        i.classList.add('focus:ring-green-400');
      });
      const serverErr = document.getElementById('serverError');
      if (serverErr) serverErr.remove();
    }

    // ===== Client-Side Validation =====
    function validate() {
      clearErrors();
      let valid = true;

      const fullName = document.getElementById('fullName').value.trim();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const confirmPassword = document.getElementById('confirmPassword').value;

      if (!fullName) {
        showError('fullName', 'Full name is required (Maqaa guutuu galchaa)');
        valid = false;
      } else if (fullName.length < 3) {
        showError('fullName', 'Full name must be at least 3 characters');
        valid = false;
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!email) {
        showError('email', 'Email is required (Email galchaa)');
        valid = false;
      } else if (!emailRegex.test(email)) {
        showError('email', 'Please enter a valid email address');
        valid = false;
      } else if (!email.toLowerCase().endsWith('@gmail.com')) {
        showError('email', 'Email Google (@gmail.com) qofatu heyyamama! (Only @gmail.com)');
        valid = false;
      }

      if (!password) {
        showError('password', 'Password is required');
        valid = false;
      } else if (password.length < 6) {
        showError('password', 'Password must be at least 6 characters');
        valid = false;
      }

      if (!confirmPassword) {
        showError('confirmPassword', 'Please confirm your password');
        valid = false;
      } else if (password !== confirmPassword) {
        showError('confirmPassword', 'Passwords do not match (Wal hin simne)');
        valid = false;
      }

      return valid;
    }

    // ===== Form Submission via AJAX with Full Fallback =====
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      successMessage.classList.add('hidden');

      if (!validate()) return;

      // Handle Remember Me
      const rememberMe = document.getElementById('rememberMe').checked;
      const emailVal = document.getElementById('email').value.trim();
      if (rememberMe) {
        localStorage.setItem('alnasrii_remembered_email', emailVal);
      } else {
        localStorage.removeItem('alnasrii_remembered_email');
      }

      // UI Loading state
      submitBtn.disabled = true;
      btnSpinner.classList.remove('hidden');
      btnText.textContent = 'Creating Account...';

      const formData = new FormData(form);

      try {
        const response = await fetch('register.php', {
          method: 'POST',
          body: formData,
          headers: {
            'X-Requested-With': 'XMLHttpRequest'
          }
        });

        const data = await response.json();

        if (data.success) {
          successMessage.textContent = data.message || "Registration successful! Welcome to Alnasrii University 🎓";
          successMessage.classList.remove('hidden');
          btnText.textContent = 'Account Created! Redirecting...';
          btnSpinner.classList.add('hidden');
          form.reset();

          setTimeout(() => {
            window.location.href = data.redirect || 'login.php?registered=1';
          }, 1500);
        } else {
          submitBtn.disabled = false;
          btnSpinner.classList.add('hidden');
          btnText.textContent = 'Create Account';

          if (data.field) {
            showError(data.field, data.message);
          } else {
            showError('email', data.message || 'Galmeen hin milkoofne. Irra deebi\'aa yaalaa.');
          }
        }
      } catch (error) {
        console.warn('AJAX submission fell back to standard submit:', error);
        // Fallback to standard form post
        document.getElementById('isAjaxInput').value = '0';
        form.submit();
      }
    });

    // ===== Google Sign-In Handler =====
    function handleGoogleCredentialResponse(response) {
      if (!response.credential) return;

      submitBtn.disabled = true;
      btnText.textContent = 'Signing in with Google...';
      btnSpinner.classList.remove('hidden');

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
          submitBtn.disabled = false;
          btnSpinner.classList.add('hidden');
          btnText.textContent = 'Create Account';
        }
      })
      .catch(err => {
        console.error(err);
        alert('Server waliin wal qunnamuu hin dandeenye.');
        submitBtn.disabled = false;
        btnSpinner.classList.add('hidden');
        btnText.textContent = 'Create Account';
      });
    }

    // Google Button Click Trigger
    document.getElementById('googleCustomBtn').addEventListener('click', () => {
      if (window.google && google.accounts && google.accounts.id) {
        google.accounts.id.prompt();
      } else {
        alert('Google Sign-In is loading or blocked by your browser extensions.');
      }
    });

    // GitHub Button Handler
    document.getElementById('githubCustomBtn').addEventListener('click', () => {
      alert("GitHub Sign-In: Alnasrii University GitHub OAuth tajaajilli yeroo dhiyootti ni eegala. Yeroof Google ykn Form fayyadamaa.");
    });

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
  </script>
</body>
</html>