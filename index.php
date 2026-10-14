<?php
include 'config.php';
require_once 'notify.php';

// Handle Logout
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit();
}

$alert_message = "";
$alert_type = "";
$active_auth_tab = "register"; // default tab: register or login or forgot

// Handle Google Login via AJAX
if (isset($_GET['action']) && $_GET['action'] === 'google_auth') {
    header('Content-Type: application/json');
    $input = json_decode(file_get_contents('php://input'), true);
    $id_token = $input['credential'] ?? '';
    if (empty($id_token)) {
        echo json_encode(['success' => false, 'message' => 'Token not provided']);
        exit();
    }
    
    // Decode token safely
    $parts = explode('.', $id_token);
    $payload = null;
    if (count($parts) === 3) {
        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
    }
    
    if (!$payload || empty($payload['email'])) {
        echo json_encode(['success' => false, 'message' => 'Invalid Google token']);
        exit();
    }
    
    $g_email = $payload['email'];
    $g_name  = $payload['name'] ?? explode('@', $g_email)[0];
    $g_pic   = $payload['picture'] ?? '';
    
    // Check if exists
    $chk = $conn->prepare("SELECT id, name, email, role FROM students WHERE email = ?");
    $chk->bind_param("s", $g_email);
    $chk->execute();
    $chk->store_result();
    
    if ($chk->num_rows > 0) {
        $chk->bind_result($db_id, $db_name, $db_email, $db_role);
        $chk->fetch();
        $student_name = $db_name;
        $student_email = $db_email;
        $student_role = is_admin($db_email) ? 'admin' : ($db_role ?: 'student');
        $chk->close();
    } else {
        $chk->close();
        $g_pass = password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT);
        $g_role = is_admin($g_email) ? 'admin' : 'student';
        $ins = $conn->prepare("INSERT INTO students (name, email, password, role) VALUES (?, ?, ?, ?)");
        $ins->bind_param("ssss", $g_name, $g_email, $g_pass, $g_role);
        $ins->execute();
        $ins->close();
        $student_name = $g_name;
        $student_email = $g_email;
        $student_role = $g_role;
        @notify_admin_new_registration($g_name, $g_email, "Google Sign-In");
    }
    
    $_SESSION['student_name'] = $student_name;
    $_SESSION['student_email'] = $student_email;
    $_SESSION['student_role'] = $student_role;
    if (!empty($g_pic)) $_SESSION['student_picture'] = $g_pic;
    
    echo json_encode(['success' => true]);
    exit();
}

// Check logged in user
$is_logged_in = isset($_SESSION['student_name']) && isset($_SESSION['student_email']);
$current_name = $_SESSION['student_name'] ?? '';
$current_email = $_SESSION['student_email'] ?? '';
$current_pic = $_SESSION['student_picture'] ?? '';
$is_admin_user = $is_logged_in && is_admin($current_email);

// Ensure fresh profile data (name, picture, role) from DB
if ($is_logged_in) {
    $u_chk = $conn->prepare("SELECT name, picture, role FROM students WHERE email = ? LIMIT 1");
    if ($u_chk) {
        $u_chk->bind_param("s", $current_email);
        $u_chk->execute();
        $u_chk->bind_result($db_u_name, $db_u_pic, $db_u_role);
        if ($u_chk->fetch()) {
            if (!empty($db_u_name)) {
                $current_name = $db_u_name;
                $_SESSION['student_name'] = $current_name;
            }
            if (!empty($db_u_pic)) {
                $current_pic = $db_u_pic;
                $_SESSION['student_picture'] = $current_pic;
            }
            if ($db_u_role === 'admin' || is_admin($current_email)) {
                $is_admin_user = true;
                $_SESSION['student_role'] = 'admin';
            }
        }
        $u_chk->close();
    }
}

if ($is_admin_user) {
    @$conn->query("UPDATE students SET role = 'admin' WHERE email = '" . $conn->real_escape_string($current_email) . "'");
}

$curr_hour = (int)date('H');
$time_greeting = ($curr_hour < 12) ? 'GOOD MORNING' : (($curr_hour < 17) ? 'GOOD AFTERNOON' : 'GOOD EVENING');

// ==========================================
// HANDLE FORM SUBMISSIONS
// ==========================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // SUPER ADMIN PROFILE UPDATE (Name & Photo)
    if ($action === 'update_admin_profile' && $is_admin_user) {
        $new_admin_name = trim($_POST['admin_name'] ?? '');
        if (!empty($new_admin_name)) {
            $uploaded_pic_path = null;
            if (isset($_FILES['admin_photo']) && $_FILES['admin_photo']['error'] === UPLOAD_ERR_OK) {
                $uploads_dir = __DIR__ . '/uploads';
                if (!is_dir($uploads_dir)) @mkdir($uploads_dir, 0777, true);
                
                $ext = strtolower(pathinfo($_FILES['admin_photo']['name'], PATHINFO_EXTENSION) ?: 'png');
                $pic_filename = 'admin_avatar_' . md5($current_email) . '.' . $ext;
                $target_pic = $uploads_dir . '/' . $pic_filename;
                
                if (move_uploaded_file($_FILES['admin_photo']['tmp_name'], $target_pic)) {
                    $uploaded_pic_path = 'uploads/' . $pic_filename . '?v=' . time();
                }
            }

            if ($uploaded_pic_path) {
                $up = $conn->prepare("UPDATE students SET name = ?, picture = ? WHERE email = ?");
                $up->bind_param("sss", $new_admin_name, $uploaded_pic_path, $current_email);
                $up->execute();
                $up->close();
                $_SESSION['student_picture'] = $uploaded_pic_path;
                $current_pic = $uploaded_pic_path;
            } else {
                $up = $conn->prepare("UPDATE students SET name = ? WHERE email = ?");
                $up->bind_param("ss", $new_admin_name, $current_email);
                $up->execute();
                $up->close();
            }

            $_SESSION['student_name'] = $new_admin_name;
            $current_name = $new_admin_name;
            $alert_message = "Ragaan Super Admin (maqaa fi suuraan) milkaa'inaan haaromeera! (Super Admin profile updated successfully)";
            $alert_type = "success";
        } else {
            $alert_message = "Maqaan duwwaa ta'uu hin danda'u! (Name cannot be empty)";
            $alert_type = "error";
        }
    }

    // LOGO UPLOAD HANDLER (Admin)
    if ($action === 'upload_logo' && $is_admin_user) {
        $is_ajax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) || (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false);
        $success = false;
        $url = '';
        if (isset($_FILES['logo']) && $_FILES['logo']['error'] === UPLOAD_ERR_OK) {
            $uploads_dir = __DIR__ . '/uploads';
            if (!is_dir($uploads_dir)) {
                @mkdir($uploads_dir, 0777, true);
            }
            $target_file = $uploads_dir . '/logo.png';
            $tmp_name = $_FILES['logo']['tmp_name'];
            if (move_uploaded_file($tmp_name, $target_file)) {
                $success = true;
                $url = 'uploads/logo.png?v=' . time();
            }
        }
        if ($is_ajax) {
            header('Content-Type: application/json');
            echo json_encode(['success' => $success, 'url' => $url, 'message' => $success ? 'Uploaded' : 'Failed']);
            exit();
        } else {
            if ($success) {
                $alert_message = "Logo university milkaa'inaan haaromeera! (Logo updated successfully)";
                $alert_type = "success";
            } else {
                $alert_message = "Logo fe'uun hin danda'amne! (Failed to upload logo)";
                $alert_type = "error";
            }
        }
    }

    // LOGO RESET HANDLER (Admin)
    if ($action === 'reset_logo' && $is_admin_user) {
        $is_ajax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) || (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false);
        $target_file = __DIR__ . '/uploads/logo.png';
        if (file_exists($target_file)) {
            @unlink($target_file);
        }
        if ($is_ajax) {
            header('Content-Type: application/json');
            echo json_encode(['success' => true]);
            exit();
        } else {
            $alert_message = "Logo university haqameera (Reverted to default 🎓)";
            $alert_type = "success";
        }
    }

    // 1. REGISTER ACTION
    if ($action === 'register') {
        $active_auth_tab = "register";
        $fullName   = trim($_POST['fullName'] ?? '');
        $email      = trim($_POST['email'] ?? '');
        $password   = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirmPassword'] ?? '';
        $department = trim($_POST['department'] ?? 'General');
        if (empty($department)) $department = 'General';

        if (empty($fullName) || empty($email) || empty($password)) {
            $alert_message = "Hundaa guutuu qabdu! (Please fill all required fields)";
            $alert_type = "error";
        } elseif (mb_strlen($fullName) < 3) {
            $alert_message = "Maqaan yoo xiqqaate qubee 3 ta'uu qaba!";
            $alert_type = "error";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $email)) {
            $alert_message = "Email Google (@gmail.com) qofatu heyyamama! (Only @gmail.com is allowed)";
            $alert_type = "error";
        } elseif (strlen($password) < 6) {
            $alert_message = "Password-n yoo xiqqaate qubee 6 ta'uu qaba!";
            $alert_type = "error";
        } elseif ($password !== $confirmPassword) {
            $alert_message = "Password-n wal hin simne! (Passwords do not match)";
            $alert_type = "error";
        } else {
            // Check duplicate
            $stmt = $conn->prepare("SELECT id FROM students WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                $alert_message = "Email kun duraan galmaa'ee jira! (Email already registered)";
                $alert_type = "error";
            } else {
                $stmt->close();
                $hashed = password_hash($password, PASSWORD_DEFAULT);
                $role = is_admin($email) ? 'admin' : 'student';

                $ins = $conn->prepare("INSERT INTO students (name, email, password, role, department) VALUES (?, ?, ?, ?, ?)");
                $ins->bind_param("sssss", $fullName, $email, $hashed, $role, $department);
                if ($ins->execute()) {
                    @notify_admin_new_registration($fullName, $email, "Form Galmee ($department)");
                    
                    // Auto login upon registration
                    $_SESSION['student_name'] = $fullName;
                    $_SESSION['student_email'] = $email;
                    $_SESSION['student_role'] = $role;
                    header("Location: index.php?registered=1");
                    exit();
                } else {
                    $alert_message = "Error: " . $ins->error;
                    $alert_type = "error";
                }
                $ins->close();
            }
        }
    }

    // 2. LOGIN ACTION
    elseif ($action === 'login') {
        $active_auth_tab = "login";
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($email) || empty($password)) {
            $alert_message = "Email fi password galchuun barbaachisaadha!";
            $alert_type = "error";
        } else {
            $stmt = $conn->prepare("SELECT id, name, email, password, role FROM students WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($db_id, $db_name, $db_email, $db_hash, $db_role);

            if ($stmt->num_rows > 0) {
                $stmt->fetch();
                if (password_verify($password, $db_hash)) {
                    if (!is_admin($db_email)) {
                        $alert_message = "Dhiifama! Sign In qophaa Administrator qofaaf heyyamama. Barattoonni fuula duraa irratti galmaa'uu qofa danda'u. (Sign in is restricted to Admins only)";
                        $alert_type = "error";
                    } else {
                        $_SESSION['student_id'] = $db_id;
                        $_SESSION['student_name'] = $db_name;
                        $_SESSION['student_email'] = $db_email;
                        $_SESSION['student_role'] = 'admin';
                        header("Location: index.php");
                        exit();
                    }
                } else {
                    $alert_message = "Password dogoggora! (Wrong password)";
                    $alert_type = "error";
                }
            } else {
                $alert_message = "Account-n email kanaan hin argamne! (User not found)";
                $alert_type = "error";
            }
            $stmt->close();
        }
    }

    // 3. FORGOT PASSWORD ACTION
    elseif ($action === 'forgot_password') {
        $active_auth_tab = "forgot";
        $email = trim($_POST['email'] ?? '');
        $new_pwd = $_POST['new_password'] ?? '';
        $cnf_pwd = $_POST['confirm_password'] ?? '';

        if (empty($email) || empty($new_pwd) || empty($cnf_pwd)) {
            $alert_message = "Hundaa guutuu qabdu!";
            $alert_type = "error";
        } elseif (strlen($new_pwd) < 6) {
            $alert_message = "Password-n yoo xiqqaate qubee 6 ta'uu qaba!";
            $alert_type = "error";
        } elseif ($new_pwd !== $cnf_pwd) {
            $alert_message = "Password-n wal hin simne!";
            $alert_type = "error";
        } else {
            $chk = $conn->prepare("SELECT id FROM students WHERE email = ?");
            $chk->bind_param("s", $email);
            $chk->execute();
            $chk->store_result();
            if ($chk->num_rows === 0) {
                $alert_message = "Email kun hin galmoofne!";
                $alert_type = "error";
            } else {
                $chk->close();
                $new_hash = password_hash($new_pwd, PASSWORD_DEFAULT);
                $up = $conn->prepare("UPDATE students SET password = ? WHERE email = ?");
                $up->bind_param("ss", $new_hash, $email);
                if ($up->execute()) {
                    $alert_message = "Password milkaa'inaan jijjiirameera! Amma seenaa. (Password updated, please sign in)";
                    $alert_type = "success";
                    $active_auth_tab = "login";
                } else {
                    $alert_message = "Error: " . $up->error;
                    $alert_type = "error";
                }
                $up->close();
            }
        }
    }

    // 4. ADMIN CRUD: ADD STUDENT
    elseif ($action === 'admin_add' && $is_admin_user) {
        $name       = trim($_POST['name'] ?? '');
        $email      = trim($_POST['email'] ?? '');
        $password   = $_POST['password'] ?? '';
        $role       = trim($_POST['role'] ?? 'student');
        $department = trim($_POST['department'] ?? 'General');
        if (empty($department)) $department = 'General';

        if (empty($name) || empty($email) || empty($password)) {
            $alert_message = "Hundaa guutuu qabdu!";
            $alert_type = "error";
        } else {
            $chk = $conn->prepare("SELECT id FROM students WHERE email = ?");
            $chk->bind_param("s", $email);
            $chk->execute();
            $chk->store_result();
            if ($chk->num_rows > 0) {
                $alert_message = "Email kun duraan galmaa'ee jira!";
                $alert_type = "error";
            } else {
                $chk->close();
                $h = password_hash($password, PASSWORD_DEFAULT);
                $ins = $conn->prepare("INSERT INTO students (name, email, password, role, department) VALUES (?, ?, ?, ?, ?)");
                $ins->bind_param("sssss", $name, $email, $h, $role, $department);
                if ($ins->execute()) {
                    $alert_message = "Barataan haaraa ('" . htmlspecialchars($name) . "') itti dabalameera!";
                    $alert_type = "success";
                    @notify_admin_new_registration($name, $email, "Admin Panel Add ($department)");
                }
                $ins->close();
            }
        }
    }

    // 5. ADMIN CRUD: EDIT STUDENT
    elseif ($action === 'admin_edit' && $is_admin_user) {
        $student_id = (int)($_POST['student_id'] ?? 0);
        $name       = trim($_POST['name'] ?? '');
        $email      = trim($_POST['email'] ?? '');
        $new_pwd    = $_POST['new_password'] ?? '';
        $role       = trim($_POST['role'] ?? 'student');
        $department = trim($_POST['department'] ?? 'General');
        if (empty($department)) $department = 'General';

        if ($student_id > 0 && !empty($name) && !empty($email)) {
            if (!empty($new_pwd)) {
                $h = password_hash($new_pwd, PASSWORD_DEFAULT);
                $up = $conn->prepare("UPDATE students SET name = ?, email = ?, password = ?, role = ?, department = ? WHERE id = ?");
                $up->bind_param("sssssi", $name, $email, $h, $role, $department, $student_id);
            } else {
                $up = $conn->prepare("UPDATE students SET name = ?, email = ?, role = ?, department = ? WHERE id = ?");
                $up->bind_param("ssssi", $name, $email, $role, $department, $student_id);
            }
            if ($up->execute()) {
                $alert_message = "Ragaan barataa milkaa'inaan haaromeera! (Updated successfully)";
                $alert_type = "success";
            }
            $up->close();
        }
    }

    // 6. ADMIN CRUD: DELETE STUDENT
    elseif ($action === 'admin_delete' && $is_admin_user) {
        $student_id = (int)($_POST['student_id'] ?? 0);
        if ($student_id > 0) {
            $del = $conn->prepare("DELETE FROM students WHERE id = ? AND email != ?");
            $del->bind_param("is", $student_id, $current_email);
            if ($del->execute()) {
                $alert_message = "Barataan milkaa'inaan haqameera! (Student deleted)";
                $alert_type = "success";
            }
            $del->close();
        }
    }
}

// Fetch all students for Admin view (Filter out admin4566 and admin123 accounts)
$all_students = [];
$total_students = 0;
if ($is_admin_user) {
    // Clean up test admin123 records and notifications if present
    @$conn->query("DELETE FROM students WHERE email LIKE '%admin123%' OR name LIKE '%admin123%'");
    @$conn->query("DELETE FROM notifications WHERE student_email LIKE '%admin4566%' OR student_email LIKE '%admin123%' OR message LIKE '%admin4566%' OR message LIKE '%admin123%'");

    $res = $conn->query("SELECT id, name, email, role, department, created_at FROM students ORDER BY id DESC");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $em_lower = strtolower(trim($row['email'] ?? ''));
            $nm_lower = strtolower(trim($row['name'] ?? ''));
            // Exclude admin4566 and admin123 from student directory
            if (strpos($em_lower, 'admin4566') !== false ||
                strpos($em_lower, 'admin123') !== false ||
                strpos($nm_lower, 'admin4566') !== false ||
                strpos($nm_lower, 'admin123') !== false) {
                continue;
            }
            $all_students[] = $row;
        }
        $total_students = count($all_students);
    }
}

// Fetch notifications (Excluding admin4566 and admin123)
$notifications = [];
if ($is_admin_user) {
    $n_res = $conn->query("SELECT title, message, student_email, created_at FROM notifications ORDER BY id DESC LIMIT 25");
    if ($n_res) {
        while ($nr = $n_res->fetch_assoc()) {
            $em = strtolower($nr['student_email'] ?? '');
            $msg = strtolower($nr['message'] ?? '');
            $tit = strtolower($nr['title'] ?? '');
            if (strpos($em, 'admin4566') !== false ||
                strpos($em, 'admin123') !== false ||
                strpos($msg, 'admin4566') !== false ||
                strpos($msg, 'admin123') !== false ||
                strpos($tit, 'admin4566') !== false ||
                strpos($tit, 'admin123') !== false) {
                continue;
            }
            $notifications[] = $nr;
            if (count($notifications) >= 6) break;
        }
    }
}

// Display-safe admin email (avoids exposing admin4566/admin123)
$display_admin_email = (strpos(strtolower($current_email), 'admin4566') !== false || strpos(strtolower($current_email), 'admin123') !== false)
    ? 'superadmin@alnasrii.edu'
    : $current_email;
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Alnasrii University - Single Portal</title>

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
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(-8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .animate-fade-in {
      animation: fadeIn 0.25s ease-out forwards;
    }
  </style>
</head>
<body id="pageBody" class="min-h-screen bg-slate-900 text-slate-100 selection:bg-green-500 selection:text-white" style="background-size:360px auto; background-repeat:no-repeat; background-position:center 120px; background-attachment:fixed;">

  <!-- Ambient Decorative Background -->
  <div id="ambientBg" class="fixed inset-0 overflow-hidden pointer-events-none">
    <div class="absolute -top-40 -left-40 w-96 h-96 bg-green-600/20 rounded-full blur-3xl"></div>
    <div class="absolute -bottom-40 -right-40 w-96 h-96 bg-emerald-500/20 rounded-full blur-3xl"></div>
  </div>

  <!-- Header Navigation (Public & Student Views) -->
  <?php if(!$is_admin_user): ?>
  <header class="border-b border-white/10 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40">
    <div class="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="site-logo-icon w-10 h-10 rounded-xl bg-gradient-to-br from-green-500 to-emerald-700 flex items-center justify-center text-xl shadow-lg overflow-hidden shrink-0 border border-white/20">
          <?php $site_logo = get_site_logo(); if($site_logo): ?>
            <img src="<?php echo $site_logo; ?>" alt="Logo" class="w-full h-full object-cover site-logo-img" />
          <?php else: ?>
            <span class="site-logo-fallback">🎓</span>
          <?php endif; ?>
        </div>
        <div>
          <span class="font-extrabold text-lg text-white tracking-tight">Alnasrii University</span>
          <?php if($is_logged_in): ?>
            <span class="text-xs bg-green-500/20 text-green-300 border border-green-500/30 px-2 py-0.5 rounded-full ml-2 font-medium">Student</span>
          <?php endif; ?>
        </div>
      </div>

      <div>
        <?php if($is_logged_in): ?>
          <a href="index.php?logout=1" class="text-xs text-red-300 hover:text-white bg-red-500/10 hover:bg-red-500/20 px-3.5 py-1.5 rounded-lg border border-red-500/30 transition font-semibold">
            Logout
          </a>
        <?php else: ?>
          <div class="flex items-center gap-3">
            <span class="text-xs text-slate-400 hidden sm:inline">Official Student Portal</span>
            <a href="login.php" class="text-xs bg-white text-green-900 hover:bg-green-100 font-bold px-3.5 py-1.5 rounded-lg shadow transition flex items-center gap-1.5">
              <span>Sign In</span>
              <span>&rarr;</span>
            </a>
          </div>
        <?php endif; ?>
      </div>
    </div>
  </header>
  <?php endif; ?>

  <main class="<?php echo $is_admin_user ? 'relative z-10 w-full min-h-screen' : 'max-w-6xl mx-auto px-4 sm:px-6 py-8 relative z-10'; ?>">

    <!-- Global Alert Message for Public / Student Views -->
    <?php if(!$is_admin_user && !empty($alert_message)): ?>
      <div class="mb-6 p-4 rounded-xl text-xs font-medium flex items-center justify-between gap-3 animate-fade-in max-w-xl mx-auto <?php echo $alert_type === 'success' ? 'bg-emerald-500/20 border border-emerald-500/40 text-emerald-200' : 'bg-red-500/20 border border-red-500/40 text-red-200'; ?>">
        <div class="flex items-center gap-2">
          <span><?php echo $alert_type === 'success' ? '✅' : '⚠️'; ?></span>
          <span><?php echo htmlspecialchars($alert_message); ?></span>
        </div>
        <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-white text-base">&times;</button>
      </div>
    <?php endif; ?>

    <?php if(isset($_GET['registered'])): ?>
      <div class="mb-6 p-4 rounded-xl text-xs font-medium bg-emerald-500/20 border border-emerald-500/40 text-emerald-200 text-center max-w-xl mx-auto animate-fade-in">
        🎉 Galmeen keessan milkaa'inaan raawwatameera! (Registration successful!)
      </div>
    <?php endif; ?>

    <!-- ============================================================== -->
    <!-- VIEW 1: UNAUTHENTICATED (ALL-IN-ONE CARD: REGISTER / LOGIN)   -->
    <!-- ============================================================== -->
    <?php if(!$is_logged_in): ?>
      <div class="max-w-md mx-auto my-4">

        <!-- Card with dynamic background photo -->
        <div id="cardBg" class="card-bg relative w-full rounded-2xl shadow-2xl overflow-hidden border border-white/10 transition-all duration-300">
          <div class="absolute inset-0 bg-gradient-to-b from-green-800/90 via-green-900/95 to-slate-950/95"></div>

          <div class="relative z-10 p-6 sm:p-8">

            <!-- Card Header -->
            <div class="text-center mb-6">
              <div class="site-logo-badge inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-white/10 border border-white/20 mb-3 shadow-inner backdrop-blur-md overflow-hidden">
                <?php if($site_logo): ?>
                  <img src="<?php echo $site_logo; ?>" alt="Logo" class="w-full h-full object-cover site-logo-img" />
                <?php else: ?>
                  <span class="text-2xl site-logo-fallback">🎓</span>
                <?php endif; ?>
              </div>
              <h1 class="text-3xl font-extrabold text-white tracking-tight mb-1">Alnasrii University</h1>
              <p class="text-green-200 text-xs font-medium">Create Your Student Account</p>
            </div>

            <!-- ================= CREATE ACCOUNT FORM ================= -->
            <form id="authRegisterForm" method="POST" action="index.php" class="space-y-4" novalidate>
              <input type="hidden" name="action" value="register">

              <!-- Full Name -->
              <div>
                <label class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Full Name</label>
                <input id="regFullName" name="fullName" type="text" placeholder="e.g. Guuta Ahmed" required class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 shadow-sm" />
              </div>

              <!-- Email -->
              <div>
                <div class="flex items-center justify-between mb-1.5">
                  <label class="text-white text-xs font-semibold uppercase tracking-wider">Email Address</label>
                  <span class="text-[11px] text-green-200/90 font-mono">(@gmail.com)</span>
                </div>
                <input id="regEmail" name="email" type="email" placeholder="student@gmail.com" required pattern=".+@gmail\.com$" class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 shadow-sm" />
              </div>

              <!-- Department -->
              <div>
                <label class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Department (Kutaa Barnootaa)</label>
                <input id="regDepartment" name="department" type="text" placeholder="Department keessan barreessaa..." required class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 shadow-sm" />
              </div>

              <!-- Password -->
              <div>
                <label class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Password</label>
                <div class="relative">
                  <input id="regPassword" name="password" type="password" placeholder="At least 6 characters" required minlength="6" class="w-full px-4 py-2.5 pr-14 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 shadow-sm" />
                  <button type="button" data-toggle="regPassword" class="absolute right-2.5 top-1/2 -translate-y-1/2 px-2 py-1 text-gray-500 hover:text-gray-800 text-xs font-semibold">Show</button>
                </div>
              </div>

              <!-- Confirm Password -->
              <div>
                <label class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Confirm Password</label>
                <div class="relative">
                  <input id="regConfirmPassword" name="confirmPassword" type="password" placeholder="Repeat your password" required minlength="6" class="w-full px-4 py-2.5 pr-14 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 shadow-sm" />
                  <button type="button" data-toggle="regConfirmPassword" class="absolute right-2.5 top-1/2 -translate-y-1/2 px-2 py-1 text-gray-500 hover:text-gray-800 text-xs font-semibold">Show</button>
                </div>
              </div>

              <button type="submit" class="w-full mt-2 bg-white text-green-800 font-bold py-3 rounded-lg shadow-lg hover:bg-green-50 active:scale-[0.99] transition text-sm flex items-center justify-center gap-2">
                <span>Create Account</span>
                <span>&rarr;</span>
              </button>
            </form>

            <!-- Link to Separate Sign In Page -->
            <div class="mt-4 pt-3 text-center">
              <p class="text-white/90 text-xs">
                Duraan account qabduu? (Already have an account?)
                <a href="login.php" class="text-white font-bold underline underline-offset-2 hover:text-green-200 transition ml-1">
                  Sign In &rarr;
                </a>
              </p>
            </div>

            <!-- Social Auth Divider -->
            <div class="mt-6 pt-5 border-t border-white/20 space-y-4">
              <div class="flex items-center gap-3">
                <div class="flex-1 h-px bg-white/20"></div>
                <span class="text-white/70 text-[11px] uppercase tracking-wider font-semibold">or continue with</span>
                <div class="flex-1 h-px bg-white/20"></div>
              </div>

              <!-- Google + GitHub -->
              <div class="grid grid-cols-2 gap-3">
                <button type="button" id="googleCustomBtn" class="flex items-center justify-center gap-2 bg-white text-gray-700 font-semibold py-2.5 px-3 rounded-lg shadow hover:bg-gray-100 transition text-xs">
                  <svg class="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                  </svg>
                  <span>Google</span>
                </button>

                <button type="button" onclick="alert('Alnasrii University GitHub OAuth tajaajilli yeroo dhiyootti ni eegala.')" class="flex items-center justify-center gap-2 bg-slate-900/90 hover:bg-slate-900 text-white font-semibold py-2.5 px-3 rounded-lg shadow border border-white/10 transition text-xs">
                  <svg class="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 .5C5.37.5 0 5.87 0 12.5c0 5.3 3.44 9.8 8.21 11.39.6.11.82-.26.82-.58 0-.29-.01-1.05-.02-2.06-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.73.08-.73 1.21.09 1.84 1.24 1.84 1.24 1.07 1.83 2.81 1.3 3.5.99.11-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.12-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.28-1.55 3.29-1.23 3.29-1.23.66 1.66.25 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.81 5.62-5.49 5.92.43.37.81 1.1.81 2.22 0 1.61-.01 2.9-.01 3.29 0 .32.21.7.83.58A12.01 12.01 0 0 0 24 12.5C24 5.87 18.63.5 12 .5z"/>
                  </svg>
                  <span>GitHub</span>
                </button>
              </div>

              <div id="g_id_onload"
                   data-client_id="<?php echo htmlspecialchars($google_client_id); ?>"
                   data-context="signin"
                   data-ux_mode="popup"
                   data-callback="handleGoogleResponse"
                   data-auto_prompt="false"
                   style="display:none;">
              </div>
            </div>

          </div>
        </div>
      </div>

    <!-- ============================================================== -->
    <!-- VIEW 2: AUTHENTICATED AS REGULAR STUDENT                       -->
    <!-- ============================================================== -->
    <?php elseif(!$is_admin_user): ?>
      <div class="bg-slate-800/60 border border-white/10 rounded-2xl p-8 text-center max-w-xl mx-auto shadow-2xl animate-fade-in my-8">
        <div class="site-logo-badge w-20 h-20 mx-auto rounded-3xl bg-emerald-500/20 border border-emerald-400/30 flex items-center justify-center text-4xl mb-4 overflow-hidden">
          <?php if($site_logo): ?>
            <img src="<?php echo $site_logo; ?>" alt="Logo" class="w-full h-full object-cover site-logo-img" />
          <?php else: ?>
            <span class="site-logo-fallback">🎓</span>
          <?php endif; ?>
        </div>
        <h2 class="text-2xl font-bold text-white mb-2">Registration Successful!</h2>
        <p class="text-emerald-300 font-medium text-sm mb-4">
          Baga Nagaan Dhufte, <?php echo htmlspecialchars($current_name); ?>!
        </p>

        <div class="p-4 rounded-xl bg-white/5 border border-white/10 text-left text-xs space-y-2 mb-6">
          <div class="flex justify-between py-1 border-b border-white/10">
            <span class="text-slate-400">Student Name:</span>
            <span class="font-bold text-white"><?php echo htmlspecialchars($current_name); ?></span>
          </div>
          <div class="flex justify-between py-1 border-b border-white/10">
            <span class="text-slate-400">Registered Email:</span>
            <span class="font-bold text-white"><?php echo htmlspecialchars($current_email); ?></span>
          </div>
          <div class="flex justify-between py-1">
            <span class="text-slate-400">Status:</span>
            <span class="text-emerald-400 font-bold">Mirkanaa'eera (Active Student)</span>
          </div>
        </div>

        <div class="p-4 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-200 text-xs text-left mb-6 leading-relaxed">
          ℹ️ <strong>Hubachiisa:</strong> Galmeen keessan milkaa'inaan Alnasrii University irratti raawwatameera. Fuulli bulchiinsaa (CRUD Dashboard) qondaaltota Admin qofaaf heyyamama.
        </div>

        <div class="flex justify-center gap-3">
          <a href="index.php?logout=1" class="bg-white text-slate-900 font-bold px-6 py-2.5 rounded-lg text-xs hover:bg-slate-200 transition">
            Sign Out (Logout)
          </a>
        </div>
      </div>

    <!-- ============================================================== -->
    <!-- VIEW 3: AUTHENTICATED AS ADMIN (COMPLETE CRUD SYSTEM)          -->
    <!-- ============================================================== -->
    <?php else: ?>

      <!-- ============================================================== -->
      <!-- VIEW 3: AUTHENTICATED AS ADMIN (SIDEBAR + RED ACCENT DASHBOARD)-->
      <!-- ============================================================== -->
      <div class="flex min-h-screen">
        
        <!-- Mobile Sidebar Backdrop Overlay -->
        <div id="sidebarBackdrop" onclick="toggleSidebar(false)" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 hidden md:hidden transition-opacity"></div>

        <!-- ══════════════════════════════════════════════════════════════ -->
        <!-- LEFT SIDEBAR                                                   -->
        <!-- ══════════════════════════════════════════════════════════════ -->
        <aside id="sidebar" class="fixed top-0 bottom-0 left-0 z-50 w-64 bg-[#14161f] border-r border-white/10 flex flex-col justify-between -translate-x-full md:translate-x-0 transition-transform duration-300 ease-in-out shadow-2xl">
          
          <!-- Top Brand & Navigation -->
          <div class="flex-1 overflow-y-auto">
            <!-- Brand Header -->
            <div class="p-5 flex items-center justify-between border-b border-white/10">
              <div class="flex items-center gap-3 cursor-pointer group" onclick="adminNav('dashboard')" title="Go to Dashboard Overview">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-red-600 to-rose-700 flex items-center justify-center text-xl shadow-lg shadow-red-950/50 overflow-hidden shrink-0 border border-white/20 group-hover:scale-105 transition">
                  <?php $site_logo = get_site_logo(); if($site_logo): ?>
                    <img src="<?php echo $site_logo; ?>" alt="Logo" class="w-full h-full object-cover site-logo-img" />
                  <?php else: ?>
                    <span class="site-logo-fallback">🎓</span>
                  <?php endif; ?>
                </div>
                <div>
                  <h1 class="font-extrabold text-white text-base tracking-tight leading-tight group-hover:text-red-400 transition">Alnasrii</h1>
                  <span class="text-[10px] uppercase font-bold tracking-widest text-red-400">Admin Control</span>
                </div>
              </div>
              <button onclick="toggleSidebar(false)" class="md:hidden text-slate-400 hover:text-white text-xl p-1 leading-none">&times;</button>
            </div>

            <!-- Navigation Links -->
            <nav id="adminSidebarNav" class="p-4 space-y-1.5 text-xs font-semibold">
              <!-- 1. Dashboard -->
              <button type="button" id="navItem_dashboard" onclick="adminNav('dashboard')" class="admin-nav-item w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl bg-red-600 text-white font-bold shadow-lg shadow-red-950/50 transition text-left cursor-pointer active:scale-95">
                <span class="text-base">📊</span>
                <span>Dashboard</span>
              </button>

              <!-- 2. Student Directory -->
              <button type="button" id="navItem_students" onclick="adminNav('students')" class="admin-nav-item w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition text-left cursor-pointer active:scale-95">
                <span class="text-base">👥</span>
                <span>Student Directory</span>
              </button>

              <!-- 3. Add Student -->
              <button type="button" id="navItem_add" onclick="adminNav('add_student')" class="admin-nav-item w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition text-left cursor-pointer active:scale-95">
                <span class="text-base">➕</span>
                <span>Add Student</span>
              </button>

              <!-- 4. Notifications -->
              <button type="button" id="navItem_notifications" onclick="adminNav('notifications')" class="admin-nav-item w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition text-left cursor-pointer active:scale-95">
                <div class="flex items-center gap-3">
                  <span class="text-base">🔔</span>
                  <span>Notifications</span>
                </div>
                <?php if(!empty($notifications)): ?>
                  <span class="bg-red-500/20 text-red-300 border border-red-500/40 text-[10px] font-bold px-2 py-0.5 rounded-full">
                    <?php echo count($notifications); ?>
                  </span>
                <?php endif; ?>
              </button>

              <!-- 5. University Logo -->
              <button type="button" id="navItem_logo" onclick="adminNav('logo')" class="admin-nav-item w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition text-left cursor-pointer active:scale-95">
                <span class="text-base">🏷️</span>
                <span>University Logo</span>
              </button>

              <!-- 6. Background & Size -->
              <button type="button" id="navItem_bg" onclick="adminNav('background')" class="admin-nav-item w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition text-left cursor-pointer active:scale-95">
                <span class="text-base">🖼️</span>
                <span>Background & Size</span>
              </button>

              <!-- 7. Admin Profile -->
              <button type="button" id="navItem_profile" onclick="adminNav('profile')" class="admin-nav-item w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition text-left cursor-pointer active:scale-95">
                <span class="text-base">👤</span>
                <span>Admin Profile</span>
              </button>
            </nav>
          </div>

          <!-- Bottom Pinned Section -->
          <div class="p-4 border-t border-white/10 space-y-1.5 text-xs font-semibold shrink-0 bg-[#14161f]">
            <a href="login.php" target="_blank" class="flex items-center justify-between px-3.5 py-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/5 transition" title="Open student portal in new tab">
              <div class="flex items-center gap-3">
                <span class="text-base">🏠</span>
                <span>Portal View</span>
              </div>
              <span class="text-[10px] text-slate-500 bg-white/5 px-1.5 py-0.5 rounded">New ↗</span>
            </a>
            <button type="button" onclick="adminNav('logout')" class="w-full flex items-center gap-3 px-3.5 py-2 rounded-xl text-red-400 hover:text-red-200 hover:bg-red-500/10 transition font-bold text-left cursor-pointer">
              <span class="text-base">🚪</span>
              <span>Logout</span>
            </button>
          </div>
        </aside>

        <!-- ══════════════════════════════════════════════════════════════ -->
        <!-- MAIN CONTENT AREA (Offset by Sidebar on md+)                    -->
        <!-- ══════════════════════════════════════════════════════════════ -->
        <div class="flex-1 md:ml-64 min-w-0 flex flex-col">
          
          <!-- Top Dashboard Header Bar -->
          <div class="h-16 px-4 sm:px-8 border-b border-white/10 bg-[#0e1017]/80 backdrop-blur-md sticky top-0 z-30 flex items-center justify-between">
            <div class="flex items-center gap-3">
              <!-- Mobile Hamburger Button -->
              <button onclick="toggleSidebar(true)" class="md:hidden text-white p-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 cursor-pointer">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>
              </button>
              <button type="button" onclick="adminNav('dashboard')" class="text-lg font-bold text-white tracking-tight flex items-center gap-2 hover:text-red-400 transition cursor-pointer">
                <span>Dashboard</span>
              </button>
            </div>

            <div class="flex items-center gap-3 sm:gap-4">
              <!-- Notification Bell with count -->
              <button type="button" onclick="adminNav('notifications')" class="relative p-2 rounded-xl text-slate-300 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition cursor-pointer" title="Notifications">
                <span class="text-base">🔔</span>
                <?php if(!empty($notifications)): ?>
                  <span class="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red-500 ring-2 ring-[#0e1017]"></span>
                <?php endif; ?>
              </button>

              <!-- Admin Profile Pill Button (Clickable to open Admin Profile modal) -->
              <div onclick="adminNav('profile')" class="flex items-center gap-2.5 bg-white/5 hover:bg-white/10 border border-white/10 px-3 py-1.5 rounded-xl cursor-pointer transition group" title="Click to edit admin photo and name">
                <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-red-500 to-rose-700 flex items-center justify-center text-white font-bold text-xs overflow-hidden shrink-0 shadow">
                  <?php if(!empty($current_pic)): ?>
                    <img src="<?php echo htmlspecialchars($current_pic); ?>" alt="Admin" class="w-full h-full object-cover" />
                  <?php else: ?>
                    <span><?php echo mb_substr($current_name, 0, 1); ?></span>
                  <?php endif; ?>
                </div>
                <div class="hidden sm:block text-left">
                  <p class="text-xs font-bold text-white group-hover:text-red-300 transition leading-tight"><?php echo htmlspecialchars($current_name); ?></p>
                  <p class="text-[10px] text-slate-400 uppercase tracking-wider">Super Admin</p>
                </div>
              </div>
            </div>
          </div>

          <!-- Main Dashboard Canvas Body -->
          <div class="p-4 sm:p-8 space-y-8 max-w-7xl w-full mx-auto">
            
            <!-- Global Alert (if any) -->
            <?php if(!empty($alert_message)): ?>
              <div class="p-4 rounded-xl text-xs font-medium flex items-center justify-between gap-3 animate-fade-in <?php echo $alert_type === 'success' ? 'bg-emerald-500/20 border border-emerald-500/40 text-emerald-200' : 'bg-red-500/20 border border-red-500/40 text-red-200'; ?>">
                <div class="flex items-center gap-2">
                  <span><?php echo $alert_type === 'success' ? '✅' : '⚠️'; ?></span>
                  <span><?php echo htmlspecialchars($alert_message); ?></span>
                </div>
                <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-white text-base">&times;</button>
              </div>
            <?php endif; ?>

            <!-- ══════════════════════════════════════════════════════════ -->
            <!-- HERO RED WELCOME CARD (Exact style from reference image)    -->
            <!-- ══════════════════════════════════════════════════════════ -->
            <div id="dashboardTop" class="relative overflow-hidden rounded-3xl bg-gradient-to-r from-red-600 via-rose-600 to-red-700 p-6 sm:p-9 shadow-2xl border border-red-500/40 text-white scroll-mt-20">
              <!-- Subtle decorative circle overlay -->
              <div class="absolute -right-10 -bottom-10 w-64 h-64 bg-white/10 rounded-full blur-2xl pointer-events-none"></div>

              <div class="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div>
                  <div class="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-widest text-red-100 bg-black/25 px-3 py-1 rounded-full mb-3">
                    <span>🌙</span>
                    <span><?php echo $time_greeting; ?></span>
                  </div>
                  <h1 class="text-2xl sm:text-4xl font-extrabold tracking-tight text-white mb-2">
                    <?php echo htmlspecialchars($current_name); ?>
                  </h1>
                  <p class="text-xs sm:text-sm text-red-100/90 max-w-xl font-normal leading-relaxed">
                    Manage your Alnasrii University students, registrations, and portal records from one place.
                  </p>

                  <!-- Pill Action Buttons on Hero -->
                  <div class="flex flex-wrap items-center gap-2.5 mt-5">
                    <button onclick="adminNav('add_student')" class="bg-white text-red-700 hover:bg-red-50 font-extrabold px-4 py-2 rounded-xl text-xs flex items-center gap-1.5 shadow-lg transition active:scale-95 cursor-pointer">
                      <span>➕</span>
                      <span>Add Student</span>
                    </button>
                    <button onclick="adminNav('students')" class="bg-white/20 hover:bg-white/30 text-white border border-white/30 font-semibold px-4 py-2 rounded-xl text-xs flex items-center gap-1.5 backdrop-blur-sm transition cursor-pointer">
                      <span>👥</span>
                      <span>View Directory</span>
                    </button>
                    <button onclick="adminNav('profile')" class="bg-white/20 hover:bg-white/30 text-white border border-white/30 font-semibold px-4 py-2 rounded-xl text-xs flex items-center gap-1.5 backdrop-blur-sm transition cursor-pointer">
                      <span>👤</span>
                      <span>Edit Profile</span>
                    </button>
                  </div>
                </div>

                <!-- Admin Avatar Badge on Right -->
                <div class="hidden lg:flex items-center gap-4 bg-black/20 p-4 rounded-2xl border border-white/15 backdrop-blur-md">
                  <div class="w-16 h-16 rounded-2xl bg-white/20 border-2 border-white/40 shadow-xl flex items-center justify-center text-2xl font-bold text-white uppercase overflow-hidden shrink-0">
                    <?php if(!empty($current_pic)): ?>
                      <img src="<?php echo htmlspecialchars($current_pic); ?>" alt="Admin" class="w-full h-full object-cover" />
                    <?php else: ?>
                      <span><?php echo mb_substr($current_name, 0, 1); ?></span>
                    <?php endif; ?>
                  </div>
                  <div>
                    <span class="text-[10px] text-red-200 uppercase font-bold tracking-wider">Super Administrator</span>
                    <p class="text-xs font-semibold text-white"><?php echo htmlspecialchars($display_admin_email); ?></p>
                    <span class="inline-block mt-1 text-[10px] bg-red-500/40 text-white px-2 py-0.5 rounded-full font-mono">Full Access</span>
                  </div>
                </div>
              </div>
            </div>

            <!-- ══════════════════════════════════════════════════════════ -->
            <!-- STATS CARDS ROW (Exact match to reference style)           -->
            <!-- ══════════════════════════════════════════════════════════ -->
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-5">
              <!-- Stat 1: Total Students -->
              <div class="bg-slate-900/80 border border-white/10 rounded-2xl p-5 shadow-lg flex items-center justify-between">
                <div>
                  <p class="text-[11px] uppercase text-slate-400 font-bold tracking-wider">Total Students</p>
                  <p class="text-3xl font-extrabold text-white mt-1.5"><?php echo $total_students; ?></p>
                  <p class="text-[11px] text-red-400 font-medium mt-1">Enrolled & Active</p>
                </div>
                <div class="w-12 h-12 rounded-2xl bg-red-500/15 border border-red-500/30 text-red-400 flex items-center justify-center text-2xl shrink-0">
                  👥
                </div>
              </div>

              <!-- Stat 2: System Access -->
              <div class="bg-slate-900/80 border border-white/10 rounded-2xl p-5 shadow-lg flex items-center justify-between">
                <div>
                  <p class="text-[11px] uppercase text-slate-400 font-bold tracking-wider">System Access</p>
                  <p class="text-xl font-extrabold text-amber-400 mt-1.5">Full CRUD Power</p>
                  <p class="text-[11px] text-amber-400/80 font-medium mt-1">Add, Update, Delete</p>
                </div>
                <div class="w-12 h-12 rounded-2xl bg-amber-500/15 border border-amber-500/30 text-amber-400 flex items-center justify-center text-2xl shrink-0">
                  ⚡
                </div>
              </div>

              <!-- Stat 3: Notifications -->
              <div class="bg-slate-900/80 border border-white/10 rounded-2xl p-5 shadow-lg flex items-center justify-between">
                <div>
                  <p class="text-[11px] uppercase text-slate-400 font-bold tracking-wider">Notifications</p>
                  <p class="text-3xl font-extrabold text-emerald-400 mt-1.5"><?php echo count($notifications); ?></p>
                  <p class="text-[11px] text-emerald-400/80 font-medium mt-1">Recent Activity Logs</p>
                </div>
                <div class="w-12 h-12 rounded-2xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 flex items-center justify-center text-2xl shrink-0">
                  🔔
                </div>
              </div>
            </div>

            <!-- ══════════════════════════════════════════════════════════ -->
            <!-- STUDENT DIRECTORY TABLE (CRUD: READ, UPDATE, DELETE)       -->
            <!-- ══════════════════════════════════════════════════════════ -->
            <div id="studentsSection" class="bg-slate-900/80 border border-white/10 rounded-2xl p-6 shadow-xl scroll-mt-20">
              <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 mb-6">
                <div>
                  <div class="flex items-center gap-2">
                    <span class="w-2.5 h-2.5 rounded-full bg-red-500"></span>
                    <h2 class="text-lg font-bold text-white tracking-tight">Recent Students (Directory)</h2>
                  </div>
                  <p class="text-xs text-slate-400 mt-1">Barattoota haaraa dabalii, kan jiran gulaali (update), ykn haqi (delete).</p>
                </div>

                <div class="flex items-center gap-3">
                  <!-- Search Filter -->
                  <div class="relative w-full sm:w-64">
                    <input type="text" id="studentSearch" placeholder="Search name or email..." class="w-full px-3.5 py-2 pl-9 rounded-xl bg-slate-950/80 border border-white/10 text-white placeholder-slate-400 text-xs outline-none focus:ring-2 focus:ring-red-500" />
                    <span class="absolute left-3 top-2.5 text-slate-400 text-xs">🔍</span>
                  </div>

                  <button onclick="openAddModal()" class="bg-red-600 hover:bg-red-500 text-white font-bold px-3.5 py-2 rounded-xl text-xs flex items-center gap-1.5 shadow transition shrink-0">
                    <span>➕</span>
                    <span class="hidden sm:inline">Add Student</span>
                  </button>
                </div>
              </div>

              <div class="overflow-x-auto rounded-xl border border-white/10">
                <table class="w-full text-left text-xs">
                  <thead class="bg-slate-950/80 text-slate-400 uppercase text-[11px] tracking-wider border-b border-white/10">
                    <tr>
                      <th class="py-3 px-4">ID</th>
                      <th class="py-3 px-4">Student Name</th>
                      <th class="py-3 px-4">Department</th>
                      <th class="py-3 px-4">Email</th>
                      <th class="py-3 px-4">Role</th>
                      <th class="py-3 px-4">Joined Date</th>
                      <th class="py-3 px-4 text-center">Actions</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-white/5">
                    <?php if(empty($all_students)): ?>
                      <tr>
                        <td colspan="7" class="py-8 text-center text-slate-400">Barataan galmaa'e hin jiru.</td>
                      </tr>
                    <?php else: ?>
                      <?php foreach($all_students as $st): ?>
                        <tr class="student-row hover:bg-white/5 transition" data-name="<?php echo htmlspecialchars(strtolower($st['name'])); ?>" data-email="<?php echo htmlspecialchars(strtolower($st['email'])); ?>" data-department="<?php echo htmlspecialchars(strtolower($st['department'] ?? '')); ?>">
                          <td class="py-3 px-4 font-mono text-slate-400">#<?php echo $st['id']; ?></td>
                          <td class="py-3 px-4 font-semibold text-white flex items-center gap-2.5">
                            <div class="w-7 h-7 rounded-full bg-red-500/20 text-red-300 font-bold flex items-center justify-center text-xs">
                              <?php echo mb_substr($st['name'], 0, 1); ?>
                            </div>
                            <span><?php echo htmlspecialchars($st['name']); ?></span>
                          </td>
                          <td class="py-3 px-4">
                            <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg bg-white/5 border border-white/10 text-slate-200 font-medium text-[11px]">
                              <span>🎓</span>
                              <span><?php echo htmlspecialchars($st['department'] ?? 'General'); ?></span>
                            </span>
                          </td>
                          <td class="py-3 px-4 text-slate-300"><?php echo htmlspecialchars($st['email']); ?></td>
                          <td class="py-3 px-4">
                            <?php if($st['role'] === 'admin'): ?>
                              <span class="bg-red-500/20 text-red-300 border border-red-500/30 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase">Admin</span>
                            <?php else: ?>
                              <span class="bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded-full text-[10px] font-medium">Student</span>
                            <?php endif; ?>
                          </td>
                          <td class="py-3 px-4 text-slate-400"><?php echo date("M d, Y", strtotime($st['created_at'])); ?></td>
                          <td class="py-3 px-4 text-center">
                            <div class="inline-flex items-center gap-2">
                              <button onclick='openEditModal(<?php echo json_encode($st); ?>)' class="bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 border border-blue-500/30 px-2.5 py-1 rounded-lg text-xs font-medium transition">
                                ✏️ Edit
                              </button>
                              <button onclick="confirmDelete(<?php echo $st['id']; ?>, '<?php echo htmlspecialchars(addslashes($st['name'])); ?>')" class="bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/30 px-2.5 py-1 rounded-lg text-xs font-medium transition">
                                🗑️ Delete
                              </button>
                            </div>
                          </td>
                        </tr>
                      <?php endforeach; ?>
                    <?php endif; ?>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- ══════════════════════════════════════════════════════════ -->
            <!-- RECENT NOTIFICATIONS & SYSTEM LOGS                         -->
            <!-- ══════════════════════════════════════════════════════════ -->
            <div id="notificationsSection" class="bg-slate-900/80 border border-white/10 rounded-2xl p-6 shadow-xl scroll-mt-20">
              <div class="flex items-center justify-between mb-4">
                <div class="flex items-center gap-2">
                  <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                  <h2 class="text-base font-bold text-white tracking-tight">Recent Registration Activity</h2>
                </div>
                <span class="text-xs text-slate-400"><?php echo count($notifications); ?> total logs</span>
              </div>
              <div class="space-y-2.5">
                <?php if(empty($notifications)): ?>
                  <p class="text-xs text-slate-400 py-3">Gabaasni haaraan hin jiru.</p>
                <?php else: ?>
                  <?php foreach($notifications as $n): ?>
                    <div class="p-3.5 rounded-xl bg-white/5 border border-white/5 flex items-start justify-between gap-4 text-xs hover:bg-white/10 transition">
                      <div class="flex items-start gap-3">
                        <span class="text-emerald-400 text-sm mt-0.5">✓</span>
                        <div>
                          <p class="font-semibold text-white"><?php echo htmlspecialchars($n['title']); ?></p>
                          <p class="text-slate-300 mt-0.5"><?php echo htmlspecialchars($n['message']); ?></p>
                        </div>
                      </div>
                      <span class="text-[10px] text-slate-400 whitespace-nowrap bg-black/30 px-2 py-0.5 rounded-md font-mono"><?php echo date("M d, H:i", strtotime($n['created_at'])); ?></span>
                    </div>
                  <?php endforeach; ?>
                <?php endif; ?>
              </div>
            </div>

            <!-- ══════════════════════════════════════════════════════════ -->
            <!-- UNIVERSITY LOGO PHOTO UPLOADER (Fuula Hundarratti)         -->
            <!-- ══════════════════════════════════════════════════════════ -->
            <div id="logoSection" class="bg-slate-900/80 border border-white/10 rounded-2xl p-6 shadow-xl scroll-mt-20">
              <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div class="flex items-center gap-4">
                  <div id="dashLogoPreview" class="w-14 h-14 rounded-2xl bg-gradient-to-br from-red-600 to-rose-700 flex items-center justify-center text-2xl shadow-lg border-2 border-white/20 overflow-hidden shrink-0">
                    <?php if($site_logo): ?>
                      <img src="<?php echo $site_logo; ?>" alt="Site Logo" class="w-full h-full object-cover site-logo-img" />
                    <?php else: ?>
                      <span class="site-logo-fallback">🎓</span>
                    <?php endif; ?>
                  </div>
                  <div>
                    <h3 class="font-bold text-white text-sm flex items-center gap-2">🏷️ University Logo Photo (Fuula Hundarratti)</h3>
                    <p class="text-xs text-slate-400 mt-1">Logo kompitara kee irraa filadhuutii fuula hundarratti (Sign In, Create Account, fi Dashboard) jijjiiri. Yeroo namni biraa administration qabates update godhee fayyadamuu danda'a.</p>
                  </div>
                </div>
                <div class="flex items-center gap-3 shrink-0">
                  <form id="logoFormDirect" method="POST" action="index.php" enctype="multipart/form-data" class="m-0 p-0">
                    <input type="hidden" name="action" value="upload_logo">
                    <label for="dashLogoUpload" class="cursor-pointer bg-red-600 hover:bg-red-500 text-white font-bold px-4 py-2 rounded-xl text-xs flex items-center gap-2 shadow-lg transition active:scale-95">
                      <span>📷</span> Choose Logo
                    </label>
                    <input id="dashLogoUpload" name="logo" type="file" accept="image/*" class="hidden" onchange="document.getElementById('logoFormDirect').submit()" />
                  </form>
                  <form id="resetLogoFormDirect" method="POST" action="index.php" class="m-0 p-0">
                    <input type="hidden" name="action" value="reset_logo">
                    <button type="submit" id="dashResetLogoBtn" class="<?php echo $site_logo ? '' : 'hidden'; ?> bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/30 px-3 py-2 rounded-xl text-xs font-semibold transition">
                      🗑️ Reset Logo
                    </button>
                  </form>
                </div>
              </div>
            </div>

            <!-- ══════════════════════════════════════════════════════════ -->
            <!-- DASHBOARD BACKGROUND PHOTO & SIZE CONTROLS                 -->
            <!-- ══════════════════════════════════════════════════════════ -->
            <div id="bgSection" class="bg-slate-900/80 border border-white/10 rounded-2xl p-6 shadow-xl scroll-mt-20">
              <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <h3 class="font-bold text-white text-sm flex items-center gap-2">🖼️ Dashboard Background Photo</h3>
                  <p class="text-xs text-slate-400 mt-1">Suuraa kompitara kee irraa filadhuutii background godhii jijjiiri. Bal'ina (size) isaas filattee xiqqeessuu dandeessa.</p>
                </div>
                <div class="flex items-center gap-3 shrink-0">
                  <label for="dashBgUpload" class="cursor-pointer bg-red-600 hover:bg-red-500 text-white font-bold px-4 py-2 rounded-xl text-xs flex items-center gap-2 shadow-lg transition active:scale-95">
                    <span>📷</span> Choose Photo
                  </label>
                  <input id="dashBgUpload" type="file" accept="image/*" class="hidden" />
                  <button type="button" id="dashResetBgBtn" class="hidden bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/30 px-3 py-2 rounded-xl text-xs font-semibold transition">
                    🗑️ Reset Background
                  </button>
                </div>
              </div>

              <!-- Size Controls (Size isii xiqeessuuf) -->
              <div class="mt-4 pt-3 border-t border-white/10 flex flex-wrap items-center justify-between gap-3 text-xs">
                <span class="text-slate-300 font-semibold flex items-center gap-1.5">
                  <span>📐</span> Size Suuraa (Background Size):
                </span>
                <div class="inline-flex rounded-xl bg-black/40 p-1 border border-white/10 gap-1">
                  <button type="button" onclick="setBgSize('240px auto')" id="btnSizeSmall" class="px-3 py-1 rounded-lg text-xs font-semibold text-slate-300 hover:text-white transition">Xiqqaata (240px)</button>
                  <button type="button" onclick="setBgSize('360px auto')" id="btnSizeMedium" class="px-3 py-1 rounded-lg text-xs font-semibold bg-red-600 text-white shadow">Giddu-galeessa (360px)</button>
                  <button type="button" onclick="setBgSize('520px auto')" id="btnSizeLarge" class="px-3 py-1 rounded-lg text-xs font-semibold text-slate-300 hover:text-white transition">Guddaa (520px)</button>
                  <button type="button" onclick="setBgSize('cover')" id="btnSizeCover" class="px-3 py-1 rounded-lg text-xs font-semibold text-slate-300 hover:text-white transition">Full Cover</button>
                </div>
              </div>

              <div id="dashBgPreview" class="hidden mt-4 rounded-xl overflow-hidden border border-white/10 h-28 bg-contain bg-center bg-no-repeat relative bg-black/20">
                <div class="absolute inset-0 bg-black/20 flex items-center justify-center pointer-events-none">
                  <span class="text-white text-xs font-semibold bg-black/60 px-3 py-1 rounded-full">🖼️ Background Preview</span>
                </div>
              </div>
            </div>

          </div>
        </div>

      </div>

      <!-- MODAL 1: ADD STUDENT -->
      <div id="addModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-900 border border-white/20 rounded-2xl w-full max-w-md p-6 shadow-2xl animate-fade-in">
          <div class="flex items-center justify-between mb-4 pb-3 border-b border-white/10">
            <h3 class="text-base font-bold text-white">➕ Add New Student</h3>
            <button onclick="closeAddModal()" class="text-slate-400 hover:text-white">&times;</button>
          </div>
          <form method="POST" action="index.php" class="space-y-4">
            <input type="hidden" name="action" value="admin_add">
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Full Name</label>
              <input type="text" name="name" required class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Email (@gmail.com)</label>
              <input type="email" name="email" required pattern=".+@gmail\.com$" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Department</label>
              <input type="text" name="department" placeholder="e.g. Computer Science, Medicine..." class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Password</label>
              <input type="password" name="password" required minlength="6" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Role</label>
              <select name="role" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
                <option value="student">Student</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <div class="flex justify-end gap-3 pt-3 border-t border-white/10">
              <button type="button" onclick="closeAddModal()" class="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium">Cancel</button>
              <button type="submit" class="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-xs shadow">Save Student</button>
            </div>
          </form>
        </div>
      </div>

      <!-- MODAL 2: EDIT STUDENT -->
      <div id="editModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-900 border border-white/20 rounded-2xl w-full max-w-md p-6 shadow-2xl animate-fade-in">
          <div class="flex items-center justify-between mb-4 pb-3 border-b border-white/10">
            <h3 class="text-base font-bold text-white">✏️ Edit Student Data</h3>
            <button onclick="closeEditModal()" class="text-slate-400 hover:text-white">&times;</button>
          </div>
          <form method="POST" action="index.php" class="space-y-4">
            <input type="hidden" name="action" value="admin_edit">
            <input type="hidden" name="student_id" id="editStudentId">
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Full Name</label>
              <input type="text" name="name" id="editName" required class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Email (@gmail.com)</label>
              <input type="email" name="email" id="editEmail" required pattern=".+@gmail\.com$" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Department</label>
              <input type="text" name="department" id="editDepartment" placeholder="e.g. Computer Science, Medicine..." class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">New Password (leave blank to keep unchanged)</label>
              <input type="password" name="new_password" placeholder="Leave blank to keep current" minlength="6" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Role</label>
              <select name="role" id="editRole" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
                <option value="student">Student</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <div class="flex justify-end gap-3 pt-3 border-t border-white/10">
              <button type="button" onclick="closeEditModal()" class="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium">Cancel</button>
              <button type="submit" class="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-xs shadow">Update Student</button>
            </div>
          </form>
        </div>
      </div>

      <!-- MODAL 3: EDIT SUPER ADMIN PROFILE (Name & Photo) -->
      <div id="adminProfileModal" class="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-900 border border-red-500/30 rounded-2xl w-full max-w-md p-6 shadow-2xl animate-fade-in relative">
          <div class="flex items-center justify-between pb-3 border-b border-white/10 mb-4">
            <h3 class="text-base font-bold text-white flex items-center gap-2">
              <span>👤</span> Edit Super Admin Profile
            </h3>
            <button onclick="closeAdminProfileModal()" class="text-slate-400 hover:text-white text-xl leading-none">&times;</button>
          </div>

          <form method="POST" action="index.php" enctype="multipart/form-data" class="space-y-4">
            <input type="hidden" name="action" value="update_admin_profile">

            <!-- Profile Photo Upload -->
            <div class="text-center">
              <div class="relative inline-block">
                <div id="adminPhotoPreview" class="w-20 h-20 mx-auto rounded-2xl bg-white/10 border-2 border-red-400/40 shadow-inner flex items-center justify-center text-3xl font-bold text-white overflow-hidden">
                  <?php if(!empty($current_pic)): ?>
                    <img src="<?php echo htmlspecialchars($current_pic); ?>" alt="Admin Preview" class="w-full h-full object-cover" />
                  <?php else: ?>
                    <span><?php echo mb_substr($current_name, 0, 1); ?></span>
                  <?php endif; ?>
                </div>
                <label for="adminPhotoInput" class="absolute -bottom-2 -right-2 bg-red-600 hover:bg-red-500 text-white p-2 rounded-full cursor-pointer shadow-lg border border-white/30 text-xs transition">
                  📷
                </label>
              </div>
              <input id="adminPhotoInput" name="admin_photo" type="file" accept="image/*" class="hidden" onchange="previewAdminPhoto(this)" />
              <p class="text-[11px] text-slate-400 mt-2">Suuraa kee filachuuf mallattoo 📷 tuqi (Click icon to pick photo)</p>
            </div>

            <!-- Admin Name -->
            <div>
              <label class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">
                Maqaa Super Admin (Full Name)
              </label>
              <input type="text" name="admin_name" value="<?php echo htmlspecialchars($current_name); ?>" required class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500" />
            </div>

            <!-- Email (Readonly) -->
            <div>
              <label class="block text-slate-400 text-xs font-semibold uppercase tracking-wider mb-1.5">
                Admin Email (System Identifier)
              </label>
              <input type="email" value="<?php echo htmlspecialchars($display_admin_email); ?>" disabled class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800/50 text-slate-400 border border-white/10 text-xs cursor-not-allowed" />
            </div>

            <div class="flex items-center justify-end gap-3 pt-3 border-t border-white/10">
              <button type="button" onclick="closeAdminProfileModal()" class="px-4 py-2 rounded-xl text-xs font-semibold text-slate-300 hover:text-white bg-white/5 hover:bg-white/10 transition">
                Haqi (Cancel)
              </button>
              <button type="submit" class="bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-bold px-5 py-2 rounded-xl text-xs shadow-lg transition">
                💾 Haaromsi (Save Profile)
              </button>
            </div>
          </form>
        </div>
      </div>

      <!-- Delete Form -->
      <form id="deleteForm" method="POST" action="index.php" style="display:none;">
        <input type="hidden" name="action" value="admin_delete">
        <input type="hidden" name="student_id" id="deleteStudentId">
      </form>

      <script>
        const searchInput = document.getElementById('studentSearch');
        if (searchInput) {
          searchInput.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase().trim();
            document.querySelectorAll('.student-row').forEach(row => {
              const name = (row.getAttribute('data-name') || '').toLowerCase();
              const email = (row.getAttribute('data-email') || '').toLowerCase();
              const dept = (row.getAttribute('data-department') || '').toLowerCase();
              row.style.display = (name.includes(query) || email.includes(query) || dept.includes(query)) ? '' : 'none';
            });
          });
        }
        function openAddModal() { document.getElementById('addModal').classList.remove('hidden'); }
        function closeAddModal() { document.getElementById('addModal').classList.add('hidden'); }
        function openEditModal(st) {
          document.getElementById('editStudentId').value = st.id;
          document.getElementById('editName').value = st.name;
          document.getElementById('editEmail').value = st.email;
          document.getElementById('editRole').value = st.role || 'student';
          const deptEl = document.getElementById('editDepartment');
          if (deptEl) deptEl.value = st.department || 'General';
          document.getElementById('editModal').classList.remove('hidden');
        }
        function closeEditModal() { document.getElementById('editModal').classList.add('hidden'); }
        function confirmDelete(id, name) {
          if (confirm("Dhuguma barataa '" + name + "' balleessuu (delete) barbaadduu?")) {
            document.getElementById('deleteStudentId').value = id;
            document.getElementById('deleteForm').submit();
          }
        }
        function toggleSidebar(open) {
          const sidebar = document.getElementById('sidebar');
          const backdrop = document.getElementById('sidebarBackdrop');
          if (!sidebar) return;
          if (open) {
            sidebar.classList.remove('-translate-x-full');
            if (backdrop) backdrop.classList.remove('hidden');
          } else {
            sidebar.classList.add('-translate-x-full');
            if (backdrop) backdrop.classList.add('hidden');
          }
        }

        // Active State Handler for Sidebar Buttons
        function setActiveNavItem(id) {
          document.querySelectorAll('.admin-nav-item').forEach(el => {
            el.classList.remove('bg-red-600', 'text-white', 'font-bold', 'shadow-lg', 'shadow-red-950/50');
            el.classList.add('text-slate-300', 'hover:text-white', 'hover:bg-white/5');
          });
          const active = document.getElementById(id);
          if (active) {
            active.classList.add('bg-red-600', 'text-white', 'font-bold', 'shadow-lg', 'shadow-red-950/50');
            active.classList.remove('text-slate-300', 'hover:text-white', 'hover:bg-white/5');
          }
        }

        // Pulse Glowing Highlight on Target Section
        function highlightSection(section) {
          if (!section) return;
          section.scrollIntoView({ behavior: 'smooth', block: 'start' });
          section.classList.remove('ring-4', 'ring-red-500/70', 'shadow-2xl', 'shadow-red-950/60');
          void section.offsetWidth; // force browser layout recalculation
          section.classList.add('ring-4', 'ring-red-500/70', 'shadow-2xl', 'shadow-red-950/60', 'transition-all', 'duration-500');
          setTimeout(() => {
            section.classList.remove('ring-4', 'ring-red-500/70', 'shadow-2xl', 'shadow-red-950/60');
          }, 1800);
        }

        // Master Navigation Router for Sidebar & Header Triggers
        function adminNav(target) {
          toggleSidebar(false); // Auto-close drawer on mobile devices

          if (target === 'dashboard') {
            setActiveNavItem('navItem_dashboard');
            const dashTop = document.getElementById('dashboardTop');
            if (dashTop) {
              dashTop.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } else {
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }
          } else if (target === 'students') {
            setActiveNavItem('navItem_students');
            const sec = document.getElementById('studentsSection');
            highlightSection(sec);
            setTimeout(() => {
              const search = document.getElementById('studentSearch');
              if (search) search.focus();
            }, 500);
          } else if (target === 'add_student') {
            openAddModal();
            setTimeout(() => {
              const nameInp = document.querySelector('#addModal input[name="name"]');
              if (nameInp) nameInp.focus();
            }, 180);
          } else if (target === 'notifications') {
            setActiveNavItem('navItem_notifications');
            const sec = document.getElementById('notificationsSection');
            highlightSection(sec);
          } else if (target === 'logo') {
            setActiveNavItem('navItem_logo');
            const sec = document.getElementById('logoSection');
            highlightSection(sec);
          } else if (target === 'background') {
            setActiveNavItem('navItem_bg');
            const sec = document.getElementById('bgSection');
            highlightSection(sec);
          } else if (target === 'profile') {
            openAdminProfileModal();
            setTimeout(() => {
              const adminNameInp = document.querySelector('#adminProfileModal input[name="admin_name"]');
              if (adminNameInp) adminNameInp.focus();
            }, 180);
          } else if (target === 'portal') {
            window.open('login.php', '_blank');
          } else if (target === 'logout') {
            if (confirm("Dhuguma keessaa ba'uu (Logout) barbaadduu?")) {
              window.location.href = "index.php?logout=1";
            }
          }
        }

        // Automatic ScrollSpy to keep Sidebar Active Pill in sync with viewport
        window.addEventListener('DOMContentLoaded', () => {
          const sectionMappings = [
            { id: 'dashboardTop', navId: 'navItem_dashboard' },
            { id: 'studentsSection', navId: 'navItem_students' },
            { id: 'notificationsSection', navId: 'navItem_notifications' },
            { id: 'logoSection', navId: 'navItem_logo' },
            { id: 'bgSection', navId: 'navItem_bg' }
          ];

          let isThrottled = false;
          window.addEventListener('scroll', () => {
            if (isThrottled) return;
            isThrottled = true;
            setTimeout(() => { isThrottled = false; }, 100);

            const scrollPos = window.scrollY + 220;
            let currentNav = 'navItem_dashboard';

            for (let i = 0; i < sectionMappings.length; i++) {
              const el = document.getElementById(sectionMappings[i].id);
              if (el && el.offsetTop <= scrollPos) {
                currentNav = sectionMappings[i].navId;
              }
            }
            setActiveNavItem(currentNav);
          }, { passive: true });
        });
      </script>

    <?php endif; ?>

  </main>

  <script src="https://accounts.google.com/gsi/client" async defer></script>
  <script>

    // Password Toggles
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

    // ===== ADMIN PROFILE MODAL HELPERS =====
    function openAdminProfileModal() {
      const m = document.getElementById('adminProfileModal');
      if (m) m.classList.remove('hidden');
    }
    function closeAdminProfileModal() {
      const m = document.getElementById('adminProfileModal');
      if (m) m.classList.add('hidden');
    }
    function previewAdminPhoto(input) {
      if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
          const preview = document.getElementById('adminPhotoPreview');
          if (preview) {
            preview.innerHTML = '<img src="' + e.target.result + '" alt="Preview" class="w-full h-full object-cover" />';
          }
        };
        reader.readAsDataURL(input.files[0]);
      }
    }

    // ===== SHARED BACKGROUND PHOTO SYSTEM =====
    const BG_KEY = 'alnasrii_bg_data';
    const BG_SIZE_KEY = 'alnasrii_bg_size';
    let currentBgSize = localStorage.getItem(BG_SIZE_KEY) || '360px auto';

    function setBgSize(size) {
      currentBgSize = size;
      localStorage.setItem(BG_SIZE_KEY, size);
      const pageBody = document.getElementById('pageBody');
      if (pageBody) {
        pageBody.style.backgroundSize = size;
        pageBody.style.backgroundRepeat = 'no-repeat';
        pageBody.style.backgroundPosition = (size === 'cover') ? 'center' : 'center 120px';
      }
      updateBgSizeButtons();
    }

    function updateBgSizeButtons() {
      const map = {
        '240px auto': 'btnSizeSmall',
        '360px auto': 'btnSizeMedium',
        '520px auto': 'btnSizeLarge',
        'cover': 'btnSizeCover'
      };
      ['btnSizeSmall', 'btnSizeMedium', 'btnSizeLarge', 'btnSizeCover'].forEach(id => {
        const btn = document.getElementById(id);
        if (!btn) return;
        btn.classList.remove('bg-red-600', 'bg-emerald-600', 'text-white', 'shadow');
        btn.classList.add('text-slate-300');
      });
      const activeId = map[currentBgSize] || 'btnSizeMedium';
      const activeBtn = document.getElementById(activeId);
      if (activeBtn) {
        activeBtn.classList.add('bg-red-600', 'text-white', 'shadow');
        activeBtn.classList.remove('text-slate-300');
      }
    }

    function applyBackground(dataUrl) {
      // Apply to auth card if exists
      const cardBg = document.getElementById('cardBg');
      if (cardBg) {
        cardBg.style.backgroundImage = "url('" + dataUrl + "')";
      }
      // Apply to full page body (for admin dashboard) with controlled smaller size
      const pageBody = document.getElementById('pageBody');
      if (pageBody) {
        pageBody.style.backgroundImage = "url('" + dataUrl + "')";
        pageBody.style.backgroundSize = currentBgSize;
        pageBody.style.backgroundRepeat = 'no-repeat';
        pageBody.style.backgroundPosition = (currentBgSize === 'cover') ? 'center' : 'center 120px';
        pageBody.style.backgroundAttachment = 'fixed';
      }
      // Show preview if available
      const preview = document.getElementById('dashBgPreview');
      if (preview) {
        preview.style.backgroundImage = "url('" + dataUrl + "')";
        preview.classList.remove('hidden');
      }
    }

    function clearBackground() {
      const cardBg = document.getElementById('cardBg');
      if (cardBg) cardBg.style.backgroundImage = 'none';
      const pageBody = document.getElementById('pageBody');
      if (pageBody) pageBody.style.backgroundImage = 'none';
      const preview = document.getElementById('dashBgPreview');
      if (preview) {
        preview.style.backgroundImage = 'none';
        preview.classList.add('hidden');
      }
      localStorage.removeItem(BG_KEY);
    }

    // Restore saved background on page load
    const savedBg = localStorage.getItem(BG_KEY);
    if (savedBg) {
      applyBackground(savedBg);
    }
    updateBgSizeButtons();

    // --- Admin Dashboard page uploader ---
    const dashBgUpload = document.getElementById('dashBgUpload');
    const dashResetBgBtn = document.getElementById('dashResetBgBtn');

    if (dashBgUpload) {
      if (savedBg && dashResetBgBtn) dashResetBgBtn.classList.remove('hidden');

      dashBgUpload.addEventListener('change', (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (event) => {
          const dataUrl = event.target.result;
          applyBackground(dataUrl);
          try { localStorage.setItem(BG_KEY, dataUrl); } catch (err) {
            alert('Suuraan baay\'ee guddaadha! Suuraa xiqqoo fayyadamaa. (Image too large for local storage)');
          }
          if (dashResetBgBtn) dashResetBgBtn.classList.remove('hidden');
        };
        reader.readAsDataURL(file);
      });
    }

    if (dashResetBgBtn) {
      dashResetBgBtn.addEventListener('click', () => {
        clearBackground();
        if (dashBgUpload) dashBgUpload.value = '';
        dashResetBgBtn.classList.add('hidden');
      });
    }

    // ===== SHARED LOGO SYSTEM (ACROSS ALL PAGES) =====
    const LOGO_KEY = 'alnasrii_logo_data';

    function applyLogo(dataUrl) {
      document.querySelectorAll('.site-logo-icon, .site-logo-badge, #dashLogoPreview').forEach(el => {
        let img = el.querySelector('img.site-logo-img');
        let fallback = el.querySelector('.site-logo-fallback');
        if (!img) {
          img = document.createElement('img');
          img.className = 'w-full h-full object-cover site-logo-img';
          img.alt = 'Logo';
          el.appendChild(img);
        }
        img.src = dataUrl;
        img.classList.remove('hidden');
        if (fallback) fallback.classList.add('hidden');
      });
    }

    function clearLogo() {
      document.querySelectorAll('.site-logo-icon, .site-logo-badge, #dashLogoPreview').forEach(el => {
        const img = el.querySelector('img.site-logo-img');
        const fallback = el.querySelector('.site-logo-fallback');
        if (img) img.remove();
        if (fallback) fallback.classList.remove('hidden');
      });
      localStorage.removeItem(LOGO_KEY);
    }

    // Restore saved logo from localStorage
    const savedLogo = localStorage.getItem(LOGO_KEY);
    if (savedLogo) {
      applyLogo(savedLogo);
    }

    // --- Admin Dashboard Logo uploader ---
    const dashLogoUpload = document.getElementById('dashLogoUpload');
    const dashResetLogoBtn = document.getElementById('dashResetLogoBtn');

    if (dashLogoUpload) {
      if ((savedLogo || "<?php echo get_site_logo() ? 'yes' : ''; ?>") && dashResetLogoBtn) {
        dashResetLogoBtn.classList.remove('hidden');
      }

      dashLogoUpload.addEventListener('change', (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (event) => {
          const dataUrl = event.target.result;
          applyLogo(dataUrl);
          try { localStorage.setItem(LOGO_KEY, dataUrl); } catch (err){}
          if (dashResetLogoBtn) dashResetLogoBtn.classList.remove('hidden');

          // Send to server to persist permanently as uploads/logo.png
          const formData = new FormData();
          formData.append('action', 'upload_logo');
          formData.append('logo', file);

          fetch('index.php', {
            method: 'POST',
            body: formData
          })
          .then(res => res.json())
          .then(res => {
            if (!res.success) {
              console.warn('Server upload:', res.message);
            }
          })
          .catch(err => console.error(err));
        };
        reader.readAsDataURL(file);
      });
    }

    if (dashResetLogoBtn) {
      dashResetLogoBtn.addEventListener('click', () => {
        clearLogo();
        if (dashLogoUpload) dashLogoUpload.value = '';
        dashResetLogoBtn.classList.add('hidden');

        const formData = new FormData();
        formData.append('action', 'reset_logo');
        fetch('index.php', { method: 'POST', body: formData }).catch(err => console.error(err));
      });
    }

    // Google Sign-In
    function handleGoogleResponse(response) {
      if (!response.credential) return;
      fetch('index.php?action=google_auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: response.credential })
      })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          window.location.href = 'index.php';
        } else {
          alert('Google error: ' + (data.message || 'Unknown error'));
        }
      })
      .catch(err => {
        console.error(err);
        alert('Server connection error');
      });
    }

    const gBtn = document.getElementById('googleCustomBtn');
    if (gBtn) {
      gBtn.addEventListener('click', () => {
        if (window.google && google.accounts && google.accounts.id) {
          google.accounts.id.prompt();
        } else {
          alert('Google Client is loading or blocked by your browser extensions.');
        }
      });
    }
  </script>
</body>
</html>
