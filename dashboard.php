<?php
include 'config.php';

// Check if user is logged in
if (!isset($_SESSION['student_name']) || !isset($_SESSION['student_email'])) {
    header("Location: login.php");
    exit();
}

$current_user_name  = $_SESSION['student_name'];
$current_user_email = $_SESSION['student_email'];
$current_user_pic   = $_SESSION['student_picture'] ?? '';
$is_admin_user      = is_admin($current_user_email);

// Ensure admin role for admin user in DB
if ($is_admin_user) {
    @$conn->query("UPDATE students SET role = 'admin' WHERE email = '" . $conn->real_escape_string($current_user_email) . "'");
}

$alert_message = "";
$alert_type = "";

// ==========================================
// ADMIN CRUD HANDLERS (Add, Edit, Delete)
// ==========================================
if ($is_admin_user && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'add_student') {
        $name     = trim($_POST['name'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $phone    = trim($_POST['phone'] ?? '');
        $password = $_POST['password'] ?? '';
        $role     = trim($_POST['role'] ?? 'student');

        if (empty($name) || empty($email)) {
            $alert_message = "Please fill in all required fields!";
            $alert_type = "error";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $email)) {
            $alert_message = "Only Google accounts (@gmail.com) are allowed!";
            $alert_type = "error";
        } else {
            // Check duplicate
            $check_stmt = $conn->prepare("SELECT id FROM students WHERE email = ?");
            $check_stmt->bind_param("s", $email);
            $check_stmt->execute();
            $check_stmt->store_result();
            if ($check_stmt->num_rows > 0) {
                $alert_message = "This email is already registered!";
                $alert_type = "error";
            } else {
                $check_stmt->close();
                $hashed = !empty($password) ? password_hash($password, PASSWORD_DEFAULT) : password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT);
                $ins_stmt = $conn->prepare("INSERT INTO students (name, email, password, role, phone) VALUES (?, ?, ?, ?, ?)");
                if ($ins_stmt) {
                    $ins_stmt->bind_param("sssss", $name, $email, $hashed, $role, $phone);
                    if ($ins_stmt->execute()) {
                        $alert_message = "New student ('" . htmlspecialchars($name) . "') added successfully!";
                        $alert_type = "success";
                        require_once 'notify.php';
                        if (function_exists('notify_admin_new_registration')) {
                            @notify_admin_new_registration($name, $email, "Admin Dashboard Add (Tel: $phone)");
                        }
                    } else {
                        $alert_message = "Error occurred: " . $ins_stmt->error;
                        $alert_type = "error";
                    }
                    $ins_stmt->close();
                }
            }
        }
    }

    // 2. EDIT / UPDATE STUDENT
    elseif ($action === 'edit_student') {
        $student_id = (int)($_POST['student_id'] ?? 0);
        $name       = trim($_POST['name'] ?? '');
        $email      = trim($_POST['email'] ?? '');
        $phone      = trim($_POST['phone'] ?? '');
        $new_pwd    = $_POST['new_password'] ?? '';
        $role       = trim($_POST['role'] ?? 'student');

        if ($student_id <= 0 || empty($name) || empty($email)) {
            $alert_message = "Invalid or incomplete student data!";
            $alert_type = "error";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $email)) {
            $alert_message = "Only Google accounts (@gmail.com) are allowed!";
            $alert_type = "error";
        } else {
            // Check duplicate email for another student
            $dup_stmt = $conn->prepare("SELECT id FROM students WHERE email = ? AND id != ?");
            $dup_stmt->bind_param("si", $email, $student_id);
            $dup_stmt->execute();
            $dup_stmt->store_result();

            if ($dup_stmt->num_rows > 0) {
                $alert_message = "This email is already taken by another student!";
                $alert_type = "error";
            } else {
                $dup_stmt->close();
                if (!empty($new_pwd)) {
                    if (strlen($new_pwd) < 6) {
                        $alert_message = "Password must be at least 6 characters long!";
                        $alert_type = "error";
                    } else {
                        $new_hashed = password_hash($new_pwd, PASSWORD_DEFAULT);
                        $up_stmt = $conn->prepare("UPDATE students SET name = ?, email = ?, password = ?, role = ?, phone = ? WHERE id = ?");
                        $up_stmt->bind_param("sssssi", $name, $email, $new_hashed, $role, $phone, $student_id);
                        if ($up_stmt->execute()) {
                            $alert_message = "Student details and password updated successfully!";
                            $alert_type = "success";
                        } else {
                            $alert_message = "Update error: " . $up_stmt->error;
                            $alert_type = "error";
                        }
                        $up_stmt->close();
                    }
                } else {
                    $up_stmt = $conn->prepare("UPDATE students SET name = ?, email = ?, role = ?, phone = ? WHERE id = ?");
                    $up_stmt->bind_param("ssssi", $name, $email, $role, $phone, $student_id);
                    if ($up_stmt->execute()) {
                        $alert_message = "Student details updated successfully!";
                        $alert_type = "success";
                    } else {
                        $alert_message = "Update error: " . $up_stmt->error;
                        $alert_type = "error";
                    }
                    $up_stmt->close();
                }
            }
        }
    }

    // 3. DELETE STUDENT
    elseif ($action === 'delete_student') {
        $student_id = (int)($_POST['student_id'] ?? 0);
        if ($student_id <= 0) {
            $alert_message = "Student ID not found!";
            $alert_type = "error";
        } else {
            // Prevent admin from deleting themselves
            $chk_self = $conn->prepare("SELECT email FROM students WHERE id = ?");
            $chk_self->bind_param("i", $student_id);
            $chk_self->execute();
            $chk_self->bind_result($del_email);
            if ($chk_self->fetch() && strtolower($del_email) === strtolower($current_user_email)) {
                $alert_message = "You cannot delete your own admin account!";
                $alert_type = "error";
            } else {
                $chk_self->close();
                $del_stmt = $conn->prepare("DELETE FROM students WHERE id = ?");
                $del_stmt->bind_param("i", $student_id);
                if ($del_stmt->execute()) {
                    $alert_message = "Student deleted successfully!";
                    $alert_type = "success";
                } else {
                    $alert_message = "Delete error: " . $del_stmt->error;
                    $alert_type = "error";
                }
                $del_stmt->close();
            }
        }
    }
}

// Fetch all students for Admin view (Filter out admin4566 and admin123 accounts)
$all_students = [];
$total_students = 0;
if ($is_admin_user) {
    $res = $conn->query("SELECT id, name, email, phone, role, created_at FROM students ORDER BY id DESC");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $em_lower = strtolower(trim($row['email'] ?? ''));
            $nm_lower = strtolower(trim($row['name'] ?? ''));
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

// Fetch registration date of current user
$joined_date = "Recent";
$stmt_me = $conn->prepare("SELECT created_at FROM students WHERE email = ?");
if ($stmt_me) {
    $stmt_me->bind_param("s", $current_user_email);
    $stmt_me->execute();
    $stmt_me->bind_result($db_date);
    if ($stmt_me->fetch()) {
        $joined_date = date("M d, Y", strtotime($db_date));
    }
    $stmt_me->close();
}

// Fetch notifications
$notifications = [];
$notif_res = $conn->query("SELECT title, message, student_email, created_at FROM notifications ORDER BY id DESC LIMIT 8");
if ($notif_res) {
    while ($nrow = $notif_res->fetch_assoc()) {
        $notifications[] = $nrow;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Alnasrii University - <?php echo $is_admin_user ? 'Admin Management Dashboard' : 'Student Status'; ?></title>

  <!-- Google Fonts: Inter -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">

  <!-- Tailwind CSS -->
  <script src="https://cdn.tailwindcss.com"></script>

  <style>
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(-8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .animate-fade-in {
      animation: fadeIn 0.25s ease-out forwards;
    }

    /* Universal Smooth Transitions */
    button, a, input, select, textarea, .stat-card, .site-logo-icon, tr {
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }

    /* Button Hover Elevation */
    button:not(:disabled):hover, a[class*="bg-"]:hover {
      transform: translateY(-2px);
    }
    button:not(:disabled):active, a[class*="bg-"]:active {
      transform: translateY(0) scale(0.97);
    }

    button[type="submit"]:hover, button[class*="bg-red"]:hover {
      box-shadow: 0 10px 25px -5px rgba(239, 68, 68, 0.4), 0 0 18px rgba(239, 68, 68, 0.25);
    }

    .site-logo-icon:hover {
      transform: scale(1.08) rotate(2deg);
      box-shadow: 0 0 20px rgba(16, 185, 129, 0.45);
    }

    input:hover:not(:disabled), select:hover:not(:disabled) {
      border-color: rgba(255, 255, 255, 0.35);
    }
  </style>
</head>
<body class="min-h-screen bg-slate-900 text-slate-100 selection:bg-green-500 selection:text-white pb-12">

  <!-- Top Navigation Bar -->
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
          <?php if($is_admin_user): ?>
            <span class="text-xs bg-red-500/20 text-red-300 border border-red-500/30 px-2 py-0.5 rounded-full ml-2 font-bold tracking-wide uppercase">
              Admin Portal
            </span>
          <?php else: ?>
            <span class="text-xs bg-green-500/20 text-green-300 border border-green-500/30 px-2 py-0.5 rounded-full ml-2 font-medium">
              Student
            </span>
          <?php endif; ?>
        </div>
      </div>

      <div class="flex items-center gap-3">
        <a href="forgot_password.php" class="text-xs text-slate-300 hover:text-white bg-white/5 hover:bg-white/10 px-3 py-1.5 rounded-lg border border-white/10 transition">
          Change Password
        </a>
        <a href="logout.php" class="text-xs text-red-300 hover:text-white bg-red-500/10 hover:bg-red-500/20 px-3 py-1.5 rounded-lg border border-red-500/30 transition font-semibold">
          Logout
        </a>
      </div>
    </div>
  </header>

  <main class="max-w-6xl mx-auto px-4 sm:px-6 py-8">

    <!-- Alert Notifications Banner -->
    <?php if(!empty($alert_message)): ?>
      <div class="mb-6 p-4 rounded-xl text-sm font-medium flex items-center justify-between gap-3 animate-fade-in <?php echo $alert_type === 'success' ? 'bg-emerald-500/20 border border-emerald-500/40 text-emerald-200' : 'bg-red-500/20 border border-red-500/40 text-red-200'; ?>">
        <div class="flex items-center gap-2.5">
          <span><?php echo $alert_type === 'success' ? '✅' : '⚠️'; ?></span>
          <span><?php echo htmlspecialchars($alert_message); ?></span>
        </div>
        <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-white text-xs">&times;</button>
      </div>
    <?php endif; ?>

    <!-- Welcome Hero Card -->
    <div class="relative overflow-hidden rounded-2xl bg-gradient-to-r from-emerald-800 via-green-800 to-teal-900 p-6 sm:p-8 shadow-2xl border border-emerald-500/30 mb-8">
      <div class="relative z-10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
        <div class="flex items-center gap-4">
          <?php if(!empty($current_user_pic)): ?>
            <img src="<?php echo htmlspecialchars($current_user_pic); ?>" alt="Profile" class="w-16 h-16 rounded-2xl border-2 border-white/30 shadow-lg object-cover">
          <?php else: ?>
            <div class="w-16 h-16 rounded-2xl bg-white/20 border-2 border-white/30 shadow-lg flex items-center justify-center text-2xl font-bold text-white uppercase backdrop-blur-md">
              <?php echo mb_substr($current_user_name, 0, 1); ?>
            </div>
          <?php endif; ?>

          <div>
            <div class="inline-flex items-center gap-1.5 text-xs text-green-200 bg-black/20 px-2.5 py-1 rounded-full mb-1">
              <span class="w-2 h-2 rounded-full <?php echo $is_admin_user ? 'bg-red-400' : 'bg-emerald-400'; ?> animate-pulse"></span>
              <?php echo $is_admin_user ? 'Administrator System Control' : 'Active Student Account'; ?>
            </div>
            <h1 class="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Welcome, <?php echo htmlspecialchars($current_user_name); ?>!
            </h1>
            <p class="text-sm text-green-100/90 mt-1 flex items-center gap-2">
              <svg class="w-4 h-4 text-green-300" fill="currentColor" viewBox="0 0 20 20"><path d="M2.003 5.884L10 9.882l7.997-3.998A2 2 0 0016 4H4a2 2 0 00-1.997 1.884z"></path><path d="M18 8.118l-8 4-8-4V14a2 2 0 002 2h12a2 2 0 002-2V8.118z"></path></svg>
              <?php echo htmlspecialchars($current_user_email); ?>
            </p>
          </div>
        </div>

        <div class="bg-black/20 border border-white/10 rounded-xl px-4 py-3 text-xs text-green-100 backdrop-blur-md">
          <p class="text-white/60 text-[11px] uppercase tracking-wider font-semibold">Registered Since</p>
          <p class="text-sm font-bold text-white mt-0.5"><?php echo htmlspecialchars($joined_date); ?></p>
        </div>
      </div>
    </div>

    <!-- ============================================================== -->
    <!-- CASE 1: REGULAR USER (STUDENT ONLY - CONFIRMATION ONLY)       -->
    <!-- ============================================================== -->
    <?php if(!$is_admin_user): ?>
      <div class="bg-slate-800/60 border border-white/10 rounded-2xl p-8 text-center max-w-2xl mx-auto shadow-xl">
        <div class="w-20 h-20 mx-auto rounded-3xl bg-emerald-500/20 border border-emerald-400/30 flex items-center justify-center text-4xl mb-4">
          🎉
        </div>
        <h2 class="text-2xl font-bold text-white mb-2">Registration Successful!</h2>
        <p class="text-emerald-300 font-medium text-sm mb-4">
          Your student account has been registered and confirmed successfully!
        </p>

        <div class="p-4 rounded-xl bg-white/5 border border-white/10 text-left text-xs space-y-2 mb-6">
          <div class="flex justify-between py-1 border-b border-white/10">
            <span class="text-slate-400">Student Name:</span>
            <span class="font-bold text-white"><?php echo htmlspecialchars($current_user_name); ?></span>
          </div>
          <div class="flex justify-between py-1 border-b border-white/10">
            <span class="text-slate-400">Registered Email:</span>
            <span class="font-bold text-white"><?php echo htmlspecialchars($current_user_email); ?></span>
          </div>
          <div class="flex justify-between py-1">
            <span class="text-slate-400">Account Status:</span>
            <span class="text-emerald-400 font-bold">Confirmed / Active</span>
          </div>
        </div>

        <div class="p-4 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-200 text-xs text-left mb-6 leading-relaxed">
          ℹ️ <strong>Notice:</strong> This is your student status overview. Administrative controls (Student Directory, Add, Edit, Delete) are restricted to authorized administrators only.
        </div>

        <div class="flex justify-center gap-3">
          <a href="logout.php" class="bg-white text-slate-900 font-bold px-6 py-2.5 rounded-lg text-xs hover:bg-slate-200 transition">
            Sign Out
          </a>
        </div>
      </div>

    <!-- ============================================================== -->
    <!-- CASE 2: ADMIN USER ONLY (FULL CRUD: ADD, EDIT, DELETE, SEARCH) -->
    <!-- ============================================================== -->
    <?php else: ?>

      <!-- Admin Stats Cards -->
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-5 mb-8">
        <div class="bg-slate-800/60 border border-white/10 rounded-2xl p-5 flex items-center justify-between">
          <div>
            <p class="text-xs uppercase text-slate-400 font-semibold tracking-wider">Total Registered Students</p>
            <p class="text-3xl font-extrabold text-white mt-1"><?php echo $total_students; ?></p>
          </div>
          <div class="w-12 h-12 rounded-2xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-xl">
            👥
          </div>
        </div>

        <div class="bg-slate-800/60 border border-white/10 rounded-2xl p-5 flex items-center justify-between">
          <div>
            <p class="text-xs uppercase text-slate-400 font-semibold tracking-wider">System Role</p>
            <p class="text-xl font-extrabold text-red-400 mt-1">Super Admin</p>
          </div>
          <div class="w-12 h-12 rounded-2xl bg-red-500/20 text-red-400 flex items-center justify-center text-xl">
            ⚡
          </div>
        </div>

        <div class="bg-slate-800/60 border border-white/10 rounded-2xl p-5 flex items-center justify-between">
          <div>
            <p class="text-xs uppercase text-slate-400 font-semibold tracking-wider">Total Alerts</p>
            <p class="text-3xl font-extrabold text-blue-400 mt-1"><?php echo count($notifications); ?></p>
          </div>
          <div class="w-12 h-12 rounded-2xl bg-blue-500/20 text-blue-400 flex items-center justify-center text-xl">
            🔔
          </div>
        </div>
      </div>

      <!-- Management Controls: Search + Add Student Button -->
      <div class="bg-slate-800/60 border border-white/10 rounded-2xl p-6 shadow-xl mb-8">
        <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 mb-6">
          <div>
            <h2 class="text-xl font-bold text-white flex items-center gap-2">
              <span>📋</span> Student Management (CRUD Control)
            </h2>
            <p class="text-xs text-slate-400 mt-0.5">Add new students, edit existing student records, or delete students.</p>
          </div>

          <div class="flex items-center gap-3">
            <!-- Search Box -->
            <div class="relative">
              <input
                type="text" id="studentSearch"
                placeholder="Search name, email, or phone..."
                class="px-3.5 py-2 pl-9 rounded-xl bg-slate-900 border border-white/10 text-white placeholder-slate-400 text-xs outline-none focus:ring-2 focus:ring-emerald-500 w-48 sm:w-60"
              />
              <span class="absolute left-3 top-2.5 text-slate-400 text-xs">🔍</span>
            </div>

            <!-- Add Student Button -->
            <button
              onclick="openAddModal()"
              class="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-4 py-2 rounded-xl text-xs flex items-center gap-2 shadow-lg transition active:scale-95 whitespace-nowrap"
            >
              <span>➕</span> Add Student
            </button>
          </div>
        </div>

        <!-- Students Table -->
        <div class="overflow-x-auto rounded-xl border border-white/10">
          <table class="w-full text-left text-xs" id="studentsTable">
            <thead class="bg-slate-950/60 text-slate-400 uppercase text-[11px] tracking-wider border-b border-white/10">
              <tr>
                <th class="py-3 px-4">ID</th>
                <th class="py-3 px-4">Student Name</th>
                <th class="py-3 px-4">Email</th>
                <th class="py-3 px-4">Phone</th>
                <th class="py-3 px-4">Role</th>
                <th class="py-3 px-4">Registered Date</th>
                <th class="py-3 px-4 text-center">Actions</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
              <?php if(empty($all_students)): ?>
                <tr>
                  <td colspan="7" class="py-8 text-center text-slate-400">
                    No registered students found.
                  </td>
                </tr>
              <?php else: ?>
                <?php foreach($all_students as $st): ?>
                  <tr class="student-row hover:bg-white/5 transition" data-name="<?php echo htmlspecialchars(strtolower($st['name'])); ?>" data-email="<?php echo htmlspecialchars(strtolower($st['email'])); ?>" data-phone="<?php echo htmlspecialchars(strtolower($st['phone'] ?? '')); ?>">
                    <td class="py-3.5 px-4 font-mono text-slate-400">#<?php echo $st['id']; ?></td>
                    <td class="py-3.5 px-4 font-semibold text-white flex items-center gap-2.5">
                      <div class="w-7 h-7 rounded-full bg-emerald-500/20 text-emerald-300 font-bold flex items-center justify-center text-xs">
                        <?php echo mb_substr($st['name'], 0, 1); ?>
                      </div>
                      <span><?php echo htmlspecialchars($st['name']); ?></span>
                    </td>
                    <td class="py-3.5 px-4 text-slate-300"><?php echo htmlspecialchars($st['email']); ?></td>
                    <td class="py-3.5 px-4 font-mono text-emerald-300 text-xs"><?php echo htmlspecialchars($st['phone'] ?? '-'); ?></td>
                    <td class="py-3.5 px-4">
                      <?php if($st['role'] === 'admin'): ?>
                        <span class="bg-red-500/20 text-red-300 border border-red-500/30 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase">Admin</span>
                      <?php else: ?>
                        <span class="bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded-full text-[10px] font-medium">Student</span>
                      <?php endif; ?>
                    </td>
                    <td class="py-3.5 px-4 text-slate-400"><?php echo date("M d, Y H:i", strtotime($st['created_at'])); ?></td>
                    <td class="py-3.5 px-4 text-center">
                      <div class="inline-flex items-center gap-2">
                        <!-- Edit Button -->
                        <button
                          onclick='openEditModal(<?php echo json_encode($st); ?>)'
                          class="bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 border border-blue-500/30 px-2.5 py-1 rounded-lg text-xs font-medium transition"
                          title="Edit Student"
                        >
                          ✏️ Edit
                        </button>

                        <!-- Delete Button -->
                        <button
                          onclick="confirmDelete(<?php echo $st['id']; ?>, '<?php echo htmlspecialchars(addslashes($st['name'])); ?>')"
                          class="bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/30 px-2.5 py-1 rounded-lg text-xs font-medium transition"
                          title="Delete Student"
                        >
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

      <!-- Activity & Notifications Log Section -->
      <div class="bg-slate-800/60 border border-white/10 rounded-2xl p-6 shadow-xl">
        <div class="flex items-center justify-between mb-4 pb-3 border-b border-white/10">
          <h2 class="font-bold text-base text-white flex items-center gap-2">
            <span>🔔</span> Recent Registration Activity &amp; Alerts
          </h2>
          <span class="text-xs text-slate-400">Total: <?php echo count($notifications); ?></span>
        </div>

        <?php if(empty($notifications)): ?>
          <p class="text-xs text-slate-400 py-4 text-center">No recent notifications or alerts.</p>
        <?php else: ?>
          <div class="space-y-2.5">
            <?php foreach($notifications as $n): ?>
              <div class="p-3 rounded-xl bg-white/5 border border-white/5 flex items-start justify-between gap-4 text-xs">
                <div>
                  <p class="font-semibold text-white"><?php echo htmlspecialchars($n['title']); ?></p>
                  <p class="text-slate-300 mt-0.5"><?php echo htmlspecialchars($n['message']); ?></p>
                  <span class="text-[10px] text-slate-500 mt-1 inline-block">Recipient: <?php echo htmlspecialchars($n['student_email']); ?></span>
                </div>
                <span class="text-[10px] text-slate-400 whitespace-nowrap"><?php echo date("M d, H:i", strtotime($n['created_at'])); ?></span>
              </div>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </div>

      <!-- ========================================== -->
      <!-- MODAL 1: ADD NEW STUDENT                   -->
      <!-- ========================================== -->
      <div id="addModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-900 border border-white/20 rounded-2xl w-full max-w-md p-6 shadow-2xl relative animate-fade-in">
          <div class="flex items-center justify-between mb-4 pb-3 border-b border-white/10">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>➕</span> Add New Student
            </h3>
            <button onclick="closeAddModal()" class="text-slate-400 hover:text-white text-lg">&times;</button>
          </div>

          <form method="POST" action="dashboard.php" class="space-y-4">
            <input type="hidden" name="action" value="add_student">

            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Full Name</label>
              <input type="text" name="name" placeholder="e.g. Caalaa Beekaa" required class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-emerald-500">
            </div>

            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Email (@gmail.com)</label>
              <input type="email" name="email" placeholder="student@gmail.com" required pattern=".+@gmail\.com$" title="Only @gmail.com is allowed" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-emerald-500">
            </div>

            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Phone Number</label>
              <input type="tel" name="phone" placeholder="e.g. 0912345678" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-emerald-500">
            </div>

            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Password (Optional)</label>
              <input type="password" name="password" placeholder="Leave empty for auto-generated" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-emerald-500">
            </div>

            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Role</label>
              <select name="role" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-emerald-500">
                <option value="student">Student</option>
                <option value="admin">Admin</option>
              </select>
            </div>

            <div class="flex justify-end gap-3 pt-3 border-t border-white/10">
              <button type="button" onclick="closeAddModal()" class="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium">Cancel</button>
              <button type="submit" class="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow">Save Student</button>
            </div>
          </form>
        </div>
      </div>

      <!-- ========================================== -->
      <!-- MODAL 2: EDIT STUDENT                      -->
      <!-- ========================================== -->
      <div id="editModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
        <div class="bg-slate-900 border border-white/20 rounded-2xl w-full max-w-md p-6 shadow-2xl relative animate-fade-in">
          <div class="flex items-center justify-between mb-4 pb-3 border-b border-white/10">
            <h3 class="text-lg font-bold text-white flex items-center gap-2">
              <span>✏️</span> Edit Student Data
            </h3>
            <button onclick="closeEditModal()" class="text-slate-400 hover:text-white text-lg">&times;</button>
          </div>

          <form method="POST" action="dashboard.php" class="space-y-4">
            <input type="hidden" name="action" value="edit_student">
            <input type="hidden" name="student_id" id="editStudentId">

            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Full Name</label>
              <input type="text" name="name" id="editName" required class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-emerald-500">
            </div>

            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Email (@gmail.com)</label>
              <input type="email" name="email" id="editEmail" required pattern=".+@gmail\.com$" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-emerald-500">
            </div>

            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Phone Number</label>
              <input type="tel" name="phone" id="editPhone" placeholder="e.g. 0912345678" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-emerald-500">
            </div>

            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">New Password (leave empty to keep unchanged)</label>
              <input type="password" name="new_password" placeholder="Leave blank to keep current" minlength="6" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-emerald-500">
            </div>

            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Role</label>
              <select name="role" id="editRole" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-emerald-500">
                <option value="student">Student</option>
                <option value="admin">Admin</option>
              </select>
            </div>

            <div class="flex justify-end gap-3 pt-3 border-t border-white/10">
              <button type="button" onclick="closeEditModal()" class="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium">Cancel</button>
              <button type="submit" class="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow">Update Student</button>
            </div>
          </form>
        </div>
      </div>

      <!-- Hidden Form for Delete -->
      <form id="deleteForm" method="POST" action="dashboard.php" style="display:none;">
        <input type="hidden" name="action" value="delete_student">
        <input type="hidden" name="student_id" id="deleteStudentId">
      </form>

      <script>
        // Search Filter
        const searchInput = document.getElementById('studentSearch');
        if (searchInput) {
          searchInput.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase().trim();
            document.querySelectorAll('.student-row').forEach(row => {
              const name = row.getAttribute('data-name') || '';
              const email = row.getAttribute('data-email') || '';
              const phone = row.getAttribute('data-phone') || '';
              if (name.includes(query) || email.includes(query) || phone.includes(query)) {
                row.style.display = '';
              } else {
                row.style.display = 'none';
              }
            });
          });
        }

        // Add Modal
        function openAddModal() {
          document.getElementById('addModal').classList.remove('hidden');
        }
        function closeAddModal() {
          document.getElementById('addModal').classList.add('hidden');
        }

        // Edit Modal
        function openEditModal(student) {
          document.getElementById('editStudentId').value = student.id;
          document.getElementById('editName').value = student.name;
          document.getElementById('editEmail').value = student.email;
          document.getElementById('editRole').value = student.role || 'student';
          const phoneEl = document.getElementById('editPhone');
          if (phoneEl) phoneEl.value = student.phone || '';
          document.getElementById('editModal').classList.remove('hidden');
        }
        function closeEditModal() {
          document.getElementById('editModal').classList.add('hidden');
        }

        // Confirm Delete
        function confirmDelete(id, name) {
          if (confirm("Are you sure you want to permanently delete student '" + name + "'?")) {
            document.getElementById('deleteStudentId').value = id;
            document.getElementById('deleteForm').submit();
          }
        }
      </script>

    <?php endif; ?>

  </main>

  <footer class="text-center py-6 text-xs text-slate-500 border-t border-white/5 mt-12">
    &copy; <?php echo date('Y'); ?> Alnasrii University. Student Portal System.
  </footer>

  <script>
    // Restore custom logo if saved locally
    const savedLogo = localStorage.getItem('alnasrii_logo_data');
    if (savedLogo) {
      document.querySelectorAll('.site-logo-icon').forEach(el => {
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

    // Restore custom background with reduced size
    const savedBg = localStorage.getItem('alnasrii_bg_data');
    const savedBgSize = localStorage.getItem('alnasrii_bg_size') || '360px auto';
    if (savedBg) {
      document.body.style.backgroundImage = "url('" + savedBg + "')";
      document.body.style.backgroundSize = savedBgSize;
      document.body.style.backgroundRepeat = 'no-repeat';
      document.body.style.backgroundPosition = (savedBgSize === 'cover') ? 'center' : 'center 120px';
      document.body.style.backgroundAttachment = 'fixed';
    }
  </script>
</body>
</html>