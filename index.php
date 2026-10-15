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
$registration_success = !empty($_SESSION['registration_success']);
unset($_SESSION['registration_success']);

if (empty($_SESSION['google_login_csrf'])) {
    $_SESSION['google_login_csrf'] = bin2hex(random_bytes(32));
}

// Handle Google Login via AJAX
if (isset($_GET['action']) && $_GET['action'] === 'google_auth') {
    header('Content-Type: application/json');
    $input = json_decode(file_get_contents('php://input'), true);
    $id_token = $input['credential'] ?? '';
    $requested_email = $input['email'] ?? '';
    $csrf_token = $input['csrf_token'] ?? '';
    if (!is_string($csrf_token) || !hash_equals($_SESSION['google_login_csrf'], $csrf_token)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'The sign-in request expired. Refresh the page and try again.']);
        exit();
    }

    if (!is_string($id_token) || $id_token === '' || strlen($id_token) > 8192) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Google did not provide a valid sign-in token.']);
        exit();
    }

    if (strpos($google_client_id, 'exampleclientid') !== false) {
        error_log('Google Sign-In is not configured with a real GOOGLE_CLIENT_ID.');
        http_response_code(503);
        echo json_encode(['success' => false, 'message' => 'Google Sign-In is not configured. Please contact the administrator.']);
        exit();
    }

    $verification_url = 'https://oauth2.googleapis.com/tokeninfo?id_token=' . rawurlencode($id_token);
    $verification_context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 8,
            'ignore_errors' => true,
            'follow_location' => 0,
            'header' => "Accept: application/json\r\nConnection: close\r\n"
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true
        ]
    ]);
    $verification_response = @file_get_contents($verification_url, false, $verification_context);
    $verification_status = 0;
    foreach ($http_response_header ?? [] as $response_header) {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $response_header, $status_match)) {
            $verification_status = (int)$status_match[1];
            break;
        }
    }
    if ($verification_response === false || $verification_status === 0 || $verification_status >= 500) {
        error_log('Google ID token verification service could not be reached; HTTP status: ' . $verification_status);
        http_response_code(503);
        echo json_encode(['success' => false, 'message' => 'Google verification is temporarily unavailable. Please try again shortly.']);
        exit();
    }
    $google_identity = is_string($verification_response) && $verification_status === 200
        ? json_decode($verification_response, true)
        : null;

    if (!is_array($google_identity)
        || !isset($google_identity['aud'], $google_identity['iss'], $google_identity['exp'], $google_identity['email'], $google_identity['email_verified'], $google_identity['sub'])
        || !hash_equals($google_client_id, (string)$google_identity['aud'])
        || !in_array($google_identity['iss'], ['accounts.google.com', 'https://accounts.google.com'], true)
        || !is_numeric($google_identity['exp'])
        || (int)$google_identity['exp'] <= time()
        || !is_string($google_identity['sub'])
        || $google_identity['sub'] === ''
        || !in_array($google_identity['email_verified'], [true, 'true'], true)
        || !filter_var($google_identity['email'], FILTER_VALIDATE_EMAIL)) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Google account could not be verified. Sign in with the Google account registered to your student record.']);
        exit();
    }

    $g_email = trim($google_identity['email']);
    if (!preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $g_email)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Use the Gmail address registered to your student account.']);
        exit();
    }

    if (!is_string($requested_email)
        || !filter_var($requested_email, FILTER_VALIDATE_EMAIL)
        || !preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $requested_email)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Enter your Gmail address in the form before continuing with Google.']);
        exit();
    }
    if (!hash_equals(strtolower(trim($requested_email)), strtolower($g_email))) {
        unset(
            $_SESSION['google_signup_email'],
            $_SESSION['google_signup_sub'],
            $_SESSION['google_signup_expires'],
            $_SESSION['google_signup_name']
        );
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'email_mismatch' => true,
            'message' => 'The Google account does not match the email you entered. Change the email or choose the matching Google account.'
        ]);
        exit();
    }

    $chk = $conn->prepare("SELECT id, name, email, role FROM students WHERE email = ? LIMIT 1");
    if (!$chk) {
        error_log('Google sign-in account lookup could not be prepared: ' . $conn->error);
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Could not check the student account. Please try again later.']);
        exit();
    }
    $chk->bind_param("s", $g_email);
    if (!$chk->execute()) {
        error_log('Google sign-in account lookup failed: ' . $chk->error);
        $chk->close();
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Could not check the student account. Please try again later.']);
        exit();
    }
    $chk->store_result();
    if ($chk->num_rows === 0) {
        $chk->close();
        if (!session_regenerate_id(true)) {
            error_log('Google signup verification succeeded but the session ID could not be regenerated.');
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Secure registration could not be started. Please try again.']);
            exit();
        }
        $_SESSION['google_signup_email'] = strtolower($g_email);
        $_SESSION['google_signup_sub'] = $google_identity['sub'];
        $_SESSION['google_signup_expires'] = (int)$google_identity['exp'];
        $_SESSION['google_signup_name'] = trim((string)($google_identity['name'] ?? ''));
        echo json_encode([
            'success' => false,
            'needs_registration' => true,
            'email' => $g_email,
            'name' => $_SESSION['google_signup_name'],
            'message' => 'Google email verified. Complete the student registration form to create your account.'
        ]);
        exit();
    }

    $chk->bind_result($db_id, $db_name, $db_email, $db_role);
    $chk->fetch();
    $chk->close();

    if (!session_regenerate_id(true)) {
        error_log('Google sign-in succeeded but the session ID could not be regenerated.');
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Secure sign-in could not be completed. Please try again.']);
        exit();
    }
    $_SESSION['google_login_csrf'] = bin2hex(random_bytes(32));
    $_SESSION['student_id'] = $db_id;
    $_SESSION['student_name'] = $db_name;
    $_SESSION['student_email'] = $db_email;
    $_SESSION['student_role'] = is_admin($db_email) ? 'admin' : ($db_role ?: 'student');

    echo json_encode(['success' => true]);
    exit();
}

// Check logged in user
$is_logged_in = isset($_SESSION['student_name']) && isset($_SESSION['student_email']);
$current_name = $_SESSION['student_name'] ?? '';
$current_email = $_SESSION['student_email'] ?? '';
$current_pic = $_SESSION['student_picture'] ?? '';
$current_student_gender = '';
$current_student_university = '';
$current_student_department = '';
$current_student_phone = '';
$current_student_status = 'Active';
$current_registration_date = date('Y-m-d');
$is_admin_user = $is_logged_in && is_admin($current_email);

// Ensure fresh profile data (name, picture, role) from DB
if ($is_logged_in) {
    $u_chk = $conn->prepare("SELECT name, picture, role, gender, university, department, phone, enrollment_status, registration_date, created_at FROM students WHERE email = ? LIMIT 1");
    if ($u_chk) {
        $u_chk->bind_param("s", $current_email);
        $u_chk->execute();
        $u_chk->bind_result($db_u_name, $db_u_pic, $db_u_role, $db_u_gender, $db_u_university, $db_u_department, $db_u_phone, $db_u_status, $db_u_registration_date, $db_u_created_at);
        if ($u_chk->fetch()) {
            if (!empty($db_u_name)) {
                $current_name = $db_u_name;
                $_SESSION['student_name'] = $current_name;
            }
            if (!empty($db_u_pic)) {
                $current_pic = $db_u_pic;
                $_SESSION['student_picture'] = $current_pic;
            }
            $current_student_gender = $db_u_gender ?? '';
            $current_student_university = $db_u_university ?? '';
            $current_student_department = $db_u_department ?? '';
            $current_student_phone = $db_u_phone ?? '';
            $current_student_status = $db_u_status ?: 'Active';
            $current_registration_date = $db_u_registration_date ?: $db_u_created_at;
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

    $create_student_records_sql = "CREATE TABLE IF NOT EXISTS student_records (
        id INT AUTO_INCREMENT PRIMARY KEY,
        student_id VARCHAR(64) NOT NULL UNIQUE,
        full_name VARCHAR(255) NOT NULL,
        gender VARCHAR(30) DEFAULT '',
        date_of_birth DATE DEFAULT NULL,
        phone VARCHAR(50) DEFAULT '',
        email VARCHAR(255) DEFAULT NULL,
        university VARCHAR(255) DEFAULT '',
        faculty VARCHAR(255) DEFAULT '',
        department VARCHAR(255) DEFAULT '',
        year_of_study VARCHAR(50) DEFAULT '',
        semester VARCHAR(50) DEFAULT '',
        academic_year VARCHAR(50) DEFAULT '',
        student_photo VARCHAR(255) DEFAULT '',
        registration_date DATE NOT NULL,
        admin_email VARCHAR(255) NOT NULL,
        status ENUM('Active', 'Inactive', 'Graduated') NOT NULL DEFAULT 'Active',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )";
    if (!$conn->query($create_student_records_sql)) {
        die("Could not prepare student records storage: " . htmlspecialchars($conn->error));
    }
    if (empty($_SESSION['student_import_csrf'])) {
        $_SESSION['student_import_csrf'] = bin2hex(random_bytes(32));
    }
}

$curr_hour = (int)date('H');
$time_greeting = ($curr_hour < 12) ? 'GOOD MORNING' : (($curr_hour < 17) ? 'GOOD AFTERNOON' : 'GOOD EVENING');

// ==========================================
// HANDLE FORM SUBMISSIONS
// ==========================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'import_students_csv' && $is_admin_user) {
        $csrf_token = $_POST['csrf_token'] ?? '';
        $upload = $_FILES['student_file'] ?? null;
        $max_file_size = 5 * 1024 * 1024;

        if (!is_string($csrf_token) || !hash_equals($_SESSION['student_import_csrf'], $csrf_token)) {
            $alert_message = "Your upload session expired. Refresh the page and try again.";
            $alert_type = "error";
        } elseif (!is_array($upload) || !isset($upload['error']) || $upload['error'] !== UPLOAD_ERR_OK) {
            $alert_message = "Choose a CSV file to upload. The upload may also have exceeded the server's file size limit.";
            $alert_type = "error";
        } elseif (!isset($upload['size']) || !is_numeric($upload['size']) || !is_string($upload['name'] ?? null) || !is_string($upload['tmp_name'] ?? null)) {
            $alert_message = "The uploaded file information is invalid.";
            $alert_type = "error";
        } elseif ($upload['size'] > $max_file_size) {
            $alert_message = "The CSV file must be 5 MB or smaller.";
            $alert_type = "error";
        } elseif (strtolower(pathinfo($upload['name'], PATHINFO_EXTENSION)) !== 'csv' || !is_uploaded_file($upload['tmp_name'])) {
            $alert_message = "Upload a valid CSV file.";
            $alert_type = "error";
        } else {
            $csv = fopen($upload['tmp_name'], 'r');
            if ($csv === false) {
                $alert_message = "The uploaded CSV file could not be read.";
                $alert_type = "error";
            } else {
                $headers = fgetcsv($csv);
                if ($headers === false) {
                    $alert_message = "The CSV file is empty.";
                    $alert_type = "error";
                } else {
                    $header_map = [];
                    foreach ($headers as $index => $header) {
                        $header = preg_replace('/^\xEF\xBB\xBF/', '', trim((string)$header));
                        $header_map[strtolower(preg_replace('/[^a-z0-9]/i', '', $header))] = $index;
                    }

                    if (!isset($header_map['studentid'], $header_map['fullname'])) {
                        $alert_message = "The CSV must include Student ID and Full Name columns.";
                        $alert_type = "error";
                    } else {
                        $columns = [
                            'studentid' => 'student_id',
                            'fullname' => 'full_name',
                            'gender' => 'gender',
                            'dateofbirth' => 'date_of_birth',
                            'phonenumber' => 'phone',
                            'phone' => 'phone',
                            'emailaddress' => 'email',
                            'email' => 'email',
                            'universitycollege' => 'university',
                            'university' => 'university',
                            'facultycollege' => 'faculty',
                            'faculty' => 'faculty',
                            'department' => 'department',
                            'yearofstudy' => 'year_of_study',
                            'semester' => 'semester',
                            'academicyear' => 'academic_year',
                            'studentphoto' => 'student_photo',
                            'registrationdate' => 'registration_date',
                            'status' => 'status'
                        ];
                        $rows = [];
                        $seen_ids = [];
                        $line_number = 1;
                        $import_error = '';

                        while (($csv_row = fgetcsv($csv)) !== false) {
                            $line_number++;
                            if ($csv_row === [null] || (count($csv_row) === 1 && trim((string)$csv_row[0]) === '')) {
                                continue;
                            }
                            $record = [
                                'student_id' => '',
                                'full_name' => '',
                                'gender' => '',
                                'date_of_birth' => null,
                                'phone' => '',
                                'email' => null,
                                'university' => '',
                                'faculty' => '',
                                'department' => '',
                                'year_of_study' => '',
                                'semester' => '',
                                'academic_year' => '',
                                'student_photo' => '',
                                'registration_date' => date('Y-m-d'),
                                'status' => 'Active'
                            ];

                            foreach ($columns as $header_key => $field_name) {
                                if (!isset($header_map[$header_key])) {
                                    continue;
                                }
                                $value = trim((string)($csv_row[$header_map[$header_key]] ?? ''));
                                if ($field_name === 'date_of_birth' || $field_name === 'registration_date') {
                                    if ($value === '' && $field_name === 'date_of_birth') {
                                        $record[$field_name] = null;
                                    } elseif ($value !== '') {
                                        $date = DateTime::createFromFormat('!Y-m-d', $value);
                                        $date_errors = DateTime::getLastErrors();
                                        if (!$date || ($date_errors && ($date_errors['warning_count'] > 0 || $date_errors['error_count'] > 0)) || $date->format('Y-m-d') !== $value) {
                                            $import_error = "Invalid date on CSV row {$line_number}; use YYYY-MM-DD.";
                                            break 2;
                                        }
                                        $record[$field_name] = $value;
                                    }
                                } elseif ($field_name === 'email') {
                                    $record[$field_name] = $value === '' ? null : $value;
                                } elseif ($field_name === 'status' && $value !== '') {
                                    $record[$field_name] = ucfirst(strtolower($value));
                                } else {
                                    $record[$field_name] = $value;
                                }
                            }

                            if ($record['student_id'] === '' || $record['full_name'] === '') {
                                $import_error = "Student ID and Full Name are required on CSV row {$line_number}.";
                                break;
                            }
                            if ($record['email'] !== null && !filter_var($record['email'], FILTER_VALIDATE_EMAIL)) {
                                $import_error = "Invalid email address on CSV row {$line_number}.";
                                break;
                            }
                            if (!in_array($record['status'], ['Active', 'Inactive', 'Graduated'], true)) {
                                $import_error = "Status on CSV row {$line_number} must be Active, Inactive, or Graduated.";
                                break;
                            }
                            if (isset($seen_ids[$record['student_id']])) {
                                $import_error = "Duplicate Student ID on CSV row {$line_number}.";
                                break;
                            }
                            $seen_ids[$record['student_id']] = true;
                            $rows[] = $record;
                        }
                        fclose($csv);

                        if ($import_error !== '') {
                            $alert_message = $import_error;
                            $alert_type = "error";
                        } elseif (empty($rows)) {
                            $alert_message = "The CSV contains no student records to import.";
                            $alert_type = "error";
                        } else {
                            $conn->begin_transaction();
                            $insert_stmt = $conn->prepare("INSERT INTO student_records
                                (student_id, full_name, gender, date_of_birth, phone, email, university, faculty, department, year_of_study, semester, academic_year, student_photo, registration_date, admin_email, status)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                            if (!$insert_stmt) {
                                $conn->rollback();
                                $alert_message = "Could not prepare the student import: " . $conn->error;
                                $alert_type = "error";
                            } else {
                                $insert_error = '';
                                foreach ($rows as $record) {
                                    $insert_stmt->bind_param(
                                        "ssssssssssssssss",
                                        $record['student_id'],
                                        $record['full_name'],
                                        $record['gender'],
                                        $record['date_of_birth'],
                                        $record['phone'],
                                        $record['email'],
                                        $record['university'],
                                        $record['faculty'],
                                        $record['department'],
                                        $record['year_of_study'],
                                        $record['semester'],
                                        $record['academic_year'],
                                        $record['student_photo'],
                                        $record['registration_date'],
                                        $current_email,
                                        $record['status']
                                    );
                                    if (!$insert_stmt->execute()) {
                                        $insert_error = $insert_stmt->errno === 1062
                                            ? "A Student ID in this file is already registered."
                                            : "Student import failed: " . $insert_stmt->error;
                                        break;
                                    }
                                }
                                $insert_stmt->close();
                                if ($insert_error !== '') {
                                    $conn->rollback();
                                    $alert_message = $insert_error . " No rows were imported.";
                                    $alert_type = "error";
                                } else {
                                    $conn->commit();
                                    $alert_message = count($rows) . " student record(s) imported successfully.";
                                    $alert_type = "success";
                                }
                            }
                        }
                    }
                }
                if (is_resource($csv)) {
                    fclose($csv);
                }
            }
        }
    }

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
            $alert_message = "Super Admin profile (name & picture) updated successfully!";
            $alert_type = "success";
        } else {
            $alert_message = "Name cannot be empty!";
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
                $alert_message = "University logo updated successfully!";
                $alert_type = "success";
            } else {
                $alert_message = "Failed to upload university logo!";
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
            $alert_message = "University logo reset to default (🎓)";
            $alert_type = "success";
        }
    }

    // 1. REGISTER ACTION
    if ($action === 'register') {
        $active_auth_tab = "register";
        $fullName   = trim($_POST['fullName'] ?? '');
        $gender     = trim($_POST['gender'] ?? '');
        $phone      = trim($_POST['phone'] ?? '');
        $university = trim($_POST['university'] ?? '');
        $department = trim($_POST['department'] ?? '');
        $email = trim($_POST['email'] ?? '');

        // Strict Ethiopian phone validation: +2519..., +2517..., 09..., 07..., 2519..., 2517...
        $clean_phone = preg_replace('/[\s\-\(\)]+/', '', $phone);
        $is_ethiopian_phone = preg_match('/^(?:\+251|251|0)(9\d{8}|7\d{8})$/', $clean_phone, $phone_matches);
        $allowed_genders = ['Female', 'Male', 'Other', 'Prefer not to say'];

        if (empty($fullName) || empty($gender) || empty($email) || empty($phone) || empty($university) || empty($department)) {
            $alert_message = "Please complete all required student and university fields.";
            $alert_type = "error";
        } elseif (mb_strlen($fullName) < 3) {
            $alert_message = "Full name must be at least 3 characters!";
            $alert_type = "error";
        } elseif (mb_strlen($fullName) > 255 || mb_strlen($email) > 255 || mb_strlen($phone) > 50 || mb_strlen($university) > 255 || mb_strlen($department) > 100) {
            $alert_message = "One or more fields exceed the allowed length. Please shorten the information and try again.";
            $alert_type = "error";
        } elseif (!in_array($gender, $allowed_genders, true)) {
            $alert_message = "Select a valid gender option.";
            $alert_type = "error";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $email)) {
            $alert_message = "Only genuine Google (@gmail.com) accounts are allowed!";
            $alert_type = "error";
        } elseif (!$is_ethiopian_phone) {
            $alert_message = "Please enter a valid Ethiopian phone number! (e.g. 0912345678, 0712345678, or +251912345678)";
            $alert_type = "error";
        } else {
            // Standardize phone to 09... or 07...
            $standard_phone = '0' . $phone_matches[1];
            $stmt = $conn->prepare("SELECT id FROM students WHERE email = ? LIMIT 1");
            if (!$stmt) {
                $alert_message = "Could not validate your registration: " . $conn->error;
                $alert_type = "error";
            } else {
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows > 0) {
                    $alert_message = "This email is already registered!";
                    $alert_type = "error";
                    $stmt->close();
                } else {
                    $stmt->close();
                    $dummy_pass = password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT);
                    $role = is_admin($email) ? 'admin' : 'student';
                    $registration_date = date('Y-m-d');
                    $status = 'Active';
                    $ins = $conn->prepare("INSERT INTO students
                        (name, email, password, role, department, phone, gender, university, registration_date, enrollment_status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                    if (!$ins) {
                        $alert_message = "Could not prepare your registration: " . $conn->error;
                        $alert_type = "error";
                    } else {
                        $ins->bind_param(
                            "ssssssssss",
                            $fullName,
                            $email,
                            $dummy_pass,
                            $role,
                            $department,
                            $standard_phone,
                            $gender,
                            $university,
                            $registration_date,
                            $status
                        );
                        if ($ins->execute()) {
                            @notify_admin_new_registration($fullName, $email, "University registration ($university | $department | Tel: $standard_phone)");
                            $_SESSION['student_name'] = $fullName;
                            $_SESSION['student_email'] = $email;
                            $_SESSION['student_role'] = $role;
                            $_SESSION['registration_success'] = true;
                            unset(
                                $_SESSION['google_signup_email'],
                                $_SESSION['google_signup_sub'],
                                $_SESSION['google_signup_expires'],
                                $_SESSION['google_signup_name']
                            );
                            $ins->close();
                            header("Location: index.php");
                            exit();
                        } else {
                            $alert_message = $ins->errno === 1062
                                ? "This email is already registered."
                                : "Registration error: " . $ins->error;
                            $alert_type = "error";
                        }
                        $ins->close();
                    }
                }
            }
        }
    }

    // 2. LOGIN ACTION
    elseif ($action === 'login') {
        $active_auth_tab = "login";
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($email) || empty($password)) {
            $alert_message = "Please enter your email and password!";
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
                        $alert_message = "Sorry! Sign In is restricted to Administrators only. Students should register on the homepage.";
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
                    $alert_message = "Incorrect password!";
                    $alert_type = "error";
                }
            } else {
                $alert_message = "No account found with this email!";
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
            $alert_message = "Please fill in all fields!";
            $alert_type = "error";
        } elseif (strlen($new_pwd) < 6) {
            $alert_message = "Password must be at least 6 characters!";
            $alert_type = "error";
        } elseif ($new_pwd !== $cnf_pwd) {
            $alert_message = "Passwords do not match!";
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
        $phone      = trim($_POST['phone'] ?? '');
        $password   = $_POST['password'] ?? '';
        $role       = trim($_POST['role'] ?? 'student');
        $gender     = trim($_POST['gender'] ?? '');
        $university = trim($_POST['university'] ?? '');
        $department = trim($_POST['department'] ?? 'General');
        $allowed_genders = ['Female', 'Male', 'Other', 'Prefer not to say'];
        $clean_phone = preg_replace('/[\s\-\(\)]+/', '', $phone);
        $is_ethiopian_phone = preg_match('/^(?:\+251|251|0)(9\d{8}|7\d{8})$/', $clean_phone, $phone_matches);
        if (!in_array($role, ['student', 'admin'], true)) {
            $role = 'student';
        }

        if (empty($name) || empty($email) || empty($phone) || empty($university) || empty($department) || empty($gender)) {
            $alert_message = "Please complete all required student fields.";
            $alert_type = "error";
        } elseif (mb_strlen($name) > 255 || mb_strlen($email) > 255 || mb_strlen($phone) > 50 || mb_strlen($university) > 255 || mb_strlen($department) > 100) {
            $alert_message = "One or more fields exceed the allowed length.";
            $alert_type = "error";
        } elseif (!in_array($gender, $allowed_genders, true)) {
            $alert_message = "Select a valid gender option.";
            $alert_type = "error";
        } elseif (!$is_ethiopian_phone) {
            $alert_message = "Enter a valid Ethiopian phone number (09..., 07..., or +251...).";
            $alert_type = "error";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/i', $email)) {
            $alert_message = "Enter a valid Gmail address.";
            $alert_type = "error";
        } else {
            $chk = $conn->prepare("SELECT id FROM students WHERE email = ?");
            if (!$chk) {
                $alert_message = "Could not validate the new student: " . $conn->error;
                $alert_type = "error";
            } else {
                $chk->bind_param("s", $email);
                $chk->execute();
                $chk->store_result();
                if ($chk->num_rows > 0) {
                    $alert_message = "This email is already registered!";
                    $alert_type = "error";
                    $chk->close();
                } else {
                    $chk->close();
                    if (!empty($password) && strlen($password) < 6) {
                        $alert_message = "Password must be at least 6 characters long.";
                        $alert_type = "error";
                    } else {
                        $phone = '0' . $phone_matches[1];
                        $h = !empty($password) ? password_hash($password, PASSWORD_DEFAULT) : password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT);
                        $registration_date = date('Y-m-d');
                        $status = 'Active';
                        $ins = $conn->prepare("INSERT INTO students
                            (name, email, password, role, department, phone, gender, university, registration_date, enrollment_status, registered_by_email)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                        if (!$ins) {
                            $alert_message = "Could not prepare the new student record: " . $conn->error;
                            $alert_type = "error";
                        } else {
                            $ins->bind_param("sssssssssss", $name, $email, $h, $role, $department, $phone, $gender, $university, $registration_date, $status, $current_email);
                            if ($ins->execute()) {
                                $alert_message = "New student ('" . htmlspecialchars($name) . "') was added successfully!";
                                $alert_type = "success";
                                @notify_admin_new_registration($name, $email, "Admin Panel Add ($university | $department | Tel: $phone)");
                            } else {
                                $alert_message = "Could not add student: " . $ins->error;
                                $alert_type = "error";
                            }
                            $ins->close();
                        }
                    }
                }
            }
        }
    }

    // 5. ADMIN CRUD: EDIT STUDENT
    elseif ($action === 'admin_edit' && $is_admin_user) {
        $student_id = (int)($_POST['student_id'] ?? 0);
        $name       = trim($_POST['name'] ?? '');
        $email      = trim($_POST['email'] ?? '');
        $phone      = trim($_POST['phone'] ?? '');
        $new_pwd    = $_POST['new_password'] ?? '';
        $role       = trim($_POST['role'] ?? 'student');
        $department = trim($_POST['department'] ?? 'General');
        if (empty($department)) $department = 'General';

        if ($student_id > 0 && !empty($name) && !empty($email)) {
            if (!empty($new_pwd)) {
                $h = password_hash($new_pwd, PASSWORD_DEFAULT);
                $up = $conn->prepare("UPDATE students SET name = ?, email = ?, password = ?, role = ?, department = ?, phone = ? WHERE id = ?");
                $up->bind_param("ssssssi", $name, $email, $h, $role, $department, $phone, $student_id);
            } else {
                $up = $conn->prepare("UPDATE students SET name = ?, email = ?, role = ?, department = ?, phone = ? WHERE id = ?");
                $up->bind_param("sssssi", $name, $email, $role, $department, $phone, $student_id);
            }
            if ($up->execute()) {
                $alert_message = "Student record updated successfully!";
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
                $alert_message = "Student deleted successfully!";
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

    $res = $conn->query("SELECT id, name, email, phone, role, university, department, gender, enrollment_status, registration_date, created_at FROM students ORDER BY id ASC");
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
    /* Base typography & smooth rendering */
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      -webkit-font-smoothing: antialiased;
    }

    .card-bg {
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
      background-color: #064e3b;
      transition: background-image 0.4s ease-in-out, transform 0.35s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.35s ease;
    }
    .card-bg:hover {
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6), 0 0 30px rgba(16, 185, 129, 0.15);
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(-8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .animate-fade-in {
      animation: fadeIn 0.25s ease-out forwards;
    }

    /* ══════════════════════════════════════════════════════════════
       GLOBAL HOVER EFFECTS & MICRO-INTERACTIONS
       ══════════════════════════════════════════════════════════════ */

    /* Smooth transitions for all interactive elements */
    button, a, input, select, textarea, .admin-nav-item, .student-row, .stat-card, .site-logo-icon, .site-logo-badge {
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }

    /* Interactive Buttons Hover Elevation & Glow */
    button:not(:disabled):hover, a[class*="bg-"]:hover {
      transform: translateY(-2px);
    }
    button:not(:disabled):active, a[class*="bg-"]:active {
      transform: translateY(0) scale(0.97);
    }

    /* Green / Emerald Theme Button Hover Glow */
    button[type="submit"]:hover, .hover-glow-green:hover {
      box-shadow: 0 10px 25px -5px rgba(16, 185, 129, 0.35), 0 0 15px rgba(16, 185, 129, 0.2);
    }

    /* Red / Crimson Theme Button Hover Glow */
    button[class*="bg-red"]:hover, .hover-glow-red:hover {
      box-shadow: 0 10px 25px -5px rgba(239, 68, 68, 0.4), 0 0 18px rgba(239, 68, 68, 0.25);
    }

    /* Blue Theme Button Hover Glow */
    button[class*="bg-blue"]:hover {
      box-shadow: 0 8px 20px -4px rgba(59, 130, 246, 0.35);
    }

    /* Arrow icon translation on button hover */
    button:hover .hover-arrow, a:hover .hover-arrow, .group:hover .group-hover-arrow {
      transform: translateX(4px);
      transition: transform 0.2s ease-out;
    }

    /* Stat Cards Hover Lift & Border Shimmer */
    .stat-card {
      transition: transform 0.3s cubic-bezier(0.34, 1.56, 0.64, 1), box-shadow 0.3s ease, border-color 0.3s ease;
    }
    .stat-card:hover {
      transform: translateY(-5px);
      border-color: rgba(239, 68, 68, 0.45);
      box-shadow: 0 20px 35px -10px rgba(0, 0, 0, 0.5), 0 0 25px rgba(239, 68, 68, 0.15);
    }
    .stat-card:hover .stat-icon {
      transform: scale(1.15) rotate(6deg);
    }
    .stat-icon {
      transition: transform 0.3s cubic-bezier(0.34, 1.56, 0.64, 1), background-color 0.3s ease;
    }

    /* Sidebar Navigation Links Hover Slide */
    .admin-nav-item {
      position: relative;
      transition: transform 0.22s cubic-bezier(0.4, 0, 0.2, 1), background-color 0.2s ease, color 0.2s ease;
    }
    .admin-nav-item:hover {
      transform: translateX(5px);
    }
    .admin-nav-item span:first-child {
      display: inline-block;
      transition: transform 0.22s ease;
    }
    .admin-nav-item:hover span:first-child {
      transform: scale(1.22);
    }

    /* Directory Table Row Hover Highlight */
    .student-row {
      transition: background-color 0.2s ease, transform 0.2s ease;
    }
    .student-row:hover {
      background-color: rgba(255, 255, 255, 0.07) !important;
    }
    .student-row:hover td:first-child {
      color: #f87171;
    }
    .student-row .rounded-full {
      transition: transform 0.25s ease;
    }
    .student-row:hover .rounded-full {
      transform: scale(1.15);
    }

    /* University Logo & Badge Hover Bounce */
    .site-logo-icon, .site-logo-badge, #dashLogoPreview {
      transition: transform 0.3s cubic-bezier(0.34, 1.56, 0.64, 1), box-shadow 0.3s ease;
    }
    .site-logo-icon:hover, .site-logo-badge:hover, #dashLogoPreview:hover {
      transform: scale(1.08) rotate(2deg);
      box-shadow: 0 0 25px rgba(16, 185, 129, 0.45);
    }

    /* Close & Dismiss Buttons Hover Rotate */
    button[onclick*="close"]:hover, button[onclick*="parentElement.remove"]:hover {
      transform: rotate(90deg) scale(1.2);
      transition: transform 0.2s ease;
    }

    /* Form Fields Hover Border Accent */
    input:hover:not(:disabled), select:hover:not(:disabled), textarea:hover:not(:disabled) {
      border-color: rgba(255, 255, 255, 0.3);
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

    <?php if($registration_success): ?>
      <div role="status" aria-live="polite" class="mb-6 p-5 rounded-2xl bg-emerald-500/15 border border-emerald-400/40 text-emerald-100 text-center max-w-xl mx-auto shadow-lg shadow-emerald-950/20 animate-fade-in">
        <div class="text-3xl mb-2" aria-hidden="true">🎉</div>
        <h2 class="text-lg font-bold mb-1">Galmeen keessan milkaa’inaan xumurame!</h2>
        <p class="text-sm text-emerald-100/90">Baga gara Alnasrii University dhuftan. Odeeffannoon galmee keessanii milkaa’inaan kuufameera.</p>
      </div>
    <?php endif; ?>

    <!-- ============================================================== -->
    <!-- VIEW 1: UNAUTHENTICATED (ALL-IN-ONE CARD: REGISTER / LOGIN)   -->
    <!-- ============================================================== -->
    <?php if(!$is_logged_in): ?>
      <div class="max-w-2xl mx-auto my-4">

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
              <p id="googleSignupNotice" class="<?php echo !empty($_SESSION['google_signup_email']) && (int)($_SESSION['google_signup_expires'] ?? 0) > time() ? 'mt-3 rounded-lg border border-emerald-300/30 bg-emerald-950/40 px-3 py-2 text-xs text-emerald-100' : 'hidden mt-3 rounded-lg border border-emerald-300/30 bg-emerald-950/40 px-3 py-2 text-xs text-emerald-100'; ?>"><?php
                if (!empty($_SESSION['google_signup_email']) && (int)($_SESSION['google_signup_expires'] ?? 0) > time()) {
                    echo 'Google account verified. Complete the student registration form below.';
                }
              ?></p>
            </div>

            <!-- ================= CREATE ACCOUNT FORM ================= -->
            <form id="authRegisterForm" method="POST" action="index.php" class="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <input type="hidden" name="action" value="register">

              <!-- Enter the email before verifying it with Google -->
              <div class="sm:col-span-2">
                <div class="flex items-center justify-between mb-1.5">
                  <label for="regEmail" class="text-white text-xs font-semibold uppercase tracking-wider">Email Address</label>
                  <span class="text-[11px] text-green-200/90 font-mono">Google verification is not required</span>
                </div>
                <input id="regEmail" name="email" type="email" value="<?php echo htmlspecialchars(trim($_POST['email'] ?? (!empty($_SESSION['google_signup_email']) && (int)($_SESSION['google_signup_expires'] ?? 0) > time() ? $_SESSION['google_signup_email'] : ''))); ?>" placeholder="student@gmail.com" required pattern=".+@gmail\.com$" class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 shadow-sm" />
              </div>

              <!-- Full Name -->
              <div>
                <label class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Full Name</label>
                <input id="regFullName" name="fullName" type="text" value="<?php echo !empty($_SESSION['google_signup_email']) && (int)($_SESSION['google_signup_expires'] ?? 0) > time() ? htmlspecialchars($_SESSION['google_signup_name'] ?? '') : ''; ?>" placeholder="e.g. Guuta Ahmed" required class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 shadow-sm" />
              </div>

              <!-- Phone Number -->
              <div>
                <div class="flex items-center justify-between mb-1.5">
                  <label class="text-white text-xs font-semibold uppercase tracking-wider">Phone Number</label>
                  <span class="text-[11px] text-green-200/90 font-mono">(09... / 07... / +251...)</span>
                </div>
                <input id="regPhone" name="phone" type="tel" placeholder="0912345678 or +251912345678" pattern="^(\+251|251|0)(9\d{8}|7\d{8})$" title="Enter a valid Ethiopian phone number: 09..., 07..., or +251..." required class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 shadow-sm" />
              </div>

              <div>
                <label for="regGender" class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Gender</label>
                <select id="regGender" name="gender" required class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 shadow-sm">
                  <option value="">Select gender</option>
                  <option value="Female">Female</option>
                  <option value="Male">Male</option>
                  <option value="Other">Other</option>
                  <option value="Prefer not to say">Prefer not to say</option>
                </select>
              </div>

              <div>
                <label for="regUniversity" class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">University / College</label>
                <input id="regUniversity" name="university" type="text" maxlength="255" placeholder="University or college name" required class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 shadow-sm" />
              </div>

              <div>
                <label for="regDepartment" class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">Department</label>
                <input id="regDepartment" name="department" type="text" maxlength="100" placeholder="e.g. Computer Science" required class="w-full px-4 py-2.5 rounded-lg bg-white/95 text-gray-900 placeholder-gray-400 text-sm font-medium outline-none focus:ring-2 focus:ring-green-400 shadow-sm" />
              </div>

              <p class="sm:col-span-2 text-[11px] text-green-100/80">Registration date is recorded automatically when you submit. Your enrollment status starts as Active.</p>

              <button id="createAccountBtn" type="submit" class="w-full sm:col-span-2 mt-2 bg-white text-green-800 font-bold py-3 rounded-lg shadow-lg hover:bg-green-50 active:scale-[0.99] transition text-sm flex items-center justify-center gap-2">
                <span>Create Account</span>
                <span>&rarr;</span>
              </button>
            </form>

            <!-- Link to Separate Sign In Page -->
            <div class="mt-4 pt-3 text-center">
              <p class="text-white/90 text-xs">
                Already have an account?
                <a href="login.php" class="text-white font-bold underline underline-offset-2 hover:text-green-200 transition ml-1">
                  Sign In &rarr;
                </a>
              </p>
            </div>

            <!-- Social Auth Divider -->
            <div class="mt-6 pt-5 border-t border-white/20 space-y-4">
              <div class="flex items-center gap-3">
                <div class="flex-1 h-px bg-white/20"></div>
                <span class="text-white/70 text-[11px] uppercase tracking-wider font-semibold">Google sign-in (optional)</span>
                <div class="flex-1 h-px bg-white/20"></div>
              </div>

              <div class="flex justify-center">
                <div id="googleButtonContainer" class="min-h-10 w-full flex justify-center"></div>
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
        <h2 class="text-2xl font-bold text-white mb-2">Baga Nagaan Dhuftan!</h2>
        <p class="text-emerald-300 font-medium text-sm mb-4">
          Welcome, <?php echo htmlspecialchars($current_name); ?>!
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
          <div class="flex justify-between gap-4 py-1 border-b border-white/10">
            <span class="text-slate-400">Phone Number:</span>
            <span class="font-bold text-white"><?php echo htmlspecialchars($current_student_phone ?: 'Not provided'); ?></span>
          </div>
          <div class="flex justify-between gap-4 py-1 border-b border-white/10">
            <span class="text-slate-400">Gender:</span>
            <span class="font-bold text-white"><?php echo htmlspecialchars($current_student_gender ?: 'Not provided'); ?></span>
          </div>
          <div class="flex justify-between gap-4 py-1 border-b border-white/10">
            <span class="text-slate-400">University / College:</span>
            <span class="text-right font-bold text-white"><?php echo htmlspecialchars($current_student_university ?: 'Not provided'); ?></span>
          </div>
          <div class="flex justify-between gap-4 py-1 border-b border-white/10">
            <span class="text-slate-400">Department:</span>
            <span class="text-right font-bold text-white"><?php echo htmlspecialchars($current_student_department ?: 'Not provided'); ?></span>
          </div>
          <div class="flex justify-between gap-4 py-1 border-b border-white/10">
            <span class="text-slate-400">Registration Date:</span>
            <span class="font-bold text-white"><?php echo htmlspecialchars(date('M d, Y', strtotime($current_registration_date))); ?></span>
          </div>
          <div class="flex justify-between py-1">
            <span class="text-slate-400">Status:</span>
            <span class="text-emerald-400 font-bold"><?php echo htmlspecialchars($current_student_status); ?></span>
          </div>
        </div>

        <div class="p-4 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-200 text-xs text-left mb-6 leading-relaxed">
          ℹ️ Odeeffannoo barataa keessan armaan olitti ilaaluu dandeessu. Dashboard bulchiinsaa admin hayyama qabu qofatu fayyadama.
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

              <!-- 3. Upload Student Records -->
              <button type="button" id="navItem_student_upload" onclick="adminNav('student_upload')" class="admin-nav-item w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition text-left cursor-pointer active:scale-95">
                <span class="text-base">📤</span>
                <span>Upload Student CSV</span>
              </button>

              <!-- 4. Add Student -->
              <button type="button" id="navItem_add" onclick="adminNav('add_student')" class="admin-nav-item w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition text-left cursor-pointer active:scale-95">
                <span class="text-base">➕</span>
                <span>Add Student</span>
              </button>

              <!-- 5. Notifications -->
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

              <!-- 6. University Logo -->
              <button type="button" id="navItem_logo" onclick="adminNav('logo')" class="admin-nav-item w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition text-left cursor-pointer active:scale-95">
                <span class="text-base">🏷️</span>
                <span>University Logo</span>
              </button>

              <!-- 7. Background & Size -->
              <button type="button" id="navItem_bg" onclick="adminNav('background')" class="admin-nav-item w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition text-left cursor-pointer active:scale-95">
                <span class="text-base">🖼️</span>
                <span>Background & Size</span>
              </button>

              <!-- 8. Admin Profile -->
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
              <div onclick="adminNav('students')" class="stat-card group bg-slate-900/80 border border-white/10 rounded-2xl p-5 shadow-lg flex items-center justify-between cursor-pointer">
                <div>
                  <p class="text-[11px] uppercase text-slate-400 font-bold tracking-wider group-hover:text-red-300 transition">Total Students</p>
                  <p class="text-3xl font-extrabold text-white mt-1.5"><?php echo $total_students; ?></p>
                  <p class="text-[11px] text-red-400 font-medium mt-1">Enrolled & Active</p>
                </div>
                <div class="stat-icon w-12 h-12 rounded-2xl bg-red-500/15 border border-red-500/30 text-red-400 flex items-center justify-center text-2xl shrink-0 group-hover:bg-red-500/25">
                  👥
                </div>
              </div>

              <!-- Stat 2: System Access -->
              <div class="stat-card group bg-slate-900/80 border border-white/10 rounded-2xl p-5 shadow-lg flex items-center justify-between cursor-default">
                <div>
                  <p class="text-[11px] uppercase text-slate-400 font-bold tracking-wider group-hover:text-amber-300 transition">System Access</p>
                  <p class="text-xl font-extrabold text-amber-400 mt-1.5">Full CRUD Power</p>
                  <p class="text-[11px] text-amber-400/80 font-medium mt-1">Add, Update, Delete</p>
                </div>
                <div class="stat-icon w-12 h-12 rounded-2xl bg-amber-500/15 border border-amber-500/30 text-amber-400 flex items-center justify-center text-2xl shrink-0 group-hover:bg-amber-500/25">
                  ⚡
                </div>
              </div>

              <!-- Stat 3: Notifications -->
              <div onclick="adminNav('notifications')" class="stat-card group bg-slate-900/80 border border-white/10 rounded-2xl p-5 shadow-lg flex items-center justify-between cursor-pointer">
                <div>
                  <p class="text-[11px] uppercase text-slate-400 font-bold tracking-wider group-hover:text-emerald-300 transition">Notifications</p>
                  <p class="text-3xl font-extrabold text-emerald-400 mt-1.5"><?php echo count($notifications); ?></p>
                  <p class="text-[11px] text-emerald-400/80 font-medium mt-1">Recent Activity Logs</p>
                </div>
                <div class="stat-icon w-12 h-12 rounded-2xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 flex items-center justify-center text-2xl shrink-0 group-hover:bg-emerald-500/25">
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
                    <h2 class="text-lg font-bold text-white tracking-tight">Student Directory</h2>
                  </div>
                  <p class="text-xs text-slate-400 mt-1">Students are listed from earliest to latest registration. IDs follow the registration sequence.</p>
                </div>

                <div class="flex items-center gap-3">
                  <!-- Search Filter -->
                  <div class="relative w-full sm:w-64">
                    <input type="text" id="studentSearch" placeholder="Search name, email, phone, or department..." class="w-full px-3.5 py-2 pl-9 rounded-xl bg-slate-950/80 border border-white/10 text-white placeholder-slate-400 text-xs outline-none focus:ring-2 focus:ring-red-500" />
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
                      <th class="py-3 px-4">Registration ID</th>
                      <th class="py-3 px-4">Student Name</th>
                      <th class="py-3 px-4">University / College</th>
                      <th class="py-3 px-4">Department</th>
                      <th class="py-3 px-4">Gender</th>
                      <th class="py-3 px-4">Email</th>
                      <th class="py-3 px-4">Phone</th>
                      <th class="py-3 px-4">Role</th>
                      <th class="py-3 px-4">Status</th>
                      <th class="py-3 px-4">Joined Date</th>
                      <th class="py-3 px-4 text-center">Actions</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-white/5">
                    <?php if(empty($all_students)): ?>
                      <tr>
                        <td colspan="11" class="py-8 text-center text-slate-400">No students registered yet.</td>
                      </tr>
                    <?php else: ?>
                      <?php foreach($all_students as $st): ?>
                        <tr class="student-row hover:bg-white/5 transition" data-name="<?php echo htmlspecialchars(strtolower($st['name'])); ?>" data-email="<?php echo htmlspecialchars(strtolower($st['email'])); ?>" data-department="<?php echo htmlspecialchars(strtolower($st['department'] ?? '')); ?>" data-phone="<?php echo htmlspecialchars(strtolower($st['phone'] ?? '')); ?>">
                          <td class="py-3 px-4 font-mono text-slate-400">#<?php echo $st['id']; ?></td>
                          <td class="py-3 px-4 font-semibold text-white flex items-center gap-2.5">
                            <div class="w-7 h-7 rounded-full bg-red-500/20 text-red-300 font-bold flex items-center justify-center text-xs">
                              <?php echo mb_substr($st['name'], 0, 1); ?>
                            </div>
                            <span><?php echo htmlspecialchars($st['name']); ?></span>
                          </td>
                          <td class="py-3 px-4 text-slate-200"><?php echo htmlspecialchars($st['university'] ?: '-'); ?></td>
                          <td class="py-3 px-4">
                            <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg bg-white/5 border border-white/10 text-slate-200 font-medium text-[11px]">
                              <span>🎓</span>
                              <span><?php echo htmlspecialchars($st['department'] ?? 'General'); ?></span>
                            </span>
                          </td>
                          <td class="py-3 px-4 text-slate-300"><?php echo htmlspecialchars($st['gender'] ?: '-'); ?></td>
                          <td class="py-3 px-4 text-slate-300"><?php echo htmlspecialchars($st['email']); ?></td>
                          <td class="py-3 px-4 font-mono text-emerald-300 text-xs"><?php echo htmlspecialchars($st['phone'] ?? '-'); ?></td>
                          <td class="py-3 px-4">
                            <?php if($st['role'] === 'admin'): ?>
                              <span class="bg-red-500/20 text-red-300 border border-red-500/30 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase">Admin</span>
                            <?php else: ?>
                              <span class="bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded-full text-[10px] font-medium">Student</span>
                            <?php endif; ?>
                          </td>
                          <td class="py-3 px-4">
                            <span class="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-300"><?php echo htmlspecialchars($st['enrollment_status'] ?: 'Active'); ?></span>
                          </td>
                          <td class="py-3 px-4 text-slate-400"><?php echo date("M d, Y", strtotime($st['registration_date'] ?: $st['created_at'])); ?></td>
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

            <!-- STUDENT RECORD FILE UPLOAD -->
            <section id="studentUploadSection" class="bg-slate-900/80 border border-white/10 rounded-2xl p-6 shadow-xl scroll-mt-20">
              <div class="mb-5">
                <h2 class="text-base font-bold text-white tracking-tight flex items-center gap-2">
                  <span>📤</span> Upload Student Records
                </h2>
                <p class="mt-1 text-xs leading-relaxed text-slate-400">
                  Import a CSV file up to 5 MB. Student ID and Full Name are required; other columns are optional.
                  Dates must use YYYY-MM-DD. Imported records do not create student login accounts.
                </p>
              </div>

              <form method="POST" action="index.php#studentUploadSection" enctype="multipart/form-data" class="flex flex-col gap-4 sm:flex-row sm:items-end">
                <input type="hidden" name="action" value="import_students_csv">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['student_import_csrf']); ?>">
                <div class="min-w-0 flex-1">
                  <label for="studentCsv" class="mb-1 block text-xs font-semibold uppercase text-slate-300">CSV file</label>
                  <input id="studentCsv" type="file" name="student_file" accept=".csv,text/csv" required class="block w-full rounded-xl border border-white/10 bg-slate-950 px-3 py-2 text-xs text-slate-200 file:mr-3 file:rounded-lg file:border-0 file:bg-red-600 file:px-3 file:py-2 file:text-xs file:font-bold file:text-white">
                </div>
                <button type="submit" class="rounded-xl bg-red-600 px-5 py-2.5 text-xs font-bold text-white shadow-lg hover:bg-red-500">Import CSV</button>
              </form>
              <p class="mt-4 text-[11px] leading-relaxed text-slate-500">
                Headers: <code class="text-slate-300">student_id, full_name, gender, date_of_birth, phone_number, email_address, university_college, faculty_college, department, year_of_study, semester, academic_year, student_photo, registration_date, status</code>.
                Status can be Active, Inactive, or Graduated. Existing Student IDs are not overwritten; an invalid row cancels the entire import.
              </p>
            </section>

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
                  <p class="text-xs text-slate-400 py-3">No recent notifications.</p>
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
            <!-- UNIVERSITY LOGO PHOTO UPLOADER                             -->
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
                    <h3 class="font-bold text-white text-sm flex items-center gap-2">🏷️ University Logo (Site-wide)</h3>
                    <p class="text-xs text-slate-400 mt-1">Upload a custom university logo from your device. It appears on Sign In, Create Account, and Dashboard pages for all users.</p>
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
                  <p class="text-xs text-slate-400 mt-1">Upload a custom background picture from your computer and adjust its display size anytime.</p>
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

              <!-- Size Controls -->
              <div class="mt-4 pt-3 border-t border-white/10 flex flex-wrap items-center justify-between gap-3 text-xs">
                <span class="text-slate-300 font-semibold flex items-center gap-1.5">
                  <span>📐</span> Background Display Size:
                </span>
                <div class="inline-flex rounded-xl bg-black/40 p-1 border border-white/10 gap-1">
                  <button type="button" onclick="setBgSize('240px auto')" id="btnSizeSmall" class="px-3 py-1 rounded-lg text-xs font-semibold text-slate-300 hover:text-white transition">Small (240px)</button>
                  <button type="button" onclick="setBgSize('360px auto')" id="btnSizeMedium" class="px-3 py-1 rounded-lg text-xs font-semibold bg-red-600 text-white shadow">Medium (360px)</button>
                  <button type="button" onclick="setBgSize('520px auto')" id="btnSizeLarge" class="px-3 py-1 rounded-lg text-xs font-semibold text-slate-300 hover:text-white transition">Large (520px)</button>
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
        <div class="bg-slate-900 border border-white/20 rounded-2xl w-full max-w-md max-h-[90vh] overflow-y-auto p-6 shadow-2xl animate-fade-in">
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
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">University / College</label>
              <input type="text" name="university" maxlength="255" required placeholder="e.g. Alnasrii University" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Department</label>
              <input type="text" name="department" maxlength="100" required placeholder="e.g. Computer Science, Medicine..." class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Gender</label>
              <select name="gender" required class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
                <option value="">Select gender</option>
                <option value="Female">Female</option>
                <option value="Male">Male</option>
                <option value="Other">Other</option>
                <option value="Prefer not to say">Prefer not to say</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Phone Number</label>
              <input type="tel" name="phone" required pattern="^(\+251|251|0)(9\d{8}|7\d{8})$" title="Enter a valid Ethiopian phone number: 09..., 07..., or +251..." placeholder="e.g. 0912345678" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Password (Optional)</label>
              <input type="password" name="password" placeholder="Leave empty for auto-generated" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Role</label>
              <select name="role" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
                <option value="student">Student</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <p class="text-[11px] text-slate-400">Registration date is recorded automatically and status starts as Active.</p>
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
              <label class="block text-xs font-semibold uppercase text-slate-300 mb-1">Phone Number</label>
              <input type="tel" name="phone" id="editPhone" placeholder="e.g. 0912345678" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-800 border border-white/10 text-white text-xs outline-none focus:ring-2 focus:ring-red-500">
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
              <p class="text-[11px] text-slate-400 mt-2">Click the 📷 icon to select a new profile photo</p>
            </div>

            <!-- Admin Name -->
            <div>
              <label class="block text-white text-xs font-semibold uppercase tracking-wider mb-1.5">
                Super Admin Full Name
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
                Cancel
              </button>
              <button type="submit" class="bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-bold px-5 py-2 rounded-xl text-xs shadow-lg transition">
                💾 Save Profile
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
              const phone = (row.getAttribute('data-phone') || '').toLowerCase();
              row.style.display = (name.includes(query) || email.includes(query) || dept.includes(query) || phone.includes(query)) ? '' : 'none';
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
          const phoneEl = document.getElementById('editPhone');
          if (phoneEl) phoneEl.value = st.phone || '';
          document.getElementById('editModal').classList.remove('hidden');
        }
        function closeEditModal() { document.getElementById('editModal').classList.add('hidden'); }
        function confirmDelete(id, name) {
          if (confirm("Are you sure you want to permanently delete student '" + name + "'?")) {
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
          } else if (target === 'student_upload') {
            setActiveNavItem('navItem_student_upload');
            const sec = document.getElementById('studentUploadSection');
            highlightSection(sec);
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
            { id: 'studentUploadSection', navId: 'navItem_student_upload' },
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
    const googleLoginCsrf = <?php echo json_encode($_SESSION['google_login_csrf'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
    const googleClientId = <?php echo json_encode($google_client_id, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
    let googleSignInInitialized = false;

    function initializeGoogleSignIn() {
      const buttonContainer = document.getElementById('googleButtonContainer');
      if (!buttonContainer || googleSignInInitialized) return true;

      const notice = document.getElementById('googleSignupNotice');
      if (!googleClientId || googleClientId.indexOf('exampleclientid') !== -1) {
        if (notice) {
          notice.textContent = 'Optional Google sign-in is unavailable. You can still create your account using this form.';
          notice.classList.remove('hidden');
        }
        return true;
      }

      if (!window.google || !google.accounts || !google.accounts.id) return false;

      google.accounts.id.initialize({
        client_id: googleClientId,
        callback: handleGoogleResponse,
        context: 'signup',
        ux_mode: 'popup',
        auto_select: false
      });
      google.accounts.id.renderButton(buttonContainer, {
        type: 'standard',
        theme: 'outline',
        size: 'large',
        text: 'continue_with',
        shape: 'rectangular',
        logo_alignment: 'left',
        width: Math.min(buttonContainer.clientWidth || 300, 400)
      });
      googleSignInInitialized = true;
      return true;
    }

    function handleGoogleResponse(response) {
      if (!response.credential) return;
      const emailInput = document.getElementById('regEmail');
      const notice = document.getElementById('googleSignupNotice');
      const requestedEmail = emailInput ? emailInput.value.trim() : '';
      if (!requestedEmail) {
        if (notice) {
          notice.textContent = 'Enter your Gmail address in the form before continuing with Google.';
          notice.classList.remove('hidden');
        }
        if (emailInput) emailInput.focus();
        return;
      }
      fetch('index.php?action=google_auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: response.credential, email: requestedEmail, csrf_token: googleLoginCsrf })
      })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          window.location.href = 'index.php';
        } else if (data.email_mismatch) {
          if (notice) {
            notice.textContent = data.message;
            notice.classList.remove('hidden');
          }
          if (emailInput) emailInput.focus();
        } else if (data.needs_registration) {
          const nameInput = document.getElementById('regFullName');
          if (nameInput && !nameInput.value && data.name) nameInput.value = data.name;
          if (notice) {
            notice.textContent = data.message;
            notice.classList.remove('hidden');
          }
          const registerForm = document.getElementById('authRegisterForm');
          if (registerForm) registerForm.scrollIntoView({ behavior: 'smooth', block: 'center' });
        } else {
          alert('Google error: ' + (data.message || 'Unknown error'));
        }
      })
      .catch(err => {
        console.error(err);
        alert('Server connection error');
      });
    }

    if (document.getElementById('googleButtonContainer') && !initializeGoogleSignIn()) {
      let googleInitAttempts = 0;
      const googleInitTimer = window.setInterval(() => {
        googleInitAttempts += 1;
        if (initializeGoogleSignIn()) {
          window.clearInterval(googleInitTimer);
        } else if (googleInitAttempts >= 80) {
          window.clearInterval(googleInitTimer);
          const notice = document.getElementById('googleSignupNotice');
          if (notice) {
            notice.textContent = 'Optional Google sign-in could not load. You can still create your account using this form.';
            notice.classList.remove('hidden');
          }
        }
      }, 100);
    }
  </script>
</body>
</html>
