<?php
include 'config.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
    exit();
}

$input = json_decode(file_get_contents('php://input'), true);
$id_token = $input['credential'] ?? ($_POST['credential'] ?? '');

if (empty($id_token)) {
    echo json_encode(['success' => false, 'message' => 'No credential token provided']);
    exit();
}

// Function to decode JWT payload safely
function parse_jwt_payload($jwt) {
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
        return null;
    }
    $payload_b64 = strtr($parts[1], '-_', '+/');
    $decoded = base64_decode($payload_b64);
    return json_decode($decoded, true);
}

// Verify with Google tokeninfo endpoint if possible, else decode
$payload = null;
$verify_url = "https://oauth2.googleapis.com/tokeninfo?id_token=" . urlencode($id_token);

$ctx = stream_context_create([
    'http' => ['timeout' => 5]
]);

$response = @file_get_contents($verify_url, false, $ctx);
if ($response !== false) {
    $verified_data = json_decode($response, true);
    if (isset($verified_data['email'])) {
        $payload = $verified_data;
    }
}

// Fallback to local JWT parsing
if (!$payload) {
    $payload = parse_jwt_payload($id_token);
}

if (!$payload || empty($payload['email'])) {
    echo json_encode(['success' => false, 'message' => 'Failed to verify Google token']);
    exit();
}

$email = $payload['email'];
$name  = $payload['name'] ?? explode('@', $email)[0];
$picture = $payload['picture'] ?? '';
$google_id = $payload['sub'] ?? '';

// Check if student already exists
$stmt = $conn->prepare("SELECT id, name, email FROM students WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    // Existing user
    $stmt->bind_result($db_id, $db_name, $db_email);
    $stmt->fetch();
    $student_name = $db_name;
    $student_email = $db_email;
    $stmt->close();
} else {
    $stmt->close();
    // New user: register automatically with Google info
    $random_password = password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT);
    $insert_stmt = $conn->prepare("INSERT INTO students (name, email, password) VALUES (?, ?, ?)");
    $insert_stmt->bind_param("sss", $name, $email, $random_password);
    
    if ($insert_stmt->execute()) {
        $student_name = $name;
        $student_email = $email;
        require_once 'notify.php';
        notify_admin_new_registration($name, $email, "Google Sign-In");
    } else {
        echo json_encode(['success' => false, 'message' => 'Registration error: ' . $insert_stmt->error]);
        exit();
    }
    $insert_stmt->close();
}

// Set session
$_SESSION['student_name'] = $student_name;
$_SESSION['student_email'] = $student_email;
if (!empty($picture)) {
    $_SESSION['student_picture'] = $picture;
}

echo json_encode([
    'success' => true,
    'redirect' => 'dashboard.php'
]);
exit();
?>
