<?php
require_once 'configure.php';

$error = '';
$student_info = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $course   = trim($_POST['course_name'] ?? '');
    $class    = trim($_POST['class_level'] ?? '');
    $term     = trim($_POST['term'] ?? '');

    if (!$username || !$course || !$class || !$term) {
        $error = 'Please fill in all fields.';
    } else {

        // Step 1: Authenticate student from users table
        $stmt = $conn->prepare(
            "SELECT student_username, full_name, class_level, role, status
             FROM users
             WHERE student_username = ? AND role = 'student'
             LIMIT 1"
        );
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$user) {
            $error = 'Student username not found. Please check your username.';
        } elseif ($user['status'] === 'suspended') {
            $error = 'Your account has been suspended. Contact your teacher.';
        } elseif (strtolower($user['class_level']) !== strtolower($class)) {
            $error = 'Class level does not match your registered class (' . htmlspecialchars($user['class_level']) . ').';
        } else {
           // Step 2: Check exam exists and is active in cbt_exams table
$stmt2 = $conn->prepare(
    "SELECT id, teacher_username FROM cbt_exams
     WHERE course_name = ? AND class_level = ? AND term = ? AND is_active = 1
     LIMIT 1"
);
$stmt2->bind_param('sss', $course, $class, $term);
$stmt2->execute();
$exam = $stmt2->get_result()->fetch_assoc();
$stmt2->close();

if (!$exam) {
    $error = 'This exam is not available yet. Contact your teacher.';
} else {
    // Step 3: Check if already completed exam
    $check = $conn->prepare(
        "SELECT id, status FROM cbt_sessions
         WHERE student_username = ? AND course_name = ? AND class_level = ? AND term = ?
         LIMIT 1"
    );
    $check->bind_param('ssss', $username, $course, $class, $term);
    $check->execute();
    $existing = $check->get_result()->fetch_assoc();
    $check->close();

    if ($existing && $existing['status'] === 'completed') {
        $error = 'You have already completed this exam. Contact your teacher for assistance.';
    } else {
        $_SESSION['cbt_student']  = $user['student_username'];
        $_SESSION['cbt_fullname'] = $user['full_name'];
        $_SESSION['cbt_teacher']  = $exam['teacher_username'];
        $_SESSION['cbt_course']   = $course;
        $_SESSION['cbt_class']    = $class;
        $_SESSION['cbt_term']     = $term;
        header('Location: cbtexam1.php');
        exit;
    }
}
}
}
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CBT Login – Student Portal</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: linear-gradient(135deg, #1a5276, #2980b9);
    min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    padding: 20px;
  }
  .card {
    background: #fff;
    border-radius: 12px;
    padding: 40px 36px;
    width: 100%; max-width: 440px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
  }
  .logo { text-align: center; margin-bottom: 24px; }
  .logo h1 { color: #1a5276; font-size: 1.6rem; }
  .logo p  { color: #666; font-size: 0.9rem; margin-top: 4px; }
  label { display: block; font-size: 0.85rem; font-weight: 600;
          color: #333; margin-bottom: 6px; margin-top: 16px; }
  input, select {
    width: 100%; padding: 10px 14px;
    border: 1.5px solid #ccc; border-radius: 7px;
    font-size: 0.95rem; transition: border-color .2s;
  }
  input:focus, select:focus {
    outline: none; border-color: #2980b9;
    box-shadow: 0 0 0 3px rgba(41,128,185,.15);
  }
  .btn {
    width: 100%; margin-top: 24px; padding: 13px;
    background: #1a5276; color: #fff; border: none;
    border-radius: 8px; font-size: 1rem; font-weight: 700;
    cursor: pointer; letter-spacing: .5px; transition: background .2s;
  }
  .btn:hover { background: #154360; }
  .error {
    background: #fdecea; border: 1px solid #e74c3c;
    color: #c0392b; border-radius: 7px;
    padding: 10px 14px; margin-bottom: 16px; font-size: .9rem;
  }
  .notice {
    background: #eaf4fb; border-left: 4px solid #2980b9;
    color: #1a5276; border-radius: 0 7px 7px 0;
    padding: 10px 14px; margin-top: 20px; font-size: .85rem;
  }
  .student-preview {
    background: #eafaf1; border: 1px solid #2ecc71;
    border-radius: 7px; padding: 10px 14px;
    margin-top: 10px; font-size: .9rem; color: #1e8449;
    display: none;
  }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1>📝 GMSSP CBT Exam Portal</h1>
    <p>Computer Based Testing – Student Login</p>
  </div>

  <?php if ($error): ?>
    <div class="error">⚠️ <?= htmlspecialchars($error) ?></div>
  <?php endif; ?>

  <form method="POST" id="loginForm">
    <label for="username">Student Username</label>
    <input type="text" id="username" name="username"
           placeholder="Enter your username" required
           value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
           oninput="fetchStudentName(this.value)">

    <!-- Live full name preview -->
    <div class="student-preview" id="namePreview">👤 <span id="previewName"></span></div>

    <label for="class_level">Class Level</label>
    <select id="class_level" name="class_level" required>
      <option value="">-- Select Class --</option>
      <?php
      $classes = ['JSS 1','JSS 2','JSS 3','SS1','SS2','SS3'];
      foreach ($classes as $c):
        $sel = (($_POST['class_level'] ?? '') === $c) ? 'selected' : '';
      ?>
        <option value="<?= $c ?>" <?= $sel ?>><?= $c ?></option>
      <?php endforeach; ?>
    </select>

    <label for="course_name">Subject / Course</label>
    <input type="text" id="course_name" name="course_name"
           placeholder="e.g. English, Mathematics"
           value="<?= htmlspecialchars($_POST['course_name'] ?? '') ?>" required>

    <label for="term">Term</label>
    <select id="term" name="term" required>
      <option value="">-- Select Term --</option>
      <?php
      $terms = ['First Term','Second Term','Third Term'];
      foreach ($terms as $t):
        $sel = (($_POST['term'] ?? '') === $t) ? 'selected' : '';
      ?>
        <option value="<?= $t ?>" <?= $sel ?>><?= $t ?></option>
      <?php endforeach; ?>
    </select>

    <button type="submit" class="btn">Start Exam →</button>
  </form>

  <div class="notice">
    ℹ️ Make sure you are registered by your teacher before taking this exam.
  </div>
</div>

<script>
let debounceTimer;
function fetchStudentName(username) {
  clearTimeout(debounceTimer);
  const preview = document.getElementById('namePreview');
  const nameSpan = document.getElementById('previewName');
  if (username.length < 3) { preview.style.display = 'none'; return; }

  debounceTimer = setTimeout(() => {
    fetch('get_student_name.php?username=' + encodeURIComponent(username))
      .then(r => r.json())
      .then(data => {
        if (data.full_name) {
          nameSpan.textContent = data.full_name;
          preview.style.display = 'block';
        } else {
          preview.style.display = 'none';
        }
      }).catch(() => { preview.style.display = 'none'; });
  }, 400);
}
</script>
</body>
</html>