<?php
declare(strict_types=1);

/* ════════════════════════════════════════════════════════════════
   GMSSP CBT exam portal (student side)
   sign in (username + exam PIN) → instructions → exam → result

   Needs: cbt_bootstrap.php, cbt_api.php, camera_signal.php (unchanged),
          configure.php, and the tables from cbt_migration.sql.
   Settings live in cbt_bootstrap.php.
════════════════════════════════════════════════════════════════ */

require_once __DIR__ . '/cbt_bootstrap.php';
cbt_session_start();

$self  = basename($_SERVER['SCRIPT_NAME']);
$nonce = base64_encode(random_bytes(16));
cbt_send_headers($nonce);
$csrf  = csrf_token();

$ERRORS = [
    'exam_unavailable' => 'This exam is not open right now. Please see your teacher.',
    'already_done'     => 'You have already completed this exam. Please see your teacher if this is a mistake.',
    'no_questions'     => 'This exam has no questions yet. Please see your teacher.',
    'time_up'          => 'Your time for this exam ran out and it was submitted automatically.',
    'not_open'         => 'This exam has not opened yet. Please wait for your teacher.',
    'closed'           => 'This exam is closed. Please see your teacher.',
    'expired'          => 'Your session ended. Please sign in again.',
];

/* ── Page-only helpers ────────────────────────────────────────── */
function ic(string $n): string { return '<svg class="ic" aria-hidden="true"><use href="#i-' . $n . '"/></svg>'; }

function leave(string $self, string $error): void {
    foreach (CBT_SESSION_KEYS as $k) unset($_SESSION[$k]);
    header('Location: ' . $self . '?error=' . rawurlencode($error));
    exit;
}
function finish_with_result(string $self, array $res): void {
    foreach (CBT_SESSION_KEYS as $k) unset($_SESSION[$k]);
    $_SESSION['cbt_flash'] = $res;
    session_regenerate_id(true);
    header('Location: ' . $self);
    exit;
}

/* Where does this student stand for this exam? → [state, existing session id, error code] */
function attempt_gate(mysqli $c, array $exam, string $student): array {
    $last = db_one($c, "SELECT id, status FROM cbt_sessions WHERE exam_id = ? AND student_username = ? ORDER BY attempt_no DESC, id DESC LIMIT 1",
        'is', [(int)$exam['id'], $student]);
    if ($last && $last['status'] === 'in_progress') return ['resume', (int)$last['id'], ''];
    if (!empty($exam['not_open'])) return ['blocked', 0, 'not_open'];
    if (!empty($exam['closed']))   return ['blocked', 0, 'closed'];
    if ($last && in_array($last['status'], ['completed', 'timed_out'], true) && (int)$exam['allow_retake'] !== 1) return ['blocked', 0, 'already_done'];
    return ['new', 0, ''];
}

/* Creates the attempt: picks and saves the questions in one transaction.
   Two quick requests can never create two attempts (row lock + unique key). */
function create_attempt(mysqli $c, array $exam, string $student, ?string $fullname): array {
    $limit = (int)($exam['max_questions'] ?? 0) > 0 ? (int)$exam['max_questions'] : CBT_DEFAULT_MAX_QUESTIONS;
    $pool  = db_all($c, "SELECT id, marks FROM cbt_questions WHERE exam_id = ? AND status = 'Active'", 'i', [(int)$exam['id']]);
    if (!$pool) return ['id' => 0, 'error' => 'no_questions'];
    shuffle($pool);
    $pick  = array_slice($pool, 0, $limit);
    $count = count($pick);
    $marks = array_sum(array_map(fn($q) => (int)$q['marks'], $pick));
    $secs  = (int)$exam['duration_minutes'] > 0 ? (int)$exam['duration_minutes'] * 60 : $count * CBT_FALLBACK_SECS_PER_Q;

    $c->begin_transaction();
    try {
        $last = db_one($c, "SELECT id, status, attempt_no FROM cbt_sessions WHERE exam_id = ? AND student_username = ? ORDER BY attempt_no DESC, id DESC LIMIT 1 FOR UPDATE",
            'is', [(int)$exam['id'], $student]);
        if ($last && $last['status'] === 'in_progress') { $c->commit(); return ['id' => (int)$last['id'], 'error' => null, 'resumed' => true]; }
        if ($last && in_array($last['status'], ['completed', 'timed_out'], true) && (int)$exam['allow_retake'] !== 1) { $c->rollback(); return ['id' => 0, 'error' => 'already_done']; }
        $attempt_no = $last ? (int)$last['attempt_no'] + 1 : 1;

        $sid = db_insert($c, "INSERT INTO cbt_sessions (student_username, teacher_username, course_name, class_level, term, status, start_time, total_questions,
                                                       exam_id, attempt_no, student_full_name, deadline_at, total_marks, ip_address, last_seen_at)
                              VALUES (?, ?, ?, ?, ?, 'in_progress', NOW(), ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), ?, ?, NOW())",
            'sssssiiisiis', [$student, $exam['teacher_username'], $exam['course_name'], $exam['class_level'], $exam['term'],
                             $count, (int)$exam['id'], $attempt_no, $fullname, $secs, $marks, client_ip()]);

        $ph = []; $types = ''; $vals = [];
        foreach ($pick as $i => $q) { $ph[] = '(?, ?, ?)'; $types .= 'iii'; array_push($vals, $sid, $i + 1, (int)$q['id']); }
        db_run($c, "INSERT INTO cbt_session_questions (session_id, position, question_id) VALUES " . implode(',', $ph), $types, $vals);
        $c->commit();
    } catch (mysqli_sql_exception $t) {
        try { $c->rollback(); } catch (Throwable $ignore) {}
        if ((int)$t->getCode() === 1062) {   // another request created it first: use that one
            $row = db_one($c, "SELECT id FROM cbt_sessions WHERE exam_id = ? AND student_username = ? AND status = 'in_progress' ORDER BY id DESC LIMIT 1", 'is', [(int)$exam['id'], $student]);
            if ($row) return ['id' => (int)$row['id'], 'error' => null, 'resumed' => true];
        }
        throw $t;
    } catch (Throwable $t) {
        try { $c->rollback(); } catch (Throwable $ignore) {}
        throw $t;
    }
    return ['id' => $sid, 'error' => null, 'resumed' => false, 'count' => $count, 'secs' => $secs];
}

$EXAM_COLS = "id, course_name, class_level, term, teacher_username, duration_minutes, access_pin, camera_required, results_released,
              max_questions, allow_retake,
              (start_at IS NOT NULL AND start_at > NOW()) AS not_open, (end_at IS NOT NULL AND end_at < NOW()) AS closed";

$student  = $_SESSION['cbt_student']  ?? null;
$fullname = $_SESSION['cbt_fullname'] ?? null;
$exam_id  = (int)($_SESSION['cbt_exam_id'] ?? 0);
$sid      = (int)($_SESSION['cbt_session_id'] ?? 0);
$is_logged_in = (bool)($student && $exam_id);
$method   = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$login_error = '';
$intro_error = '';
$login_user  = '';

/* ══════════════ SIGN IN: username + the exam's general PIN ══════════════ */
if (!$is_logged_in && $method === 'POST' && isset($_POST['student_login'])) {
    $login_user = mb_substr(trim((string)($_POST['username'] ?? '')), 0, 64);
    $pin        = mb_substr(trim((string)($_POST['pin'] ?? '')), 0, 32);
    $ip         = client_ip();
    $generic    = 'The username or exam PIN is not correct. Check both and try again.';

    if (!csrf_ok($_POST['csrf'] ?? null)) {
        $login_error = 'This page expired. Please try again.';
    } elseif ($login_user === '' || $pin === '') {
        $login_error = 'Enter your username and the exam PIN.';
    } elseif (login_blocked($conn, $login_user, $ip)) {
        $login_error = 'Too many wrong attempts. Please wait a few minutes and try again.';
    } else {
        sweep_expired($conn);
        $user = db_one($conn, "SELECT student_username, full_name, class_level, status FROM users WHERE student_username = ? AND role = 'student' LIMIT 1", 's', [$login_user]);
        $exam = null;
        if ($user) {
            // Only exams of the student's own class are checked against the PIN
            foreach (db_all($conn, "SELECT $EXAM_COLS FROM cbt_exams WHERE LOWER(class_level) = LOWER(?) AND is_active = 1 ORDER BY id DESC", 's', [(string)$user['class_level']]) as $ex) {
                if ($ex['access_pin'] !== null && $ex['access_pin'] !== '' && hash_equals((string)$ex['access_pin'], $pin)) { $exam = $ex; break; }
            }
        }
        if (!$user || !$exam) {
            record_attempt($conn, $login_user, $ip, false);
            cbt_log($conn, null, $login_user, 'login_failed', 'Wrong username or exam PIN');
            $login_error = $generic;
        } elseif ($user['status'] === 'suspended') {
            record_attempt($conn, $login_user, $ip, false);
            cbt_log($conn, null, $login_user, 'login_failed', 'Suspended account');
            $login_error = 'Your account is suspended. Please see your teacher.';
        } else {
            [$state, $existing, $code] = attempt_gate($conn, $exam, (string)$user['student_username']);
            if ($state === 'blocked') {
                $login_error = $ERRORS[$code] ?? $generic;
            } else {
                session_regenerate_id(true);
                $_SESSION['cbt_student']  = $user['student_username'];
                $_SESSION['cbt_fullname'] = $user['full_name'];
                $_SESSION['cbt_teacher']  = $exam['teacher_username'];
                $_SESSION['cbt_course']   = $exam['course_name'];
                $_SESSION['cbt_class']    = $exam['class_level'];
                $_SESSION['cbt_term']     = $exam['term'];
                $_SESSION['cbt_exam_id']  = (int)$exam['id'];
                if ($state === 'resume') $_SESSION['cbt_session_id'] = $existing; else unset($_SESSION['cbt_session_id']);
                $_SESSION['csrf'] = bin2hex(random_bytes(32));
                record_attempt($conn, $login_user, $ip, true);
                cbt_log($conn, $state === 'resume' ? $existing : null, (string)$user['student_username'], 'login_success', 'Signed in to ' . $exam['course_name']);
                header('Location: ' . $self);
                exit;
            }
        }
    }
}

if (!$is_logged_in && $login_error === '' && isset($_GET['error'])) {
    $login_error = $ERRORS[(string)$_GET['error']] ?? '';
}

/* ══════════════ SIGNED IN ══════════════ */
$view = 'login';
$exam = null; $att = null; $questions = []; $answers = []; $flag_idx = [];
$question_count = 0; $left = 0; $resumed = false; $intro = [];

if ($is_logged_in) {
    $exam = db_one($conn, "SELECT $EXAM_COLS FROM cbt_exams WHERE id = ? AND is_active = 1 LIMIT 1", 'i', [$exam_id]);
    if (!$exam) leave($self, 'exam_unavailable');

    /* Sign out (instructions page only) */
    if ($method === 'POST' && isset($_POST['logout']) && csrf_ok($_POST['csrf'] ?? null)) {
        foreach (CBT_SESSION_KEYS as $k) unset($_SESSION[$k]);
        session_regenerate_id(true);
        header('Location: ' . $self);
        exit;
    }

    /* ── Start: create the attempt after the student accepts the instructions ── */
    if (!$sid && $method === 'POST' && isset($_POST['start_exam'])) {
        if (!csrf_ok($_POST['csrf'] ?? null)) {
            $intro_error = 'This page expired. Please reload it and try again.';
        } elseif (empty($_POST['accept'])) {
            $intro_error = 'Tick the box to confirm you have read the instructions.';
        } elseif ((int)$exam['camera_required'] === 1 && ($_POST['cam_ok'] ?? '') !== '1') {
            $intro_error = 'Your teacher requires your camera for this exam. Press “Test my camera” and allow access first.';
        } else {
            [$state, $existing, $code] = attempt_gate($conn, $exam, (string)$student);
            if ($state === 'blocked') leave($self, $code);
            if ($state === 'resume') {
                $_SESSION['cbt_session_id'] = $existing;
            } else {
                $r = create_attempt($conn, $exam, (string)$student, $fullname ? (string)$fullname : null);
                if ($r['error']) leave($self, (string)$r['error']);
                $_SESSION['cbt_session_id'] = $r['id'];
                if (empty($r['resumed'])) {
                    cbt_log($conn, $r['id'], (string)$student, 'exam_started', $exam['course_name'] . ': ' . $r['count'] . ' questions, ' . intdiv((int)$r['secs'], 60) . ' minutes');
                    if (($_POST['cam_ok'] ?? '') === '1') cbt_log($conn, $r['id'], (string)$student, 'camera_connected', 'Camera checked on the instructions page');
                }
            }
            header('Location: ' . $self);
            exit;
        }
    }

    if ($sid) {
        $att = load_attempt($conn, $sid, (string)$student);
        if (!$att)                           { unset($_SESSION['cbt_session_id']); leave($self, 'expired'); }
        if ($att['status'] !== 'in_progress') leave($self, $att['status'] === 'timed_out' ? 'time_up' : 'already_done');

        /* ── Submit (manual). The server decides whether it is late. ── */
        if ($method === 'POST' && isset($_POST['submit_exam'])) {
            if (!csrf_ok($_POST['csrf'] ?? null)) { cbt_log($conn, $sid, (string)$student, 'suspicious', 'Submit without a valid security token'); leave($self, 'expired'); }
            $res = finalize_session($conn, $sid, 'student');
            if (!$res) leave($self, 'already_done');
            finish_with_result($self, $res);
        }

        /* Deadline already passed (for example the student came back late): finish it now */
        if ($att['left_secs'] <= 0) {
            $res = finalize_session($conn, $sid, 'student');
            if ($res) finish_with_result($self, $res);
            leave($self, 'time_up');
        }

        $left = (int)$att['left_secs'];
        foreach (db_all($conn, "SELECT sq.position, q.id, q.question_text, q.option_a, q.option_b, q.option_c, q.option_d, q.marks, q.difficulty, q.question_image
                                FROM cbt_session_questions sq JOIN cbt_questions q ON q.id = sq.question_id
                                WHERE sq.session_id = ? ORDER BY sq.position", 'i', [$sid]) as $r) $questions[] = $r;
        $question_count = count($questions);
        if ($question_count === 0) leave($self, 'no_questions');

        $flagged = [];
        foreach (db_all($conn, "SELECT question_id, selected_option, is_flagged FROM cbt_answers WHERE session_id = ?", 'i', [$sid]) as $r) {
            if ($r['selected_option'] !== null && $r['selected_option'] !== '') $answers[(int)$r['question_id']] = strtoupper((string)$r['selected_option']);
            if ((int)$r['is_flagged'] === 1) $flagged[(int)$r['question_id']] = true;
        }
        foreach ($questions as $i => $q) if (isset($flagged[(int)$q['id']])) $flag_idx[] = $i;

        $resumed = $att['elapsed'] > 20;
        if ($resumed) cbt_log($conn, $sid, (string)$student, 'exam_resumed', 'Exam page reloaded or resumed with ' . count($answers) . ' saved answers');
        $view = 'exam';
    } else {
        $n = db_one($conn, "SELECT COUNT(*) AS n FROM cbt_questions WHERE exam_id = ? AND status = 'Active'", 'i', [$exam_id]);
        $limit = (int)($exam['max_questions'] ?? 0) > 0 ? (int)$exam['max_questions'] : CBT_DEFAULT_MAX_QUESTIONS;
        $qn = min((int)($n['n'] ?? 0), $limit);
        if ($qn === 0) leave($self, 'no_questions');
        $intro = ['questions' => $qn, 'minutes' => (int)$exam['duration_minutes'] > 0 ? (int)$exam['duration_minutes'] : (int)ceil($qn * CBT_FALLBACK_SECS_PER_Q / 60)];
        $view = 'intro';
    }
} elseif (!empty($_SESSION['cbt_flash']) && is_array($_SESSION['cbt_flash'])) {
    $result = $_SESSION['cbt_flash'];
    unset($_SESSION['cbt_flash']);
    $view = 'result';
}

session_write_close();   // the page and camera_signal.php can now run side by side without waiting on each other

function diff_badge(?string $d): string {
    return match ($d) {
        'Easy'  => '<span class="chip ok">Easy</span>',
        'Hard'  => '<span class="chip bad">Hard</span>',
        default => '<span class="chip warn">Medium</span>',
    };
}
function palette_grid(int $n): string {
    $o = '<div class="pal-grid" role="group" aria-label="Jump to a question">';
    for ($i = 0; $i < $n; $i++) $o .= '<button type="button" class="pal" data-goto="' . $i . '">' . ($i + 1) . '</button>';
    return $o . '</div>';
}
function palette_legend(): string {
    return '<ul class="legend"><li><i class="k-ans"></i>Answered</li><li><i class="k-cur"></i>Current</li><li><i class="k-flag"></i>Flagged</li><li><i class="k-none"></i>Not answered</li></ul>';
}
$course = $exam['course_name'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="theme-color" content="#2f54eb">
<meta name="robots" content="noindex, nofollow">
<link rel="icon" type="image/png" href="favicon.png">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<title><?= ($is_logged_in && $course) ? e($course) . ' · ' : '' ?>GMSSP CBT portal</title>
<style>
  /* Tokens ─ 4/8 px spacing grid, one typeface, no external requests (works on slow school networks) */
  :root {
    --bg:#f5f6f8; --surface:#fff; --ink:#111827; --ink-2:#4b5563; --ink-3:#6b7280;
    --line:#e5e7eb; --line-2:#d1d5db;
    --brand:#2f54eb; --brand-d:#2441c7; --brand-soft:#eef2ff; --focus:rgba(47,84,235,.28);
    --ok:#0f8a5f; --ok-soft:#e7f6ef; --warn:#b45309; --warn-soft:#fff4e0; --bad:#c62828; --bad-soft:#fdecec;
    --deep:#16224f;
    --r-s:8px; --r-m:12px; --r-l:20px;
    --shadow:0 1px 2px rgba(17,24,39,.05),0 8px 24px rgba(17,24,39,.06);
    --shadow-lg:0 16px 48px rgba(17,24,39,.22);
    --font:Inter,ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
  }
  *,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
  html { -webkit-text-size-adjust:100%; }
  body { font:16px/1.5 var(--font); background:var(--bg); color:var(--ink); min-height:100vh; -webkit-font-smoothing:antialiased; }
  button,input,select { font:inherit; color:inherit; }
  fieldset { border:0; min-width:0; }
  :focus-visible { outline:3px solid var(--focus); outline-offset:2px; border-radius:6px; }
  .ic { width:20px; height:20px; flex:none; fill:none; stroke:currentColor; stroke-width:2; stroke-linecap:round; stroke-linejoin:round; }
  .sr { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap; }
  [hidden] { display:none !important; }

  /* Buttons + chips */
  .btn { display:inline-flex; align-items:center; justify-content:center; gap:8px; min-height:44px; padding:0 20px; border:1.5px solid var(--line-2); background:var(--surface); border-radius:var(--r-s); font-weight:600; cursor:pointer; transition:background .12s,border-color .12s,box-shadow .12s; text-decoration:none; color:var(--ink); }
  .btn:hover { background:var(--bg); }
  .btn.primary { background:var(--brand); border-color:var(--brand); color:#fff; }
  .btn.primary:hover { background:var(--brand-d); border-color:var(--brand-d); }
  .btn.ok { background:var(--ok); border-color:var(--ok); color:#fff; } .btn.ok:hover { filter:brightness(.92); background:var(--ok); }
  .btn:disabled { opacity:.45; cursor:not-allowed; }
  .btn.block { width:100%; }
  .chip { display:inline-flex; align-items:center; gap:6px; padding:2px 10px; border-radius:99px; font-size:13px; font-weight:600; background:var(--brand-soft); color:var(--brand); }
  .chip.ok { background:var(--ok-soft); color:var(--ok); } .chip.warn { background:var(--warn-soft); color:var(--warn); } .chip.bad { background:var(--bad-soft); color:var(--bad); }

  /* ═════════ LOGIN ═════════ */
  .login { min-height:100vh; display:grid; grid-template-columns:minmax(0,5fr) minmax(0,6fr); }
  .login-aside { background:var(--deep); color:#fff; padding:32px; display:flex; flex-direction:column; justify-content:flex-start; gap:20px; }
  .login-aside .brand { flex:1; min-height:280px; width:100%; display:grid; place-items:center; }
  .login-aside .brand img { display:block; width:100%; height:100%; max-height:calc(100vh - 160px); object-fit:contain; filter:drop-shadow(0 0 1.5px #fff) drop-shadow(0 0 1.5px #fff); }
  .login-aside h1 { font-size:clamp(26px,2.8vw,38px); font-weight:800; line-height:1.15; letter-spacing:-.02em; text-align:center; }
  .login-main { display:grid; place-items:center; padding:48px 32px; background:var(--surface); }
  .login-card { width:100%; max-width:420px; }
  .login-card h2 { font-size:28px; letter-spacing:-.02em; line-height:1.2; }
  .login-card > p { color:var(--ink-2); margin:6px 0 28px; }
  .field { margin-bottom:20px; }
  .field label { display:block; font-size:14px; font-weight:600; margin-bottom:8px; }
  .field input,.field select { width:100%; height:48px; padding:0 16px; border:1.5px solid var(--line-2); border-radius:var(--r-s); background:var(--surface); transition:border-color .12s,box-shadow .12s; }
  .field input:focus,.field select:focus { outline:none; border-color:var(--brand); box-shadow:0 0 0 4px var(--focus); }
  .field small { display:block; margin-top:6px; font-size:13px; color:var(--ink-3); }
  .row2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  .alert { display:flex; gap:12px; padding:14px 16px; border-radius:var(--r-s); margin-bottom:20px; background:var(--bad-soft); color:var(--bad); font-size:15px; }
  .alert .ic { margin-top:2px; }

  /* ═════════ INSTRUCTIONS ═════════ */
  .intro { min-height:100vh; display:grid; place-items:center; padding:24px; }
  .intro-card { width:100%; max-width:680px; background:var(--surface); border:1px solid var(--line); border-radius:var(--r-l); box-shadow:var(--shadow); padding:36px; }
  .intro-card h1 { font-size:26px; letter-spacing:-.02em; line-height:1.2; }
  .intro-card .lead { color:var(--ink-2); margin:6px 0 24px; }
  .info { display:grid; grid-template-columns:repeat(2,1fr); gap:12px; margin-bottom:24px; }
  .info div { background:var(--bg); border-radius:var(--r-m); padding:12px 16px; min-width:0; }
  .info span { display:block; font-size:13px; color:var(--ink-3); } .info b { font-size:16px; overflow-wrap:anywhere; }
  .intro-card h2 { font-size:16px; margin-bottom:12px; }
  .rules { list-style:none; display:grid; gap:12px; margin-bottom:24px; }
  .rules li { display:flex; gap:12px; color:var(--ink-2); font-size:15px; }
  .rules .ic { margin-top:2px; color:var(--brand); }
  .camtest { display:flex; align-items:center; gap:16px; padding:14px 16px; border:1.5px solid var(--line-2); border-radius:var(--r-m); margin-bottom:16px; }
  .camtest video { width:96px; height:72px; border-radius:var(--r-s); background:#111; object-fit:cover; transform:scaleX(-1); flex:none; }
  .camtest div { flex:1; min-width:0; font-size:14px; color:var(--ink-2); }
  .camtest b { display:block; color:var(--ink); }
  .camtest.good { border-color:var(--ok); background:var(--ok-soft); } .camtest.bad { border-color:var(--bad); background:var(--bad-soft); }
  .accept { display:flex; gap:12px; align-items:flex-start; padding:14px 16px; border:1.5px solid var(--line-2); border-radius:var(--r-m); margin-bottom:16px; cursor:pointer; font-size:15px; }
  .accept input { width:20px; height:20px; margin-top:2px; accent-color:var(--brand); flex:none; }
  .intro-actions { display:grid; gap:12px; }
  .linkbtn { background:none; border:0; color:var(--ink-3); font-size:14px; text-decoration:underline; cursor:pointer; padding:8px; justify-self:center; }

  /* ═════════ EXAM ═════════ */
  .topbar { position:sticky; top:0; z-index:40; height:64px; padding:0 24px; background:var(--surface); border-bottom:1px solid var(--line); display:grid; grid-template-columns:1fr auto 1fr; align-items:center; gap:16px; }
  .who { display:flex; align-items:center; gap:12px; min-width:0; }
  .avatar { width:36px; height:36px; border-radius:50%; background:var(--brand-soft); color:var(--brand); display:grid; place-items:center; font-weight:700; flex:none; }
  .who div { min-width:0; line-height:1.3; }
  .who strong,.who span { display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .who span { font-size:13px; color:var(--ink-3); }
  .clock { text-align:center; line-height:1.2; }
  .clock small { display:block; font-size:12px; color:var(--ink-3); }
  .clock b { font-size:22px; font-variant-numeric:tabular-nums; letter-spacing:.01em; }
  .clock[data-state=warn] b { color:var(--warn); } .clock[data-state=crit] b { color:var(--bad); }
  .tools { display:flex; justify-content:flex-end; align-items:center; gap:8px; }
  .icon-btn { width:44px; height:44px; padding:0; border-radius:50%; border:1.5px solid var(--line-2); background:var(--surface); display:grid; place-items:center; cursor:pointer; color:var(--ink-2); }
  .icon-btn:hover { background:var(--bg); } .icon-btn[aria-pressed=false] { color:var(--ink-3); background:var(--bg); }
  .cam { display:flex; align-items:center; gap:8px; padding:4px 12px 4px 4px; border:1.5px solid var(--line-2); border-radius:99px; font-size:13px; font-weight:600; }
  .cam video { width:36px; height:36px; border-radius:50%; object-fit:cover; background:#111; transform:scaleX(-1); }
  .cam i { width:8px; height:8px; border-radius:50%; background:var(--bad); }
  .cam[data-state=asking] i, .cam[data-state=live] i { background:#f59e0b; }
  .cam[data-state=linked] i { background:#22c55e; box-shadow:0 0 0 3px rgba(34,197,94,.25); }

  .exam { max-width:1120px; margin:0 auto; padding:24px 20px 32px; display:grid; grid-template-columns:minmax(0,1fr) 296px; gap:24px; align-items:start; }
  .exam.cam-block .stage .card, .exam.cam-block .stage .dock { opacity:.35; pointer-events:none; }
  .banner { grid-column:1 / -1; display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; padding:12px 16px; border-radius:var(--r-m); background:var(--warn-soft); color:var(--warn); font-weight:500; }
  .banner .btn { min-height:36px; padding:0 14px; background:var(--surface); }

  .stage { display:grid; gap:16px; min-width:0; }
  .progress { display:flex; align-items:center; gap:16px; background:var(--surface); border:1px solid var(--line); border-radius:var(--r-m); padding:12px 16px; }
  .progress .bar { flex:1; height:8px; border-radius:99px; background:var(--line); overflow:hidden; }
  .progress .bar i { display:block; height:100%; width:0; background:var(--brand); border-radius:99px; transition:width .3s ease; }
  .progress > span { font-size:14px; color:var(--ink-2); white-space:nowrap; }
  .save { display:inline-flex; align-items:center; gap:6px; font-size:13px; font-weight:600; color:var(--ink-3); white-space:nowrap; }
  .save i { width:8px; height:8px; border-radius:50%; background:#22c55e; flex:none; }
  .save[data-state=saving] i { background:#f59e0b; }
  .save[data-state=offline], .save[data-state=failed] { color:var(--bad); }
  .save[data-state=offline] i, .save[data-state=failed] i { background:var(--bad); }
  .qtimer { position:relative; width:52px; height:52px; flex:none; }
  .qtimer svg { width:52px; height:52px; transform:rotate(-90deg); }
  .qtimer circle { fill:none; stroke-width:5; }
  .qtimer .t { stroke:var(--line); } .qtimer .r { stroke:var(--ok); stroke-linecap:round; stroke-dasharray:131.95; transition:stroke .3s; }
  .qtimer[data-state=warn] .r { stroke:var(--warn); } .qtimer[data-state=crit] .r { stroke:var(--bad); }
  .qtimer b { position:absolute; inset:0; display:grid; place-items:center; font-size:15px; font-variant-numeric:tabular-nums; }
  .qtimer[data-state=crit] b { color:var(--bad); }

  .card { background:var(--surface); border:1px solid var(--line); border-radius:var(--r-l); box-shadow:var(--shadow); padding:32px; }
  .q-slide { animation:in .18s ease; } @keyframes in { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:none; } }
  .q-head { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:16px; }
  .q-head h2 { font-size:14px; font-weight:600; color:var(--ink-3); }
  .q-head .meta { display:flex; gap:8px; }
  .q-img { display:block; width:100%; max-height:280px; object-fit:contain; border-radius:var(--r-s); border:1px solid var(--line); background:var(--bg); margin-bottom:20px; }
  .q-text { font-size:20px; line-height:1.55; font-weight:600; letter-spacing:-.005em; margin-bottom:24px; max-width:68ch; white-space:pre-line; }
  .options { display:grid; gap:12px; }
  .option { display:flex; align-items:center; gap:16px; min-height:60px; padding:12px 16px; border:1.5px solid var(--line-2); border-radius:var(--r-m); background:var(--surface); cursor:pointer; user-select:none; transition:border-color .12s,background .12s,box-shadow .12s; }
  .option:hover { border-color:var(--brand); background:var(--brand-soft); }
  .option .letter { width:36px; height:36px; border-radius:50%; border:1.5px solid var(--line-2); display:grid; place-items:center; font-weight:700; font-size:14px; color:var(--ink-2); flex:none; background:var(--surface); }
  .option .text { flex:1; line-height:1.45; }
  .option.is-selected { border-color:var(--brand); background:var(--brand-soft); box-shadow:0 0 0 3px var(--focus); }
  .option input:checked ~ .letter { background:var(--brand); border-color:var(--brand); color:#fff; }
  .option input:focus-visible ~ .letter { outline:3px solid var(--focus); outline-offset:2px; }

  .dock { position:sticky; bottom:16px; background:var(--surface); border:1px solid var(--line-2); border-radius:var(--r-m); box-shadow:var(--shadow-lg); padding:12px; z-index:20; }
  .dock .hint { min-height:0; font-size:14px; color:var(--warn); padding:0 4px 8px; font-weight:500; } .dock .hint:empty { display:none; }
  .dock-row { display:flex; align-items:center; justify-content:space-between; gap:8px; }
  .dock-mid { display:flex; gap:8px; }
  .btn[aria-pressed=true] { background:var(--warn-soft); border-color:var(--warn); color:var(--warn); }
  .only-small { display:none; }
  .keys { font-size:13px; color:var(--ink-3); text-align:center; }
  .shake { animation:shake .4s ease; } @keyframes shake { 20%,60% { transform:translateX(-6px); } 40%,80% { transform:translateX(6px); } }

  .nav-panel { position:sticky; top:88px; background:var(--surface); border:1px solid var(--line); border-radius:var(--r-l); padding:20px; box-shadow:var(--shadow); }
  .nav-panel h3,.dlg h3 { font-size:16px; margin-bottom:4px; } .nav-panel .sub { font-size:14px; color:var(--ink-3); margin-bottom:16px; }
  .pal-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:8px; }
  .pal { position:relative; height:44px; border-radius:var(--r-s); border:1.5px solid var(--line-2); background:var(--surface); font-weight:600; font-size:14px; cursor:pointer; font-variant-numeric:tabular-nums; }
  .pal:hover { border-color:var(--brand); }
  .pal.answered { background:var(--brand); border-color:var(--brand); color:#fff; }
  .pal.current { box-shadow:0 0 0 3px var(--focus); border-color:var(--brand); }
  .pal.current:not(.answered) { color:var(--brand); background:var(--brand-soft); }
  .pal.flagged::after { content:''; position:absolute; top:-4px; right:-4px; width:12px; height:12px; border-radius:50%; background:#f59e0b; border:2px solid var(--surface); }
  .legend { list-style:none; display:grid; grid-template-columns:1fr 1fr; gap:8px; margin:16px 0 20px; font-size:13px; color:var(--ink-3); }
  .legend li { display:flex; align-items:center; gap:8px; } .legend i { width:14px; height:14px; border-radius:4px; border:1.5px solid var(--line-2); display:block; }
  .k-ans { background:var(--brand); border-color:var(--brand) !important; } .k-cur { background:var(--brand-soft); border-color:var(--brand) !important; } .k-flag { background:#f59e0b; border-color:#f59e0b !important; border-radius:50% !important; }

  /* Dialogs */
  dialog { border:0; border-radius:var(--r-l); padding:0; width:min(420px,calc(100vw - 32px)); background:var(--surface); color:var(--ink); box-shadow:var(--shadow-lg); margin:auto; }
  dialog::backdrop { background:rgba(17,24,39,.55); backdrop-filter:blur(3px); }
  .dlg { padding:28px; text-align:center; }
  .dlg .badge { width:56px; height:56px; border-radius:50%; background:var(--brand-soft); color:var(--brand); display:grid; place-items:center; margin:0 auto 16px; } .dlg .badge .ic { width:28px; height:28px; }
  .dlg .badge.bad { background:var(--bad-soft); color:var(--bad); }
  .dlg p { color:var(--ink-2); font-size:15px; }
  .stats { display:flex; justify-content:center; gap:32px; margin:20px 0 24px; }
  .stats b { display:block; font-size:28px; line-height:1.1; font-variant-numeric:tabular-nums; } .stats span { font-size:13px; color:var(--ink-3); }
  .dlg-actions { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  .dlg.wide { text-align:left; } .dlg.wide .head { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
  #toasts { position:fixed; left:50%; bottom:96px; transform:translateX(-50%); display:grid; gap:8px; z-index:99; width:max-content; max-width:calc(100vw - 32px); }
  .toast { background:var(--ink); color:#fff; padding:12px 20px; border-radius:var(--r-s); box-shadow:var(--shadow-lg); font-weight:500; text-align:center; }
  .toast.bad { background:var(--bad); } .toast.ok { background:var(--ok); }

  /* ═════════ RESULT ═════════ */
  .done { min-height:100vh; display:grid; place-items:center; padding:24px; }
  .done-card { width:100%; max-width:480px; text-align:center; background:var(--surface); border:1px solid var(--line); border-radius:var(--r-l); box-shadow:var(--shadow); padding:48px 40px 40px; }
  .done-card .badge { width:64px; height:64px; border-radius:50%; display:grid; place-items:center; margin:0 auto 20px; background:var(--ok-soft); color:var(--ok); } .done-card .badge.bad { background:var(--bad-soft); color:var(--bad); } .done-card .badge .ic { width:32px; height:32px; }
  .done-card h1 { font-size:26px; letter-spacing:-.02em; line-height:1.2; }
  .done-card .sub { color:var(--ink-2); margin:6px 0 28px; }
  .ring { width:168px; height:168px; border-radius:50%; margin:0 auto 28px; display:grid; place-items:center; background:conic-gradient(var(--ring-color) var(--deg), var(--line) 0); }
  .ring div { width:136px; height:136px; border-radius:50%; background:var(--surface); display:grid; place-content:center; }
  .ring b { font-size:44px; line-height:1; font-variant-numeric:tabular-nums; } .ring span { font-size:13px; color:var(--ink-3); }
  .facts { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; background:var(--bg); border-radius:var(--r-m); padding:16px; margin-bottom:28px; }
  .facts b { display:block; font-size:18px; font-variant-numeric:tabular-nums; } .facts span { font-size:13px; color:var(--ink-3); }
  .held { background:var(--bg); border-radius:var(--r-m); padding:16px; margin-bottom:28px; color:var(--ink-2); font-size:15px; }

  @media (max-width:960px) {
    .login { grid-template-columns:1fr; } .login-aside { padding:40px 28px; gap:24px; } .login-main { padding:32px 20px 48px; }
    .exam { grid-template-columns:1fr; padding:16px 12px 24px; } .nav-panel { display:none; } .only-small { display:inline-flex; }
    .topbar { padding:0 12px; grid-template-columns:1fr auto auto; } .who span,.cam span { display:none; } .cam { padding:4px; }
    .card { padding:20px 16px; } .q-text { font-size:18px; } .keys { display:none; }
  }
  @media (max-width:520px) { .row2,.info { grid-template-columns:1fr; } .who div { display:none; } .done-card { padding:36px 20px 28px; } .intro-card { padding:24px 18px; } .dock .btn { padding:0 14px; } .progress { gap:10px; padding:10px 12px; } }
  @media (prefers-reduced-motion:reduce) { *,*::before,*::after { animation:none !important; transition:none !important; } }
</style>
</head>
<body>

<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <symbol id="i-check" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></symbol>
  <symbol id="i-alert" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></symbol>
  <symbol id="i-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></symbol>
  <symbol id="i-shuffle" viewBox="0 0 24 24"><path d="M16 3h5v5M4 20L21 3M21 16v5h-5M15 15l6 6M4 4l5 5"/></symbol>
  <symbol id="i-cam" viewBox="0 0 24 24"><rect x="3" y="6" width="13" height="12" rx="2"/><path d="M16 10l5-3v10l-5-3z"/></symbol>
  <symbol id="i-wifi" viewBox="0 0 24 24"><path d="M2 9a15 15 0 0 1 20 0M5 13a10 10 0 0 1 14 0M8.5 16.5a5 5 0 0 1 7 0M12 20h.01"/></symbol>
  <symbol id="i-left" viewBox="0 0 24 24"><path d="M19 12H5M12 19l-7-7 7-7"/></symbol>
  <symbol id="i-right" viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></symbol>
  <symbol id="i-flag" viewBox="0 0 24 24"><path d="M5 21V4M5 4h11l-2 4 2 4H5"/></symbol>
  <symbol id="i-grid" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></symbol>
  <symbol id="i-sound" viewBox="0 0 24 24"><path d="M11 5L6 9H3v6h3l5 4zM16 9a4 4 0 0 1 0 6M19 6a8 8 0 0 1 0 12"/></symbol>
  <symbol id="i-mute" viewBox="0 0 24 24"><path d="M11 5L6 9H3v6h3l5 4zM22 9l-6 6M16 9l6 6"/></symbol>
  <symbol id="i-save" viewBox="0 0 24 24"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2zM17 21v-8H7v8M7 3v5h8"/></symbol>
  <symbol id="i-flagrule" viewBox="0 0 24 24"><path d="M5 21V4M5 4h11l-2 4 2 4H5"/></symbol>
</svg>
<noscript><div class="alert" style="margin:16px">This exam needs JavaScript. Turn it on in your browser and reload.</div></noscript>

<?php if ($view === 'login'): /* ═════════════ SIGN IN ═════════════ */ ?>
<div class="login">
  <aside class="login-aside">
    <h1>Computer Based Testing</h1>
    <div class="brand">
      <img src="<?= e(rawurlencode(CBT_LOGO)) ?>" alt="GMSS Pankshin ICT – Unity and Knowledge" width="320" height="256">
    </div>
  </aside>

  <main class="login-main">
    <div class="login-card">
      <h2>Sign in to your exam</h2>
      <p>Enter your username and the exam PIN your teacher gave you.</p>

      <?php if ($login_error): ?><div class="alert" role="alert"><?= ic('alert') ?><span><?= e($login_error) ?></span></div><?php endif; ?>

      <form method="post" id="loginForm" novalidate>
        <input type="hidden" name="student_login" value="1">
        <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
        <div class="field">
          <label for="username">Student username</label>
          <input id="username" name="username" type="text" maxlength="64" autocomplete="off" autocapitalize="none" spellcheck="false" autofocus required value="<?= e($login_user) ?>">
        </div>
        <div class="field">
          <label for="pin">Exam PIN</label>
          <input id="pin" name="pin" type="password" maxlength="32" autocomplete="off" autocapitalize="none" spellcheck="false" required>
          <small>Your teacher shares this PIN for the exam you are about to take.</small>
        </div>
        <button class="btn primary block" id="loginBtn" style="min-height:52px"><span>Continue</span><?= ic('right') ?></button>
      </form>
    </div>
  </main>
</div>

<script nonce="<?= e($nonce) ?>">
(() => {
  const $ = id => document.getElementById(id);
  $('loginForm').addEventListener('submit', ev => {
    const f = ev.target;
    if (!f.checkValidity()) { ev.preventDefault(); f.reportValidity(); return; }
    $('loginBtn').disabled = true;   // stops double submits on slow networks
    $('loginBtn').firstElementChild.textContent = 'Checking…';
  });
})();
</script>

<?php elseif ($view === 'intro'): /* ═════════════ INSTRUCTIONS ═════════════ */
    $camReq = (int)$exam['camera_required'] === 1; ?>
<main class="intro">
  <section class="intro-card">
    <h1>Before you start</h1>
    <p class="lead">Check your details and read the rules. The clock starts when you press Start exam.</p>

    <div class="info">
      <div><span>Student</span><b><?= e($fullname ?: $student) ?></b></div>
      <div><span>Username</span><b><?= e($student) ?></b></div>
      <div><span>Course</span><b><?= e($exam['course_name']) ?></b></div>
      <div><span>Class and term</span><b><?= e($exam['class_level']) ?> · <?= e($exam['term']) ?></b></div>
      <div><span>Questions</span><b><?= (int)$intro['questions'] ?></b></div>
      <div><span>Total time</span><b><?= (int)$intro['minutes'] ?> minutes</b></div>
    </div>

    <h2>Exam rules</h2>
    <ul class="rules">
      <li><?= ic('clock') ?><span>You have <?= (int)$intro['minutes'] ?> minutes for the whole exam. The clock is kept by the server, so refreshing, closing the page or losing internet does not stop it.</span></li>
      <li><?= ic('check') ?><span>Choose one answer for each question. Your answers are saved automatically the moment you choose them.</span></li>
      <li><?= ic('right') ?><span>Use Previous and Next, or tap a question number to jump to it.<?= CBT_SECS_PER_QUESTION > 0 ? ' Each question also has a ' . (int)CBT_SECS_PER_QUESTION . '-second timer and the exam moves on when it ends.' : '' ?> Flag a question to come back to it.</span></li>
      <li><?= ic('cam') ?><span><?= $camReq ? 'Your camera must stay on for the whole exam, or your answers cannot be saved.' : 'Allow your camera when asked.' ?> Your teacher watches live and nothing is recorded.</span></li>
      <li><?= ic('save') ?><span>If your page closes or your internet drops, sign in again with the same username and PIN to carry on where you stopped.</span></li>
      <li><?= ic('alert') ?><span>Press Submit exam when you finish. You cannot change answers after that. The exam is submitted automatically when time runs out.</span></li>
    </ul>

    <?php if ($intro_error): ?><div class="alert" role="alert"><?= ic('alert') ?><span><?= e($intro_error) ?></span></div><?php endif; ?>

    <form method="post" id="startForm" novalidate>
      <input type="hidden" name="start_exam" value="1">
      <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
      <input type="hidden" name="cam_ok" id="camOk" value="">

      <div class="camtest" id="camTest">
        <video id="testVideo" autoplay muted playsinline></video>
        <div><b id="camTestTitle"><?= $camReq ? 'Camera check required' : 'Camera check (recommended)' ?></b><span id="camTestText">Press the button to test your camera before you start.</span></div>
        <button class="btn" type="button" id="camTestBtn">Test my camera</button>
      </div>

      <label class="accept"><input type="checkbox" name="accept" value="1" id="accept"><span>I have read the exam instructions and I accept them.</span></label>

      <div class="intro-actions">
        <button class="btn primary block" id="startBtn" style="min-height:52px" disabled><span>Start exam</span><?= ic('right') ?></button>
      </div>
    </form>
    <form method="post" class="intro-actions" style="margin-top:8px">
      <input type="hidden" name="logout" value="1"><input type="hidden" name="csrf" value="<?= e($csrf) ?>">
      <button class="linkbtn" type="submit">Not you? Sign out</button>
    </form>
  </section>
</main>

<script nonce="<?= e($nonce) ?>">
(() => {
  const $ = id => document.getElementById(id), need = <?= $camReq ? 'true' : 'false' ?>;
  let camOk = false, stream = null;
  const sync = () => { $('startBtn').disabled = !($('accept').checked && (!need || camOk)); };
  $('accept').addEventListener('change', sync);
  $('camTestBtn').addEventListener('click', async () => {
    const box = $('camTest'), txt = $('camTestText');
    box.className = 'camtest'; txt.textContent = 'Waiting for permission…';
    try {
      if (!navigator.mediaDevices?.getUserMedia) throw new Error('unsupported');
      if (stream) stream.getTracks().forEach(t => t.stop());
      stream = await navigator.mediaDevices.getUserMedia({ video: { width: 320, height: 240 }, audio: false });
      $('testVideo').srcObject = stream;
      camOk = true; $('camOk').value = '1'; box.classList.add('good'); txt.textContent = 'Your camera is working. You are ready.';
    } catch (err) {
      camOk = false; $('camOk').value = ''; box.classList.add('bad');
      txt.textContent = err && err.name === 'NotAllowedError' ? 'Camera blocked. Allow camera access in your browser (the icon beside the address bar), then try again.' : 'We could not find a working camera. Check it is connected and not used by another app.';
    }
    sync();
  });
  $('startForm').addEventListener('submit', ev => {
    if ($('startBtn').disabled) { ev.preventDefault(); return; }
    if (stream) stream.getTracks().forEach(t => t.stop());   // the exam page asks again; the browser remembers your choice
    $('startBtn').disabled = true; $('startBtn').firstElementChild.textContent = 'Starting…';
  });
  sync();
})();
</script>

<?php elseif ($view === 'result'):  /* ═════════════ RESULT ═════════════ */
    $total = (int)$result['total_marks'];
    $pct   = (float)$result['percentage'];
    $deg   = (int)round(((float)$result['score_60'] / 60) * 360);
    $color = $result['score_60'] >= 45 ? '#0f8a5f' : ($result['score_60'] >= 30 ? '#b45309' : '#c62828');
    $timed = $result['status'] === 'timed_out'; ?>
<main class="done">
  <section class="done-card">
    <div class="badge <?= $timed ? 'bad' : '' ?>"><?= ic($timed ? 'clock' : 'check') ?></div>
    <h1><?= $timed ? 'Time is up' : 'Exam submitted' ?></h1>
    <p class="sub"><?= e($result['course']) ?> · <?= e($result['class']) ?> · <?= e($result['term']) ?><br><?= $timed ? 'Your answers were submitted automatically.' : 'Your answers have been saved.' ?></p>

<?php if (!empty($result['released'])): ?>
    <div class="ring" style="--deg:<?= $deg ?>deg;--ring-color:<?= $color ?>" role="img" aria-label="Score <?= e($result['score_60']) ?> out of 60">
      <div><b><?= e($result['score_60']) ?></b><span>out of 60</span></div>
    </div>

    <div class="facts">
      <div><b><?= (int)$result['raw_score'] ?>/<?= $total ?></b><span>Marks</span></div>
      <div><b><?= round($pct, 1) ?>%</b><span>Percentage</span></div>
      <div><b><?= (int)$result['question_count'] ?></b><span>Questions</span></div>
    </div>
<?php else: ?>
    <p class="held">Your result will be shown when your school releases it. Please ask your teacher.</p>
<?php endif; ?>
    <a class="btn primary block" href="<?= e($self) ?>" style="min-height:52px">Back to sign in</a>
  </section>
</main>
<script nonce="<?= e($nonce) ?>">
/* The server has confirmed the submission: remove the temporary answer queue from this browser */
(() => { try { Object.keys(localStorage).filter(k => k.startsWith('cbt:pending:')).forEach(k => localStorage.removeItem(k)); } catch (e) {} })();
</script>

<?php else: /* ═════════════ EXAM ═════════════ */ ?>
<header class="topbar">
  <div class="who">
    <div class="avatar"><?= e(mb_strtoupper(mb_substr((string)($fullname ?: $student), 0, 1))) ?></div>
    <div><strong><?= e($fullname ?: $student) ?></strong><span><?= e($course) ?> · <?= e($exam['class_level']) ?> · <?= e($exam['term']) ?></span></div>
  </div>
  <div class="clock" id="clock" role="timer" aria-label="Total time left"><small>Time left</small><b id="clockText">--:--</b></div>
  <div class="tools">
    <button class="icon-btn" type="button" id="soundBtn" aria-pressed="true" aria-label="Read-aloud prompts"><?= ic('sound') ?></button>
    <div class="cam" id="cam" data-state="asking" title="Your teacher can see this camera while you sit the exam"><video id="camPreview" autoplay muted playsinline></video><i></i><span id="camText">Allow camera…</span></div>
  </div>
</header>

<form method="post" id="examForm">
  <input type="hidden" name="submit_exam" value="1">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  <div class="exam" id="examWrap">
    <div class="banner" id="camBanner" hidden role="alert">
      <span id="camBannerText"></span>
      <button class="btn" type="button" id="camRetry">Try again</button>
    </div>

    <div class="stage">
      <div class="progress">
        <span><b id="answeredText">0</b> of <?= (int)$question_count ?> answered</span>
        <div class="bar" aria-hidden="true"><i id="progFill"></i></div>
        <span class="save" id="saveState" data-state="saved" role="status" aria-live="polite"><i></i><em id="saveText" style="font-style:normal">Saved</em></span>
<?php if (CBT_SECS_PER_QUESTION > 0): ?>
        <div class="qtimer" id="qtimer" role="timer" aria-label="Time left for this question">
          <svg viewBox="0 0 52 52" aria-hidden="true"><circle class="t" cx="26" cy="26" r="21"/><circle class="r" id="qring" cx="26" cy="26" r="21"/></svg>
          <b id="qtext"><?= (int)CBT_SECS_PER_QUESTION ?></b>
        </div>
<?php endif; ?>
      </div>

      <section class="card" aria-live="off">
        <?php foreach ($questions as $i => $q): $qid = (int)$q['id']; ?>
        <div class="q-slide" data-qid="<?= $qid ?>" <?= $i ? 'hidden' : '' ?>>
          <div class="q-head">
            <h2>Question <?= $i + 1 ?> of <?= (int)$question_count ?></h2>
            <div class="meta"><span class="chip"><?= (int)$q['marks'] ?> mark<?= (int)$q['marks'] === 1 ? '' : 's' ?></span><?= diff_badge($q['difficulty'] ?? null) ?></div>
          </div>
          <?php if (!empty($q['question_image'])): ?><img class="q-img" src="<?= e($q['question_image']) ?>" alt="Picture for question <?= $i + 1 ?>"><?php endif; ?>
          <p class="q-text"><?= e($q['question_text']) ?></p>
          <fieldset class="options">
            <legend class="sr">Choose one answer for question <?= $i + 1 ?></legend>
            <?php foreach (['a', 'b', 'c', 'd'] as $o):
                $text = (string)$q['option_' . $o]; if ($text === '') continue; $L = strtoupper($o); ?>
              <label class="option">
                <input class="sr" type="radio" name="answer[<?= $qid ?>]" value="<?= $L ?>"<?= ($answers[$qid] ?? '') === $L ? ' checked' : '' ?>>
                <span class="letter"><?= $L ?></span><span class="text"><?= e($text) ?></span>
              </label>
            <?php endforeach; ?>
          </fieldset>
        </div>
        <?php endforeach; ?>
      </section>

      <div class="dock">
        <p class="hint" id="hint" role="status"></p>
        <div class="dock-row">
          <button class="btn" type="button" id="btnPrev"><?= ic('left') ?>Previous</button>
          <div class="dock-mid">
            <button class="btn" type="button" id="btnFlag" aria-pressed="false"><?= ic('flag') ?><span>Flag</span></button>
            <button class="btn only-small" type="button" id="btnNav"><?= ic('grid') ?>Questions</button>
          </div>
          <button class="btn primary" type="button" id="btnNext"><span>Next</span><?= ic('right') ?></button>
        </div>
      </div>
      <p class="keys">Shortcuts: A to D choose an answer · N next · P previous · F flag</p>
    </div>

    <aside class="nav-panel" aria-label="Question navigator">
      <h3>Questions</h3>
      <p class="sub"><span data-count="answered">0</span> answered · <span data-count="flagged">0</span> flagged</p>
      <?= palette_grid($question_count) ?>
      <?= palette_legend() ?>
      <button class="btn ok block" type="button" data-submit><?= ic('check') ?>Submit exam</button>
    </aside>
  </div>
</form>

<!-- Phone navigator -->
<dialog id="dlgNav" aria-labelledby="dlgNavT">
  <div class="dlg wide">
    <div class="head"><h3 id="dlgNavT">Questions</h3><button class="btn" type="button" data-close style="min-height:36px">Close</button></div>
    <?= palette_grid($question_count) ?>
    <?= palette_legend() ?>
    <button class="btn ok block" type="button" data-submit><?= ic('check') ?>Submit exam</button>
  </div>
</dialog>

<dialog id="dlgSubmit" aria-labelledby="dlgSubmitT">
  <div class="dlg">
    <div class="badge"><?= ic('check') ?></div>
    <h3 id="dlgSubmitT">Submit your exam?</h3>
    <p id="submitDesc"></p>
    <div class="stats">
      <div><b id="sAnswered">0</b><span>Answered</span></div>
      <div><b id="sLeft">0</b><span>Not answered</span></div>
      <div><b id="sFlagged">0</b><span>Flagged</span></div>
    </div>
    <div class="dlg-actions">
      <button class="btn" type="button" data-close>Keep working</button>
      <button class="btn ok" type="button" id="confirmSubmit">Submit exam</button>
    </div>
  </div>
</dialog>

<dialog id="dlgTime" aria-labelledby="dlgTimeT">
  <div class="dlg">
    <div class="badge bad"><?= ic('clock') ?></div>
    <h3 id="dlgTimeT">Time is up</h3>
    <p>Your answers are being submitted automatically.</p>
    <button class="btn ok block" type="button" id="submitNow" style="margin-top:20px">Submit now</button>
  </div>
</dialog>

<div id="toasts" role="status" aria-live="polite"></div>
<script type="application/json" id="cfg"><?= json_encode([
    'total'          => (int)$question_count,
    'secsPerQ'       => (int)CBT_SECS_PER_QUESTION,
    'remaining'      => (int)$left,
    'sessionId'      => (int)$sid,
    'csrf'           => $csrf,
    'api'            => 'cbt_api.php',
    'pingMs'         => (int)CBT_PING_SECS * 1000,
    'ice'            => cbt_ice(),
    'cameraRequired' => (int)$exam['camera_required'] === 1,
    'flags'          => $flag_idx,
    'resumed'        => $resumed,
], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>

<script nonce="<?= e($nonce) ?>">
(() => {
  'use strict';
  const cfg = JSON.parse(document.getElementById('cfg').textContent);
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const form = $('#examForm'), slides = $$('.q-slide'), N = cfg.total, last = N - 1;
  const qidOf = i => +slides[i].dataset.qid;
  const S = { current: 0, qEnd: 0, totalEnd: 0, initialTotal: cfg.remaining, spoke30: false, done: false, ending: false, flags: new Set(cfg.flags), tickId: 0 };

  /* ── Read-aloud prompts (can be muted) ── */
  const TTS = (() => {
    const ok = 'speechSynthesis' in window; let voices = [], pending = [], muted = false;
    try { muted = localStorage.getItem('cbt-sound') === 'off'; } catch (e) {}
    const speak = text => {
      speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(text); u.lang = 'en-GB'; u.rate = .93; u.pitch = 1.05;
      u.voice = voices.find(v => v.lang.startsWith('en') && /female|woman|zira|hazel|susan|karen|samantha/i.test(v.name)) || voices.find(v => v.lang.startsWith('en')) || voices[0] || null;
      speechSynthesis.speak(u);
    };
    const load = () => { voices = speechSynthesis.getVoices(); while (voices.length && pending.length) speak(pending.shift()); };
    if (ok) { speechSynthesis.onvoiceschanged = load; load(); }
    return {
      get muted() { return muted; },
      toggle() { muted = !muted; try { localStorage.setItem('cbt-sound', muted ? 'off' : 'on'); } catch (e) {} if (muted && ok) speechSynthesis.cancel(); return muted; },
      say(text) { if (!ok || muted) return; if (!voices.length) { pending = [text]; return; } speak(text); }
    };
  })();
  const soundBtn = $('#soundBtn');
  const paintSound = () => { soundBtn.setAttribute('aria-pressed', String(!TTS.muted)); soundBtn.firstElementChild.firstElementChild.setAttribute('href', TTS.muted ? '#i-mute' : '#i-sound'); soundBtn.title = TTS.muted ? 'Read-aloud is off' : 'Read-aloud is on'; };
  soundBtn.addEventListener('click', () => { TTS.toggle(); paintSound(); });
  paintSound();

  /* ── Small helpers ── */
  const toast = (msg, type = '') => { const el = Object.assign(document.createElement('div'), { className: 'toast ' + type, textContent: msg }); $('#toasts').appendChild(el); setTimeout(() => el.remove(), 4500); };
  const mmss  = s => String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
  const isAnswered = i => !!$('input:checked', slides[i]);
  const answeredN  = () => slides.filter((_, i) => isAnswered(i)).length;
  const openDlg = id => { const d = document.getElementById(id); if (!d.open) d.showModal(); return d; };
  const reloadPage = () => { S.done = true; window.removeEventListener('beforeunload', guard); location.reload(); };

  /* ── Talking to the server ── */
  async function api(body, ms = 8000) {
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), ms);
    try {
      const r = await fetch(cfg.api, { method: 'POST', credentials: 'same-origin', signal: ctl.signal,
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': cfg.csrf }, body: JSON.stringify(body) });
      let d = null; try { d = await r.json(); } catch (e) {}
      return d || { ok: false, code: 'network' };
    } catch (e) { return { ok: false, code: 'network' }; }
    finally { clearTimeout(t); }
  }
  const ev = (type, detail = '') => { api({ action: 'event', type, detail }, 6000); };
  /* The server clock is the only one that counts: every reply re-aligns the countdown */
  const syncLeft = left => { if (typeof left === 'number' && !S.done) S.totalEnd = Date.now() + Math.max(0, left) * 1000; };

  /* ── Autosave: every answer goes to MySQL at once; if the connection drops, changes wait here and are sent when it returns ── */
  const SAVE_TEXT = { saved: 'Saved', saving: 'Saving…', offline: 'Connection interrupted', failed: 'Save failed' };
  const setState = st => { $('#saveState').dataset.state = st; $('#saveText').textContent = SAVE_TEXT[st]; };
  const Q = {
    key: 'cbt:pending:' + cfg.sessionId, map: new Map(), flushing: false, v: 0, timer: 0, retry: 0, backoff: 2000,
    load() { try { JSON.parse(localStorage.getItem(this.key) || '[]').forEach(c => this.map.set(c.q, c)); } catch (e) {} },
    store() { try { this.map.size ? localStorage.setItem(this.key, JSON.stringify([...this.map.values()])) : localStorage.removeItem(this.key); } catch (e) {} },
    add(q, patch) {
      const cur = this.map.get(q) || { q }; Object.assign(cur, patch); cur.v = ++this.v;
      this.map.set(q, cur); this.store(); setState('saving');
      clearTimeout(this.timer); this.timer = setTimeout(() => this.flush(), 120);
    },
    async flush() {
      if (this.flushing) return false;
      if (!this.map.size) return true;
      this.flushing = true; clearTimeout(this.retry);
      const batch = [...this.map.values()].slice(0, 50).map(c => ({ ...c }));
      const changes = batch.map(c => { const o = { q: c.q }; if (c.a !== undefined) o.a = c.a; if (c.f !== undefined) o.f = c.f; return o; });
      const d = await api({ action: 'save', changes });
      this.flushing = false;
      if (d.ok) {
        batch.forEach(b => { const cur = this.map.get(b.q); if (cur && cur.v === b.v) this.map.delete(b.q); });
        this.store(); this.backoff = 2000; syncLeft(d.left);
        if (this.map.size) return this.flush();
        setState('saved'); return true;
      }
      this.failed(d); return false;
    },
    failed(d) {
      const again = ms => { clearTimeout(this.retry); this.retry = setTimeout(() => this.flush(), ms); };
      if (d.code === 'expired') { timeUp(); return; }
      if (d.code === 'closed' || d.code === 'auth' || d.code === 'csrf') { reloadPage(); return; }
      if (d.code === 'camera_required') { setState('failed'); cam.demand(); again(5000); return; }
      setState(d.code === 'network' ? 'offline' : 'failed');
      again(this.backoff); this.backoff = Math.min(this.backoff * 2, 15000);
    },
    async flushAll(ms = 6000) {
      const end = Date.now() + ms;
      while (this.map.size && Date.now() < end) { await this.flush(); if (this.map.size) await sleep(400); }
      return !this.map.size;
    }
  };

  /* ── Navigator, progress ── */
  function paint() {
    const n = answeredN();
    $('#progFill').style.width = (n / N * 100) + '%';
    $('#answeredText').textContent = n;
    $$('[data-count=answered]').forEach(el => el.textContent = n);
    $$('[data-count=flagged]').forEach(el => el.textContent = S.flags.size);
    $$('.pal').forEach(b => {
      const i = +b.dataset.goto, ans = isAnswered(i), flag = S.flags.has(i);
      b.classList.toggle('answered', ans); b.classList.toggle('flagged', flag); b.classList.toggle('current', i === S.current);
      b.setAttribute('aria-label', 'Question ' + (i + 1) + (ans ? ', answered' : ', not answered') + (flag ? ', flagged' : '') + (i === S.current ? ', current' : ''));
    });
    const f = $('#btnFlag'); f.setAttribute('aria-pressed', String(S.flags.has(S.current))); $('span', f).textContent = S.flags.has(S.current) ? 'Flagged' : 'Flag';
    $$('.option', form).forEach(o => o.classList.toggle('is-selected', o.querySelector('input').checked));
  }

  function goTo(i) {
    if (i < 0 || i > last || S.done) return;
    slides.forEach((s, k) => s.hidden = k !== i);
    S.current = i;
    $('#hint').textContent = '';
    $('#btnPrev').disabled = i === 0;
    const next = $('#btnNext'); $('span', next).textContent = i === last ? 'Review and submit' : 'Next';
    S.qEnd = Date.now() + cfg.secsPerQ * 1000;
    paint(); paintQ(cfg.secsPerQ);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
  function tryNext() {
    if (S.current === last) return openSubmit();
    if (isAnswered(S.current) || S.flags.has(S.current)) return goTo(S.current + 1);
    $('#hint').textContent = 'Choose an answer, or flag this question to come back to it.';
    TTS.say('Please answer this question before moving on.');
    const box = $('.options', slides[S.current]); box.classList.remove('shake'); void box.offsetWidth; box.classList.add('shake');
  }

  document.addEventListener('click', ev => {
    const t = ev.target;
    const g = t.closest('[data-goto]'); if (g) { goTo(+g.dataset.goto); $('#dlgNav').close(); }
    if (t.closest('[data-submit]')) { $('#dlgNav').close(); openSubmit(); }
    if (t.closest('[data-close]')) t.closest('dialog').close();
  });
  $('#btnPrev').addEventListener('click', () => goTo(S.current - 1));
  $('#btnNext').addEventListener('click', tryNext);
  $('#btnNav').addEventListener('click', () => openDlg('dlgNav'));
  $('#btnFlag').addEventListener('click', () => {
    S.flags.has(S.current) ? S.flags.delete(S.current) : S.flags.add(S.current);
    Q.add(qidOf(S.current), { f: S.flags.has(S.current) ? 1 : 0 }); paint();
  });
  form.addEventListener('change', ev => {
    if (!ev.target.matches('input[type=radio]')) return;
    const m = /\[(\d+)\]/.exec(ev.target.name); if (!m) return;
    $('#hint').textContent = ''; resetIdle(); paint();
    Q.add(+m[1], { a: ev.target.value });
  });
  document.addEventListener('keydown', ev => {
    if (ev.ctrlKey || ev.metaKey || ev.altKey || document.querySelector('dialog[open]') || S.done) return;
    const k = ev.key.toLowerCase();
    if ('abcd'.includes(k) && k.length === 1) { const r = $(`input[value="${k.toUpperCase()}"]`, slides[S.current]); if (r) { r.checked = true; r.dispatchEvent(new Event('change', { bubbles: true })); } }
    else if (k === 'n') tryNext(); else if (k === 'p') goTo(S.current - 1); else if (k === 'f') $('#btnFlag').click();
  });

  /* ── Submit ── */
  function openSubmit() {
    const a = answeredN(), left = N - a;
    $('#sAnswered').textContent = a; $('#sLeft').textContent = left; $('#sFlagged').textContent = S.flags.size;
    $('#submitDesc').textContent = left > 0 ? 'You still have ' + left + ' unanswered question' + (left === 1 ? '' : 's') + '. You can’t change your answers after you submit.' : 'You answered every question. You can’t change your answers after you submit.';
    openDlg('dlgSubmit');
  }
  function finishSubmit() {
    if (S.done) return;
    S.done = true; clearInterval(S.tickId); cam.stop();
    window.removeEventListener('beforeunload', guard);
    setTimeout(() => form.submit(), 500);
  }
  async function submitExam() {
    if (S.done || S.ending) return;
    S.ending = true;
    const btn = $('#confirmSubmit'); btn.disabled = true; btn.textContent = 'Saving…';
    const saved = await Q.flushAll(8000);      // every answer must reach the server before the exam is closed
    if (!saved) {
      S.ending = false; btn.disabled = false; btn.textContent = 'Submit exam';
      toast('Some answers are not saved yet. Check your internet and try again.', 'bad'); return;
    }
    TTS.say('Exam submitted successfully.');
    finishSubmit();
  }
  $('#confirmSubmit').addEventListener('click', submitExam);
  $('#submitNow').addEventListener('click', () => { S.ending = true; finishSubmit(); });
  $('#dlgTime').addEventListener('cancel', ev => ev.preventDefault());
  async function timeUp() {
    if (S.done || S.ending) return;
    S.ending = true; clearInterval(S.tickId);
    $$('dialog[open]').forEach(d => d.close());
    TTS.say('Time is up. Your answers are being submitted.');
    openDlg('dlgTime');
    await Q.flushAll(3000);                    // last chance to save; the server has the final say on time
    finishSubmit();
  }

  /* ── Timers: the server sets the deadline; this page only displays it ── */
  const RING = 131.95, qtimer = $('#qtimer');
  const state = s => s <= 10 ? 'crit' : s <= 20 ? 'warn' : 'ok';
  function paintQ(s) { if (!qtimer) return; $('#qtext').textContent = s; $('#qring').style.strokeDashoffset = RING * (1 - s / cfg.secsPerQ); qtimer.dataset.state = state(s); }
  function tick() {
    if (S.done) return;
    const now = Date.now(), t = Math.max(0, Math.ceil((S.totalEnd - now) / 1000));
    $('#clockText').textContent = mmss(t);
    $('#clock').dataset.state = t <= 60 ? 'crit' : t <= 300 ? 'warn' : '';
    if (!S.spoke30 && S.initialTotal > 1800 && t <= 1800) { S.spoke30 = true; TTS.say('You have 30 minutes remaining.'); }
    if (t <= 0) return timeUp();
    if (cfg.secsPerQ > 0) {
      const q = Math.max(0, Math.ceil((S.qEnd - now) / 1000));
      paintQ(q);
      if (q <= 0) S.current < last ? goTo(S.current + 1) : openSubmit();
    }
  }

  /* ── Camera (WebRTC straight to the teacher; camera_signal.php only relays the handshake) ──
     "Camera on" means your camera is really capturing. "Camera live" means the teacher's connection is up too. */
  const cam = {
    pc: null, stream: null, after: 0, pollT: 0, retryT: 0, discT: 0, status: 'asking', linked: false, everLive: false, stopped: false,
    liveTrack() { return !!this.stream && this.stream.getVideoTracks().some(t => t.readyState === 'live'); },
    set(status) {
      if (this.status === status && status !== 'live') return false;
      const changed = this.status !== status; this.status = status; this.paint(); return changed;
    },
    paint() {
      const st = this.status, live = st === 'live';
      $('#cam').dataset.state = live ? (this.linked ? 'linked' : 'live') : st;
      $('#camText').textContent = { asking: 'Allow camera…', denied: 'Camera blocked', lost: 'Reconnecting…', idle: 'Camera off', live: this.linked ? 'Camera live' : 'Camera on' }[st];
      const problem = st === 'denied' || st === 'lost';
      $('#camBanner').hidden = !problem;
      if (problem) $('#camBannerText').textContent = (st === 'denied'
        ? 'Your camera is blocked. Allow camera access in your browser (the icon beside the address bar), then press Try again.'
        : 'Your camera was disconnected. Plug it back in or close other apps using it. We keep trying automatically.')
        + (cfg.cameraRequired ? ' The exam is paused until your camera works, but the timer keeps running.' : '');
      $('#examWrap').classList.toggle('cam-block', cfg.cameraRequired && (problem || st === 'idle'));
    },
    demand() { if (this.status === 'live') return; this.paint(); },
    send(type, payload, keepalive = false) {
      fetch('camera_signal.php', { method: 'POST', headers: { 'Content-Type': 'application/json' }, keepalive,
        body: JSON.stringify({ session_id: cfg.sessionId, role: 'student', type, payload }) }).catch(() => {});
    },
    releaseStream() { if (this.stream) { this.stream.getTracks().forEach(t => { t.onended = null; t.stop(); }); this.stream = null; } },
    closePc(quiet) {
      clearTimeout(this.discT); clearTimeout(this.pollT);
      if (this.pc) { this.pc.onconnectionstatechange = null; this.pc.onicecandidate = null; this.pc.close(); this.pc = null; if (!quiet) this.send('bye', '1', true); }
      this.linked = false;
    },
    async start() {
      if (this.stopped) return;
      clearTimeout(this.retryT); this.set('asking');
      try {
        if (!navigator.mediaDevices?.getUserMedia) throw Object.assign(new Error('unsupported'), { name: 'NotSupportedError' });
        if (!this.liveTrack()) { this.releaseStream(); this.stream = await navigator.mediaDevices.getUserMedia({ video: { width: 320, height: 240 }, audio: false }); }
      } catch (err) {
        const blocked = !!err && (err.name === 'NotAllowedError' || err.name === 'SecurityError');
        if (this.set(blocked ? 'denied' : 'lost')) { ev(blocked ? 'camera_denied' : 'camera_disconnected', err && err.name || ''); if (blocked) TTS.say('Camera access is required to continue this exam.'); }
        if (!blocked) this.retryT = setTimeout(() => this.start(), 5000);
        return;
      }
      this.stream.getVideoTracks().forEach(t => { t.onended = () => this.onLost(); });
      $('#camPreview').srcObject = this.stream;
      const again = this.everLive; this.everLive = true;
      if (this.set('live') && again) ev('camera_reconnected');
      else if (!again) ev('camera_connected');
      await this.connect();
    },
    onLost() {
      if (this.stopped) return;
      this.closePc(true);
      if (this.set('lost')) { ev('camera_disconnected', 'track ended'); TTS.say('Your camera was disconnected.'); }
      clearTimeout(this.retryT); this.retryT = setTimeout(() => this.start(), 3000);
    },
    async connect() {
      if (this.stopped || !this.stream) return;
      this.closePc(true);
      const pc = this.pc = new RTCPeerConnection({ iceServers: cfg.ice });
      this.stream.getTracks().forEach(t => pc.addTrack(t, this.stream));
      pc.onicecandidate = e => e.candidate && this.send('candidate', JSON.stringify(e.candidate));
      pc.onconnectionstatechange = () => {
        if (this.pc !== pc) return;
        const st = pc.connectionState;
        if (st === 'connected') { clearTimeout(this.discT); this.linked = true; this.paint(); }
        else if (st === 'disconnected' || st === 'failed') {
          this.linked = false; this.paint(); clearTimeout(this.discT);
          this.discT = setTimeout(() => { if (this.pc === pc && this.status === 'live') this.connect(); }, st === 'failed' ? 1500 : 6000);
        }
      };
      const offer = await pc.createOffer(); await pc.setLocalDescription(offer);
      if (this.pc !== pc) return;
      this.send('offer', JSON.stringify(offer));
      this.poll();
    },
    async poll() {
      const pc = this.pc; if (!pc || this.stopped) return;
      try {
        const d = await (await fetch(`camera_signal.php?session_id=${cfg.sessionId}&role=student&after_id=${this.after}`)).json();
        if (this.pc !== pc) return;
        if (d.ok && d.messages.length) {
          this.after = d.max_id;
          for (const m of d.messages) {
            if (m.type === 'answer' && this.pc && this.pc.signalingState !== 'stable') await this.pc.setRemoteDescription(new RTCSessionDescription(JSON.parse(m.payload)));
            else if (m.type === 'candidate' && this.pc) { try { await this.pc.addIceCandidate(JSON.parse(m.payload)); } catch (e) {} }
          }
        }
      } catch (e) {}
      if (this.pc === pc) this.pollT = setTimeout(() => this.poll(), this.linked ? 5000 : 1500);
    },
    stop() {
      this.stopped = true; clearTimeout(this.retryT);
      this.closePc(false); this.releaseStream();
    }
  };
  $('#camRetry').addEventListener('click', () => { cam.stopped = false; cam.start(); });
  navigator.mediaDevices?.addEventListener?.('devicechange', () => { if (!cam.stopped && cam.status === 'lost') cam.start(); });

  /* ── Gentle nudges when a student goes quiet ── */
  let idleTimer = 0, idleStage = 0, lastActive = Date.now(), lastMove = 0;
  function resetIdle() { lastActive = Date.now(); idleStage = 0; clearTimeout(idleTimer); idleTimer = setTimeout(checkIdle, 20000); }
  function checkIdle() {
    const s = Math.floor((Date.now() - lastActive) / 1000);
    if (idleStage === 0 && s >= 20) { idleStage = 1; TTS.say('Are you still there? Please select an answer to continue.'); toast('Still there? Pick an answer to continue.', 'bad'); idleTimer = setTimeout(checkIdle, 20000); }
    else if (idleStage === 1 && s >= 40) { idleStage = 2; TTS.say('You are not answering. The timer is still running. Please choose an option now.'); toast('The timer is still running. Choose an answer now.', 'bad'); idleTimer = setTimeout(checkIdle, 30000); }
    else if (idleStage === 2) { TTS.say('Please answer the current question.'); idleTimer = setTimeout(checkIdle, 30000); }
  }
  ['click', 'keydown', 'touchstart'].forEach(e => document.addEventListener(e, resetIdle, { passive: true }));
  document.addEventListener('mousemove', () => { const n = Date.now(); if (n - lastMove > 1000) { lastMove = n; resetIdle(); } }, { passive: true });

  /* ── Connection + leaving the page ── */
  let offAt = 0;
  window.addEventListener('offline', () => { offAt = Date.now(); setState('offline'); TTS.say('Internet connection lost.'); toast('You are offline. Your answers are kept and will be saved when you reconnect.', 'bad'); });
  window.addEventListener('online', () => {
    const secs = offAt ? Math.round((Date.now() - offAt) / 1000) : 0; offAt = 0;
    toast('You are back online.', 'ok');
    ev('offline', 'for ' + secs + ' seconds'); ev('online');
    Q.flush();
    if (!cam.stopped && cam.status !== 'live') cam.start(); else if (!cam.linked && cam.liveTrack()) cam.connect();
  });
  const guard = e => { e.preventDefault(); e.returnValue = ''; };
  window.addEventListener('beforeunload', guard);
  window.addEventListener('pagehide', () => cam.stop());

  /* ── Start ── */
  Q.load();
  Q.map.forEach(c => {   // changes that never reached the server (crash while offline) go back on screen and are sent now
    const i = slides.findIndex(s => +s.dataset.qid === c.q); if (i < 0) return;
    if (c.a !== undefined) { const r = $(`input[value="${c.a}"]`, slides[i]); if (r) r.checked = true; }
    if (c.f !== undefined) c.f ? S.flags.add(i) : S.flags.delete(i);
  });
  const firstOpen = slides.findIndex((_, i) => !isAnswered(i));
  goTo(firstOpen < 0 ? 0 : firstOpen);
  $('#clockText').textContent = mmss(cfg.remaining);
  if (cfg.remaining <= 0) { timeUp(); return; }
  if (Q.map.size) { setState('saving'); Q.flush(); }
  S.totalEnd = Date.now() + cfg.remaining * 1000;
  S.tickId = setInterval(tick, 250);
  setInterval(async () => {           // keeps the clock honest and tells the teacher the student is still here
    if (S.done) return;
    const d = await api({ action: 'ping' });
    if (d.ok) syncLeft(d.left);
    else if (d.code === 'expired') timeUp();
    else if (d.code === 'closed' || d.code === 'auth') reloadPage();
  }, cfg.pingMs);
  cam.start();
  TTS.say(cfg.resumed ? 'Welcome back. Your saved answers have been restored. You have ' + N + ' questions.' : 'Your examination has started. You have ' + N + ' questions. Good luck!');
  resetIdle();
})();
</script>
<?php endif; ?>
</body>
</html>