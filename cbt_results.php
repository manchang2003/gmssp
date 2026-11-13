<?php
declare(strict_types=1);

/* ════════════════════════════════════════════════════════════════
   CBT Management Panel (teacher side): exams, questions, sessions,
   live monitor and results in one page.
   Controls every feature the student portal reads:
     exam PIN, schedule window, duration, question limit, retake,
     camera requirement, result release, question status/difficulty/image.
   Requires PHP 8.0+, configure.php ($conn = mysqli) and the columns from
   cbt_migration.sql (cbt_exams.access_pin, camera_required, results_released,
   max_questions, allow_retake, start_at, end_at; cbt_questions.status,
   difficulty, question_image; cbt_sessions.exam_id, attempt_no, last_seen_at).
════════════════════════════════════════════════════════════════ */

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => !empty($_SERVER['HTTPS']),
    ]);
    session_start();
}
require_once 'configure.php';
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$conn->set_charset('utf8mb4');

$teacher = $_SESSION['teacher_username'] ?? null;
if (empty($teacher)) { header('Location: login.php'); exit; }

/* ── Settings ─────────────────────────────────────────────────── */
const MAX_CA   = 10;   // max for each of Assignment 1, Assignment 2, Test 1, Test 2
const MAX_CBT  = 60;   // CBT exam is scored out of 60 (cbt_sessions.exam_score_60)
const CLASSES  = ['JSS 1', 'JSS 2', 'JSS 3', 'SS1', 'SS2', 'SS3'];
const TERMS    = ['First Term', 'Second Term', 'Third Term'];
const TABS     = ['overview', 'exams', 'questions', 'sessions', 'monitor', 'results'];
const LEVELS   = ['Easy', 'Medium', 'Hard'];
const PER_PAGE = 25;
const STATS_TTL = 20;
const LIST_TTL  = 60;
const IDLE_WARN = 90;  // seconds without a ping before the monitor marks a student as quiet

/* ── Security headers ─────────────────────────────────────────── */
$nonce = base64_encode(random_bytes(16));
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header("Content-Security-Policy: default-src 'self'; script-src 'nonce-$nonce'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'");
if (!empty($_SERVER['HTTPS'])) header('Strict-Transport-Security: max-age=31536000');

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
$csrf  = $_SESSION['csrf'];
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

/* ── Helpers ──────────────────────────────────────────────────── */
function h($v): string { return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function db_all(mysqli $c, string $sql, string $types = '', array $p = []): array {
    $st = $c->prepare($sql);
    if ($types !== '') $st->bind_param($types, ...$p);
    $st->execute();
    $rs   = $st->get_result();
    $rows = $rs ? $rs->fetch_all(MYSQLI_ASSOC) : [];
    $st->close();
    return $rows;
}
function db_one(mysqli $c, string $sql, string $types = '', array $p = []): ?array {
    return db_all($c, $sql, $types, $p)[0] ?? null;
}
function db_run(mysqli $c, string $sql, string $types = '', array $p = []): int {
    $st = $c->prepare($sql);
    if ($types !== '') $st->bind_param($types, ...$p);
    $st->execute();
    $n = $st->affected_rows;
    $st->close();
    return (int)$n;
}

function self_url(string $tab = 'overview', array $q = []): string {
    return basename($_SERVER['SCRIPT_NAME']) . '?' . http_build_query(['tab' => $tab] + $q);
}
function go(string $tab, array $q, string $type, string $text): void {
    $_SESSION['flash'] = ['type' => $type, 'text' => $text];
    header('Location: ' . self_url($tab, $q));
    exit;
}

/* Cache: APCu when available (shared), session otherwise. */
function cache_apcu(): bool { return function_exists('apcu_fetch') && filter_var(ini_get('apc.enabled'), FILTER_VALIDATE_BOOLEAN); }
function cache_ver(string $t): int {
    if (cache_apcu()) { $v = apcu_fetch("cbtp:v:$t", $ok); if (!$ok) { $v = 1; apcu_store("cbtp:v:$t", 1); } return (int)$v; }
    return (int)($_SESSION['_cver'] ?? 1);
}
function cache_bust(string $t): void {
    if (cache_apcu()) { apcu_inc("cbtp:v:$t", 1, $ok); if (!$ok) apcu_store("cbtp:v:$t", 2); }
    else { $_SESSION['_cver'] = (int)($_SESSION['_cver'] ?? 1) + 1; $_SESSION['_cache'] = []; }
}
function cache_get(string $t, string $key, int $ttl, callable $fn) {
    $k = "cbtp:$t:" . cache_ver($t) . ":$key";
    if (cache_apcu()) {
        $v = apcu_fetch($k, $ok);
        if ($ok) return $v;
        $v = $fn(); apcu_store($k, $v, $ttl); return $v;
    }
    $c = $_SESSION['_cache'][$k] ?? null;
    if ($c && $c['t'] > time()) return $c['v'];
    $v = $fn();
    $_SESSION['_cache'][$k] = ['v' => $v, 't' => time() + $ttl];
    return $v;
}

function csv_safe($v): string {
    $v = (string)$v;
    return ($v !== '' && strpos("=+-@\t\r", $v[0]) !== false) ? "'" . $v : $v;
}
function csv_out(string $name, array $head, iterable $rows): void {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $name . '"');
    header('Cache-Control: private, no-store');
    $o = fopen('php://output', 'w');
    fwrite($o, "\xEF\xBB\xBF");
    fputcsv($o, $head, ',', '"', '');
    foreach ($rows as $r) fputcsv($o, array_map('csv_safe', $r), ',', '"', '');
    fclose($o);
    exit;
}
function slug(string $s): string { return trim(preg_replace('/[^A-Za-z0-9]+/', '_', $s), '_'); }

function ic(string $n): string { return '<svg class="ic" aria-hidden="true"><use href="#i-' . $n . '"/></svg>'; }
function hidden(string $do, string $tab, array $extra = []): string {
    global $csrf;
    $o = '<input type="hidden" name="csrf" value="' . h($csrf) . '"><input type="hidden" name="do" value="' . h($do) . '"><input type="hidden" name="tab" value="' . h($tab) . '">';
    foreach ($extra as $k => $v) $o .= '<input type="hidden" name="' . h($k) . '" value="' . h($v) . '">';
    return $o;
}

/* Exam PIN: students sign in with username + this PIN, and the portal finds the exam
   by (class, PIN) among active exams, so a PIN must be unique inside a class. */
function pin_taken(mysqli $c, string $class, string $pin, int $exceptId): bool {
    return (bool)db_one($c, "SELECT id FROM cbt_exams WHERE LOWER(class_level) = LOWER(?) AND is_active = 1 AND access_pin = ? AND id <> ? LIMIT 1", 'ssi', [$class, $pin, $exceptId]);
}
function make_pin(mysqli $c, string $class, int $exceptId = 0): string {
    for ($i = 0; $i < 30; $i++) {
        $p = (string)random_int(100000, 999999);
        if (!pin_taken($c, $class, $p, $exceptId)) return $p;
    }
    return (string)random_int(10000000, 99999999);
}
/* datetime-local ("2026-11-12T09:30") → MySQL datetime, '' → null, false → invalid */
function parse_dt(string $v) {
    $v = trim($v);
    if ($v === '') return null;
    $d = DateTime::createFromFormat('Y-m-d\TH:i', $v) ?: DateTime::createFromFormat('Y-m-d H:i:s', $v);
    return $d ? $d->format('Y-m-d H:i:s') : false;
}
function image_ok(string $v): bool {
    if ($v === '') return true;
    if (strpos($v, '..') !== false || mb_strlen($v) > 255) return false;
    return (bool)preg_match('~^(https://[^\s"\'<>]+|[A-Za-z0-9_\-/]+\.(png|jpe?g|gif|webp))$~i', $v);
}
function exam_state(array $e): array {
    if ((int)$e['is_active'] !== 1)  return ['Closed', 'b-grey'];
    if (!empty($e['not_open']))      return ['Scheduled', 'b-amber'];
    if (!empty($e['closed']))        return ['Ended', 'b-red'];
    return ['Open', 'b-green'];
}

/* ── Data that every request needs ───────────────────────────── */
$exams = cache_get($teacher, 'exams', LIST_TTL, fn() => db_all($conn,
    "SELECT e.*,
            (e.start_at IS NOT NULL AND e.start_at > NOW()) AS not_open,
            (e.end_at IS NOT NULL AND e.end_at < NOW()) AS closed,
            (SELECT COUNT(*) FROM cbt_questions q WHERE q.exam_id = e.id) AS q_count,
            (SELECT COUNT(*) FROM cbt_questions q WHERE q.exam_id = e.id AND q.status = 'Active') AS q_active,
            (SELECT COALESCE(SUM(q.marks),0) FROM cbt_questions q WHERE q.exam_id = e.id AND q.status = 'Active') AS q_marks,
            (SELECT COUNT(*) FROM cbt_sessions s WHERE s.exam_id = e.id) AS s_count
     FROM cbt_exams e WHERE e.teacher_username = ? ORDER BY e.created_at DESC", 's', [$teacher]));
$examsById = [];
foreach ($exams as $e) $examsById[(int)$e['id']] = $e;

/* ══════════════════════════════════════════════════════════════
   WRITE ACTIONS (POST only, CSRF checked, prepared statements)
══════════════════════════════════════════════════════════════ */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $do      = (string)($_POST['do'] ?? '');
    $retTab  = in_array($_POST['tab'] ?? '', TABS, true) ? $_POST['tab'] : 'overview';
    $examId  = (int)($_POST['exam_id'] ?? 0);
    $retQ    = $examId ? ['exam_id' => $examId] : [];

    if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
        go($retTab, $retQ, 'error', 'Your session expired. Reload the page and try again.');
    }

    try {
        switch ($do) {

        /* ─ Exams ─ */
        case 'exam_add':
            $course = trim((string)($_POST['course_name'] ?? ''));
            $class  = (string)($_POST['class_level'] ?? '');
            $term   = (string)($_POST['term'] ?? '');
            $dur    = max(5, min(180, (int)($_POST['duration_minutes'] ?? 30)));
            if ($course === '' || mb_strlen($course) > 100 || !in_array($class, CLASSES, true) || !in_array($term, TERMS, true)) {
                go('exams', [], 'error', 'Enter a subject, class and term to create the exam.');
            }
            $pin = make_pin($conn, $class);
            // An exam that belongs to another teacher is never taken over.
            $n = db_run($conn,
                "INSERT INTO cbt_exams (course_name, class_level, term, teacher_username, duration_minutes, access_pin)
                 VALUES (?,?,?,?,?,?)
                 ON DUPLICATE KEY UPDATE
                   is_active = IF(teacher_username = VALUES(teacher_username), 1, is_active),
                   duration_minutes = IF(teacher_username = VALUES(teacher_username), VALUES(duration_minutes), duration_minutes)",
                'ssssis', [$course, $class, $term, $teacher, $dur, $pin]);
            cache_bust($teacher);
            go('exams', [], $n > 0 ? 'ok' : 'warn', $n > 0 ? 'Exam saved. Share its PIN with the class when you are ready.' : 'This exam already exists.');

        case 'exam_toggle': {
            $ex = $examsById[$examId] ?? null;
            if (!$ex) go('exams', [], 'error', 'Exam not found.');
            $opening = (int)$ex['is_active'] === 0;
            if ($opening && ($ex['access_pin'] === null || $ex['access_pin'] === '' || pin_taken($conn, $ex['class_level'], (string)$ex['access_pin'], $examId))) {
                db_run($conn, "UPDATE cbt_exams SET access_pin = ? WHERE id = ? AND teacher_username = ?", 'sis', [make_pin($conn, $ex['class_level'], $examId), $examId, $teacher]);
            }
            db_run($conn, "UPDATE cbt_exams SET is_active = 1 - is_active WHERE id = ? AND teacher_username = ?", 'is', [$examId, $teacher]);
            cache_bust($teacher);
            go('exams', [], 'ok', $opening ? 'Exam opened to students.' : 'Exam closed. Students can no longer sign in to it.');
        }

        case 'exam_settings': {
            $ex = $examsById[$examId] ?? null;
            if (!$ex) go('exams', [], 'error', 'Exam not found.');
            $dur   = max(5, min(180, (int)($_POST['duration_minutes'] ?? 30)));
            $maxQ  = max(0, min(200, (int)($_POST['max_questions'] ?? 0)));
            $cam   = (int)($_POST['camera_required'] ?? 0) === 1 ? 1 : 0;
            $rel   = (int)($_POST['results_released'] ?? 0) === 1 ? 1 : 0;
            $retake= (int)($_POST['allow_retake'] ?? 0) === 1 ? 1 : 0;
            $start = parse_dt((string)($_POST['start_at'] ?? ''));
            $end   = parse_dt((string)($_POST['end_at'] ?? ''));
            $pin   = trim((string)($_POST['access_pin'] ?? ''));
            if ($start === false || $end === false) go('exams', [], 'error', 'One of the dates is not valid.');
            if ($start !== null && $end !== null && $end <= $start) go('exams', [], 'error', 'The closing time must be after the opening time.');
            if (!preg_match('/^[A-Za-z0-9]{4,12}$/', $pin)) go('exams', [], 'error', 'The PIN must be 4 to 12 letters or numbers.');
            if (pin_taken($conn, $ex['class_level'], $pin, $examId)) go('exams', [], 'error', 'Another open exam for ' . $ex['class_level'] . ' already uses that PIN. Choose a different one.');
            db_run($conn,
                "UPDATE cbt_exams SET duration_minutes=?, max_questions=?, camera_required=?, results_released=?, allow_retake=?, start_at=?, end_at=?, access_pin=?
                 WHERE id=? AND teacher_username=?",
                'iiiiisssis', [$dur, $maxQ, $cam, $rel, $retake, $start, $end, $pin, $examId, $teacher]);
            cache_bust($teacher);
            go('exams', [], 'ok', 'Exam settings saved.');
        }

        case 'exam_pin': {
            $ex = $examsById[$examId] ?? null;
            if (!$ex) go('exams', [], 'error', 'Exam not found.');
            db_run($conn, "UPDATE cbt_exams SET access_pin = ? WHERE id = ? AND teacher_username = ?", 'sis', [make_pin($conn, $ex['class_level'], $examId), $examId, $teacher]);
            cache_bust($teacher);
            go('exams', [], 'ok', 'New PIN created. Students already sitting the exam are not affected.');
        }

        case 'exam_release': {
            $ex = $examsById[$examId] ?? null;
            if (!$ex) go($retTab, [], 'error', 'Exam not found.');
            $new = (int)$ex['results_released'] === 1 ? 0 : 1;
            db_run($conn, "UPDATE cbt_exams SET results_released = ? WHERE id = ? AND teacher_username = ?", 'iis', [$new, $examId, $teacher]);
            cache_bust($teacher);
            go($retTab, $retQ, 'ok', $new ? 'Scores are now shown to students when they submit.' : 'Scores are hidden from students.');
        }

        case 'exam_delete':
            $ex = $examsById[$examId] ?? null;
            if (!$ex) go('exams', [], 'error', 'Exam not found.');
            if ((int)$ex['s_count'] > 0) {
                go('exams', [], 'error', 'This exam already has student attempts, so it cannot be deleted. Close it instead.');
            }
            $conn->begin_transaction();
            db_run($conn, "DELETE FROM cbt_questions WHERE exam_id = ? AND teacher_username = ?", 'is', [$examId, $teacher]);
            db_run($conn, "DELETE FROM cbt_exams WHERE id = ? AND teacher_username = ?", 'is', [$examId, $teacher]);
            $conn->commit();
            cache_bust($teacher);
            go('exams', [], 'ok', 'Exam and its questions deleted.');

        /* ─ Questions ─ */
        case 'q_save':
            $qid  = (int)($_POST['id'] ?? 0);
            $f    = [];
            foreach (['question_text', 'option_a', 'option_b', 'option_c', 'option_d'] as $k) $f[$k] = trim((string)($_POST[$k] ?? ''));
            $ans   = (string)($_POST['correct_answer'] ?? '');
            $marks = max(1, min(10, (int)($_POST['marks'] ?? 1)));
            $diff  = in_array($_POST['difficulty'] ?? '', LEVELS, true) ? $_POST['difficulty'] : 'Medium';
            $stat  = ($_POST['status'] ?? 'Active') === 'Inactive' ? 'Inactive' : 'Active';
            $img   = trim((string)($_POST['question_image'] ?? ''));
            if (in_array('', $f, true) || !in_array($ans, ['A', 'B', 'C', 'D'], true)) {
                go('questions', $retQ, 'error', 'Fill in the question, all four options and the correct answer.');
            }
            if (!image_ok($img)) go('questions', $retQ, 'error', 'The picture must be a file path like images/q1.png or an https link to an image.');
            $img = $img === '' ? null : $img;
            if ($qid > 0) {
                db_run($conn,
                    "UPDATE cbt_questions SET question_text=?, option_a=?, option_b=?, option_c=?, option_d=?, correct_answer=?, marks=?, difficulty=?, status=?, question_image=?
                     WHERE id=? AND teacher_username=?",
                    'ssssssisssis', [$f['question_text'], $f['option_a'], $f['option_b'], $f['option_c'], $f['option_d'], $ans, $marks, $diff, $stat, $img, $qid, $teacher]);
                $msg = 'Question updated.';
            } else {
                $ex = $examsById[$examId] ?? null;
                if (!$ex) go('questions', [], 'error', 'Choose an exam first.');
                db_run($conn,
                    "INSERT INTO cbt_questions (exam_id, teacher_username, course_name, class_level, term, question_text, option_a, option_b, option_c, option_d, correct_answer, marks, difficulty, status, question_image)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    'issssssssssisss', [$examId, $teacher, $ex['course_name'], $ex['class_level'], $ex['term'], $f['question_text'], $f['option_a'], $f['option_b'], $f['option_c'], $f['option_d'], $ans, $marks, $diff, $stat, $img]);
                $msg = 'Question added.';
            }
            cache_bust($teacher);
            go('questions', $retQ, 'ok', $msg);

        case 'q_status':
            db_run($conn, "UPDATE cbt_questions SET status = IF(status = 'Active', 'Inactive', 'Active') WHERE id = ? AND teacher_username = ?", 'is', [(int)($_POST['id'] ?? 0), $teacher]);
            cache_bust($teacher);
            go('questions', $retQ, 'ok', 'Question status changed. Only Active questions are given to students.');

        case 'q_delete':
            db_run($conn, "DELETE FROM cbt_questions WHERE id = ? AND teacher_username = ?", 'is', [(int)($_POST['id'] ?? 0), $teacher]);
            cache_bust($teacher);
            go('questions', $retQ, 'ok', 'Question deleted.');

        case 'q_duplicate':
            db_run($conn,
                "INSERT INTO cbt_questions (exam_id, teacher_username, course_name, class_level, term, question_text, option_a, option_b, option_c, option_d, correct_answer, marks, difficulty, status, question_image)
                 SELECT exam_id, teacher_username, course_name, class_level, term, question_text, option_a, option_b, option_c, option_d, correct_answer, marks, difficulty, status, question_image
                 FROM cbt_questions WHERE id = ? AND teacher_username = ?", 'is', [(int)($_POST['id'] ?? 0), $teacher]);
            cache_bust($teacher);
            go('questions', $retQ, 'ok', 'Question duplicated.');

        case 'q_import':
            $ex = $examsById[$examId] ?? null;
            if (!$ex) go('questions', [], 'error', 'Choose an exam first.');
            $file = $_FILES['csv'] ?? null;
            if (!$file || $file['error'] !== UPLOAD_ERR_OK || $file['size'] > 1048576) {
                go('questions', $retQ, 'error', 'Upload a CSV file smaller than 1 MB.');
            }
            $fh = fopen($file['tmp_name'], 'r');
            $ins = $conn->prepare(
                "INSERT INTO cbt_questions (exam_id, teacher_username, course_name, class_level, term, question_text, option_a, option_b, option_c, option_d, correct_answer, marks, difficulty, status, question_image)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'Active',?)");
            $added = $skipped = 0;
            $conn->begin_transaction();
            while (($r = fgetcsv($fh, 0, ',', '"', '')) !== false && $added < 500) {
                if (count($r) < 6) { $skipped++; continue; }
                $r   = array_map(fn($x) => trim((string)$x), $r);
                $ans = strtoupper($r[5]);
                if (!in_array($ans, ['A', 'B', 'C', 'D'], true)) { $skipped++; continue; }   // also skips the header row
                if ($r[0] === '' || $r[1] === '' || $r[2] === '' || $r[3] === '' || $r[4] === '') { $skipped++; continue; }
                $m    = max(1, min(10, (int)($r[6] ?? 1)));
                $dRaw = ucfirst(strtolower($r[7] ?? ''));
                $d    = in_array($dRaw, LEVELS, true) ? $dRaw : 'Medium';
                $img  = $r[8] ?? '';
                if (!image_ok($img)) $img = '';
                $imgV = $img === '' ? null : $img;
                $ins->bind_param('issssssssssiss', $examId, $teacher, $ex['course_name'], $ex['class_level'], $ex['term'], $r[0], $r[1], $r[2], $r[3], $r[4], $ans, $m, $d, $imgV);
                $ins->execute();
                $added++;
            }
            $conn->commit();
            $ins->close(); fclose($fh);
            cache_bust($teacher);
            go('questions', $retQ, $added ? 'ok' : 'warn', "$added question(s) imported" . ($skipped ? ", $skipped row(s) skipped." : '.'));

        /* ─ Results ─ */
        case 'results_pull':
        case 'results_save':
        case 'results_send':
            $exam = $examsById[$examId] ?? null;
            if (!$exam) go('results', [], 'error', 'Choose an exam first.');

            if ($do === 'results_pull') {
                // Latest finished attempt per student. Older sessions without an exam_id are matched by subject, class and term.
                $found = db_all($conn,
                    "SELECT s.student_username, s.exam_score_60, u.full_name
                     FROM cbt_sessions s
                     LEFT JOIN users u ON u.student_username COLLATE utf8mb4_unicode_ci = s.student_username COLLATE utf8mb4_unicode_ci
                     WHERE s.student_username IS NOT NULL AND s.id IN (
                        SELECT MAX(id) FROM cbt_sessions
                        WHERE teacher_username = ?
                          AND (exam_id = ? OR (exam_id IS NULL AND course_name = ? AND class_level = ? AND term = ?))
                          AND status IN ('completed','timed_out')
                        GROUP BY student_username)",
                    'sisss', [$teacher, $examId, $exam['course_name'], $exam['class_level'], $exam['term']]);

                $added = $updated = $locked = 0;
                $conn->begin_transaction();
                foreach ($found as $r) {
                    $score = max(0, min(MAX_CBT, (int)$r['exam_score_60']));
                    $name  = $r['full_name'] ?: $r['student_username'];
                    $row = db_one($conn,
                        "SELECT id, fm_verified FROM results WHERE teacher_username=? AND student_username=? AND course_name=? AND class_level=? AND term=? LIMIT 1",
                        'sssss', [$teacher, $r['student_username'], $exam['course_name'], $exam['class_level'], $exam['term']]);
                    if ($row) {
                        if ((int)$row['fm_verified'] === 1) { $locked++; continue; }
                        db_run($conn, "UPDATE results SET exam=? WHERE id=?", 'ii', [$score, (int)$row['id']]);
                        $updated++;
                    } else {
                        db_run($conn,
                            "INSERT INTO results (teacher_username, student_username, full_name, class_level, course_name, term, exam) VALUES (?,?,?,?,?,?,?)",
                            'ssssssi', [$teacher, $r['student_username'], $name, $exam['class_level'], $exam['course_name'], $exam['term'], $score]);
                        $added++;
                    }
                }
                $conn->commit();
                if ($added + $updated + $locked === 0) go('results', $retQ, 'warn', 'No finished CBT attempts were found for this exam yet.');
                go('results', $retQ, 'ok', "CBT scores picked up: $added added, $updated refreshed" . ($locked ? ", $locked skipped (already verified by the form master)." : '.'));
            }

            // save / send
            $clamp = fn($v) => max(0, min(MAX_CA, (int)$v));
            $n = 0;
            $conn->begin_transaction();
            foreach (($_POST['row'] ?? []) as $rid => $f) {
                if (!is_array($f)) continue;
                db_run($conn,
                    "UPDATE results SET assignment1=?, assignment2=?, test1=?, test2=?
                     WHERE id=? AND teacher_username=? AND course_name=? AND class_level=? AND term=? AND fm_verified=0",
                    'iiiiissss', [$clamp($f['assignment1'] ?? 0), $clamp($f['assignment2'] ?? 0), $clamp($f['test1'] ?? 0), $clamp($f['test2'] ?? 0),
                                  (int)$rid, $teacher, $exam['course_name'], $exam['class_level'], $exam['term']]);
                $n++;
            }
            if ($do === 'results_send') {
                db_run($conn,
                    "UPDATE results SET approved=0, fm_verified=0, date_uploaded=NOW()
                     WHERE teacher_username=? AND course_name=? AND class_level=? AND term=? AND fm_verified=0",
                    'ssss', [$teacher, $exam['course_name'], $exam['class_level'], $exam['term']]);
            }
            $conn->commit();
            go('results', $retQ, 'ok', $do === 'results_send'
                ? "Results sent. $n student record(s) with CA and CBT scores are now with the form master."
                : "Draft saved for $n student(s). Nothing has been sent yet.");

        default:
            go($retTab, $retQ, 'error', 'Unknown action.');
        }
    } catch (Throwable $e) {
        try { $conn->rollback(); } catch (Throwable $ignore) {}
        error_log('[cbt_panel] ' . $e->getMessage());
        go($retTab, $retQ, 'error', 'Something went wrong and nothing was changed. Please try again.');
    }
}

/* ══════════════════════════════════════════════════════════════
   JSON ENDPOINTS + CSV EXPORTS (GET)
══════════════════════════════════════════════════════════════ */
function stats_for(mysqli $c, string $t, array $exams): array {
    $s = db_one($c,
        "SELECT COUNT(*) AS total,
                COALESCE(SUM(status='completed'),0) AS completed,
                COALESCE(SUM(status='in_progress'),0) AS in_progress,
                COALESCE(SUM(status='timed_out'),0) AS timed_out,
                ROUND(AVG(CASE WHEN status <> 'in_progress' THEN exam_score_60 END),1) AS avg_score
         FROM cbt_sessions WHERE teacher_username = ?", 's', [$t]) ?? [];
    return [
        'exams'       => count($exams),
        'active'      => count(array_filter($exams, fn($e) => (int)$e['is_active'] === 1)),
        'questions'   => array_sum(array_map(fn($e) => (int)$e['q_active'], $exams)),
        'sessions'    => (int)($s['total'] ?? 0),
        'completed'   => (int)($s['completed'] ?? 0),
        'in_progress' => (int)($s['in_progress'] ?? 0),
        'timed_out'   => (int)($s['timed_out'] ?? 0),
        'avg_score'   => $s['avg_score'] !== null ? (float)$s['avg_score'] : null,
    ];
}
function live_for(mysqli $c, string $t): array {
    return db_all($c,
        "SELECT cs.id AS session_id, cs.student_username, cs.course_name, cs.class_level, cs.term, cs.attempt_no,
                TIMESTAMPDIFF(SECOND, cs.last_seen_at, NOW()) AS idle_secs,
                TIMESTAMPDIFF(SECOND, NOW(), cs.deadline_at) AS left_secs,
                u.full_name
         FROM cbt_sessions cs
         LEFT JOIN users u ON u.student_username COLLATE utf8mb4_unicode_ci = cs.student_username COLLATE utf8mb4_unicode_ci
         WHERE cs.teacher_username = ? AND cs.status = 'in_progress' ORDER BY cs.start_time DESC", 's', [$t]);
}

$api = $_GET['api'] ?? '';
if ($api === 'live') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: private, no-store');
    echo json_encode(['sessions' => array_map(fn($r) => [
        'session_id' => (int)$r['session_id'],
        'name'       => $r['full_name'] ?: $r['student_username'],
        'meta'       => $r['course_name'] . ' · ' . $r['class_level'] . ' · ' . $r['term'] . ((int)$r['attempt_no'] > 1 ? ' · attempt ' . (int)$r['attempt_no'] : ''),
        'idle'       => $r['idle_secs'] !== null ? max(0, (int)$r['idle_secs']) : null,
        'left'       => $r['left_secs'] !== null ? max(0, (int)$r['left_secs']) : null,
    ], live_for($conn, $teacher))], JSON_UNESCAPED_UNICODE);
    exit;
}
if ($api === 'stats') {
    $data = cache_get($teacher, 'stats', STATS_TTL, fn() => stats_for($conn, $teacher, $exams));
    $json = json_encode($data);
    $etag = '"' . md5($json) . '"';
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: private, max-age=0, must-revalidate');
    header("ETag: $etag");
    if (trim((string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? '')) === $etag) { http_response_code(304); exit; }
    echo $json;
    exit;
}

$tab    = in_array($_GET['tab'] ?? '', TABS, true) ? $_GET['tab'] : 'overview';
$selId  = (int)($_GET['exam_id'] ?? 0);
$sel    = $examsById[$selId] ?? null;
$export = $_GET['export'] ?? '';

/* Sessions filter (shared by the page and its CSV export) */
$fStatus = in_array($_GET['status'] ?? '', ['completed', 'in_progress', 'timed_out'], true) ? $_GET['status'] : '';
$fQ      = trim((string)($_GET['q'] ?? ''));
function sessions_query(string $teacher, string $status, string $q): array {
    $where = 's.teacher_username = ?'; $types = 's'; $p = [$teacher];
    if ($status !== '') { $where .= ' AND s.status = ?'; $types .= 's'; $p[] = $status; }
    if ($q !== '') {
        $like = '%' . addcslashes($q, '%_\\') . '%';
        $where .= ' AND (s.student_username LIKE ? OR u.full_name LIKE ? OR s.course_name LIKE ?)';
        $types .= 'sss'; array_push($p, $like, $like, $like);
    }
    $from = "FROM cbt_sessions s LEFT JOIN users u ON u.student_username COLLATE utf8mb4_unicode_ci = s.student_username COLLATE utf8mb4_unicode_ci WHERE $where";
    return [$from, $types, $p];
}

if ($export === 'template') {
    csv_out('questions_template.csv', ['question', 'option_a', 'option_b', 'option_c', 'option_d', 'correct_answer', 'marks', 'difficulty', 'image'],
        [['What is 2 + 2?', '3', '4', '5', '6', 'B', '1', 'Easy', '']]);
}
if ($export === 'questions' && $sel) {
    $rows = db_all($conn, "SELECT question_text, option_a, option_b, option_c, option_d, correct_answer, marks, difficulty, COALESCE(question_image,'') AS question_image FROM cbt_questions WHERE exam_id=? AND teacher_username=? ORDER BY id", 'is', [$selId, $teacher]);
    csv_out('questions_' . slug($sel['course_name'] . '_' . $sel['class_level'] . '_' . $sel['term']) . '.csv',
        ['question', 'option_a', 'option_b', 'option_c', 'option_d', 'correct_answer', 'marks', 'difficulty', 'image'], array_map('array_values', $rows));
}
if ($export === 'sessions') {
    [$from, $types, $p] = sessions_query($teacher, $fStatus, $fQ);
    $rows = db_all($conn, "SELECT s.student_username, u.full_name, s.course_name, s.class_level, s.term, s.attempt_no, s.raw_score, s.total_questions, s.exam_score_60, s.status, s.start_time, s.end_time $from ORDER BY s.start_time DESC LIMIT 5000", $types, $p);
    csv_out('sessions.csv', ['Username', 'Full name', 'Subject', 'Class', 'Term', 'Attempt', 'Raw score', 'Questions', 'Score /60', 'Status', 'Started', 'Ended'], array_map('array_values', $rows));
}

/* ── Tab data ─────────────────────────────────────────────────── */
$stats = cache_get($teacher, 'stats', STATS_TTL, fn() => stats_for($conn, $teacher, $exams));
$liveCount = (int)(db_one($conn, "SELECT COUNT(*) AS c FROM cbt_sessions WHERE teacher_username = ? AND status = 'in_progress'", 's', [$teacher])['c'] ?? 0);

$questions = $sheet = $sessionRows = $recent = [];
$sessionTotal = $pages = 0; $page = 1;
$rank = []; $resStats = null;

if ($tab === 'overview') {
    $recent = db_all($conn,
        "SELECT s.student_username, u.full_name, s.course_name, s.class_level, s.exam_score_60, s.status, s.start_time
         FROM cbt_sessions s LEFT JOIN users u ON u.student_username COLLATE utf8mb4_unicode_ci = s.student_username COLLATE utf8mb4_unicode_ci
         WHERE s.teacher_username = ? ORDER BY s.start_time DESC LIMIT 6", 's', [$teacher]);
}
if ($tab === 'questions' && $sel) {
    $questions = db_all($conn, "SELECT * FROM cbt_questions WHERE exam_id = ? AND teacher_username = ? ORDER BY id", 'is', [$selId, $teacher]);
}
if ($tab === 'sessions') {
    [$from, $types, $p] = sessions_query($teacher, $fStatus, $fQ);
    $sessionTotal = (int)(db_one($conn, "SELECT COUNT(*) AS c $from", $types, $p)['c'] ?? 0);
    $pages = max(1, (int)ceil($sessionTotal / PER_PAGE));
    $page  = max(1, min($pages, (int)($_GET['page'] ?? 1)));
    $sessionRows = db_all($conn, "SELECT s.*, u.full_name $from ORDER BY s.start_time DESC LIMIT ? OFFSET ?",
        $types . 'ii', array_merge($p, [PER_PAGE, ($page - 1) * PER_PAGE]));
}
if ($tab === 'results' && $sel) {
    $sheet = db_all($conn, "SELECT * FROM results WHERE teacher_username=? AND course_name=? AND class_level=? AND term=? ORDER BY full_name",
        'ssss', [$teacher, $sel['course_name'], $sel['class_level'], $sel['term']]);

    if ($export === 'results') {
        csv_out('results_' . slug($sel['course_name'] . '_' . $sel['class_level'] . '_' . $sel['term']) . '.csv',
            ['Username', 'Full name', 'Class', 'Subject', 'Term', 'Assignment 1', 'Assignment 2', 'Test 1', 'Test 2', 'CBT exam', 'Total', 'Grade'],
            array_map(fn($r) => [$r['student_username'], $r['full_name'], $r['class_level'], $r['course_name'], $r['term'], $r['assignment1'], $r['assignment2'], $r['test1'], $r['test2'], $r['exam'], $r['total'], $r['grade']], $sheet));
    }
    // Position in class (ties share a position)
    $totals = array_map(fn($r) => (int)$r['total'], $sheet);
    $sorted = $totals; rsort($sorted);
    foreach ($sheet as $r) $rank[(int)$r['id']] = array_search((int)$r['total'], $sorted, true) + 1;
    if ($sheet) $resStats = ['avg' => round(array_sum($totals) / count($totals), 1), 'max' => max($totals), 'min' => min($totals)];
}
$locked = count(array_filter($sheet, fn($r) => (int)$r['fm_verified'] === 1));

$titles = [
    'overview'  => ['Overview',     'How your exams are going right now.'],
    'exams'     => ['Exams',        'Create exams, set the PIN, schedule and rules, and decide which ones students can sit.'],
    'questions' => ['Questions',    'Write, import and review the questions for an exam.'],
    'sessions'  => ['Sessions',     'Every attempt students have made on your exams.'],
    'monitor'   => ['Live monitor', 'Watch students who are sitting an exam right now.'],
    'results'   => ['Results',      'Combine CBT scores with continuous assessment and send them to the form master.'],
];
$badge = fn(string $s) => match ($s) { 'completed' => 'b-blue', 'in_progress' => 'b-amber', 'timed_out' => 'b-red', default => 'b-grey' };
$fmtDt = fn($v) => $v ? date('D j M, g:i a', strtotime((string)$v)) : '';
$inDt  = fn($v) => $v ? date('Y-m-d\TH:i', strtotime((string)$v)) : '';

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: private, no-store');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex, nofollow">
<title><?= h($titles[$tab][0]) ?> · CBT panel</title>
<style>
  :root {
    --canvas:#f5f5f7; --surface:#fff; --raised:#fafafb; --ink:#1c1c1e; --ink-2:#55555c; --ink-3:#8a8a93;
    --line:#e7e7ea; --line-2:#d6d6db; --accent:#0c7ff2; --accent-ink:#fff; --accent-soft:#e8f2fe;
    --ok:#17803d; --ok-soft:#e3f5ea; --warn:#9a5b00; --warn-soft:#fff3dc; --bad:#c42b1c; --bad-soft:#fdeceb;
    --shadow:0 1px 2px rgba(16,16,24,.06),0 4px 16px rgba(16,16,24,.06); --shadow-lg:0 12px 40px rgba(16,16,24,.22);
    --r-s:6px; --r-m:8px; --r-l:12px;
    --font:Inter,ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
  }
  :root[data-theme="dark"] {
    --canvas:#141416; --surface:#1d1d20; --raised:#232327; --ink:#f2f2f4; --ink-2:#b4b4bc; --ink-3:#7f7f89;
    --line:#2d2d32; --line-2:#3c3c43; --accent:#3b9bff; --accent-ink:#06121f; --accent-soft:#17283d;
    --ok:#4cc380; --ok-soft:#143323; --warn:#f0b04a; --warn-soft:#3a2b10; --bad:#ff7a6e; --bad-soft:#3b1b18;
    --shadow:0 1px 2px rgba(0,0,0,.4),0 4px 16px rgba(0,0,0,.35); --shadow-lg:0 12px 40px rgba(0,0,0,.6);
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --canvas:#141416; --surface:#1d1d20; --raised:#232327; --ink:#f2f2f4; --ink-2:#b4b4bc; --ink-3:#7f7f89;
      --line:#2d2d32; --line-2:#3c3c43; --accent:#3b9bff; --accent-ink:#06121f; --accent-soft:#17283d;
      --ok:#4cc380; --ok-soft:#143323; --warn:#f0b04a; --warn-soft:#3a2b10; --bad:#ff7a6e; --bad-soft:#3b1b18;
      --shadow:0 1px 2px rgba(0,0,0,.4),0 4px 16px rgba(0,0,0,.35); --shadow-lg:0 12px 40px rgba(0,0,0,.6);
    }
  }

  *,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
  html { -webkit-text-size-adjust:100%; }
  body { font:14px/1.5 var(--font); background:var(--canvas); color:var(--ink); -webkit-font-smoothing:antialiased; }
  a { color:inherit; text-decoration:none; }
  button,input,select,textarea { font:inherit; color:inherit; }
  :focus-visible { outline:2px solid var(--accent); outline-offset:2px; border-radius:var(--r-s); }
  .ic { width:18px; height:18px; flex:none; fill:none; stroke:currentColor; stroke-width:1.75; stroke-linecap:round; stroke-linejoin:round; }
  .sr { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap; }

  .app { display:grid; grid-template-columns:248px minmax(0,1fr); min-height:100vh; }
  .side { position:sticky; top:0; height:100vh; background:var(--surface); border-right:1px solid var(--line); padding:16px 12px; display:flex; flex-direction:column; gap:20px; }
  .brand { display:flex; align-items:center; gap:10px; padding:4px 8px; font-weight:700; font-size:15px; }
  .brand i { width:28px; height:28px; border-radius:8px; background:var(--accent); color:var(--accent-ink); display:grid; place-items:center; font-style:normal; font-size:13px; }
  .nav { display:flex; flex-direction:column; gap:2px; }
  .nav a { display:flex; align-items:center; gap:10px; padding:8px 10px; border-radius:var(--r-m); color:var(--ink-2); font-weight:500; }
  .nav a:hover { background:var(--raised); color:var(--ink); }
  .nav a[aria-current="page"] { background:var(--accent-soft); color:var(--accent); }
  .nav .n { margin-left:auto; font-size:12px; padding:1px 8px; border-radius:99px; background:var(--raised); color:var(--ink-2); }
  .nav a[aria-current="page"] .n { background:var(--surface); color:var(--accent); }
  .nav .n.live { background:var(--ok-soft); color:var(--ok); }
  .me { margin-top:auto; display:flex; align-items:center; gap:10px; padding:10px; border:1px solid var(--line); border-radius:var(--r-l); }
  .me .av { width:32px; height:32px; border-radius:50%; background:var(--accent-soft); color:var(--accent); display:grid; place-items:center; font-weight:700; }
  .me b { display:block; font-size:13px; line-height:1.2; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:110px; }
  .me small { color:var(--ink-3); font-size:12px; }
  .me button { margin-left:auto; }

  .main { padding:28px 32px 64px; min-width:0; }
  .head { display:flex; align-items:flex-end; justify-content:space-between; gap:16px; flex-wrap:wrap; margin-bottom:24px; }
  .head h1 { font-size:24px; line-height:1.2; letter-spacing:-.02em; }
  .head p { color:var(--ink-2); margin-top:4px; max-width:62ch; }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }

  .btn { display:inline-flex; align-items:center; gap:8px; height:34px; padding:0 14px; border:1px solid var(--line-2); background:var(--surface); border-radius:var(--r-m); font-weight:600; font-size:13px; cursor:pointer; white-space:nowrap; transition:background .12s,border-color .12s; }
  .btn:hover { background:var(--raised); }
  .btn.primary { background:var(--accent); color:var(--accent-ink); border-color:var(--accent); }
  .btn.primary:hover { filter:brightness(1.08); }
  .btn.ok { background:var(--ok); color:#fff; border-color:var(--ok); } .btn.ok:hover { filter:brightness(1.08); background:var(--ok); }
  .btn.danger { color:var(--bad); } .btn.danger:hover { background:var(--bad-soft); border-color:var(--bad); }
  .btn.sm { height:28px; padding:0 10px; font-size:12px; }
  .btn.icon { width:28px; height:28px; padding:0; justify-content:center; }
  .btn.ghost { border-color:transparent; background:transparent; }
  .btn:disabled { opacity:.5; cursor:not-allowed; }
  label { display:block; font-size:12px; font-weight:600; color:var(--ink-2); margin-bottom:6px; }
  .field { margin-bottom:14px; }
  input[type=text],input[type=number],input[type=search],input[type=file],input[type=datetime-local],select,textarea {
    width:100%; height:36px; padding:0 12px; border:1px solid var(--line-2); border-radius:var(--r-m); background:var(--surface);
  }
  textarea { height:auto; min-height:88px; padding:10px 12px; resize:vertical; }
  input:focus,select:focus,textarea:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 3px var(--accent-soft); }
  input[type=file] { padding:5px 8px; height:auto; }
  .search { position:relative; } .search .ic { position:absolute; left:10px; top:9px; color:var(--ink-3); width:16px; height:16px; }
  .search input { padding-left:34px; width:240px; }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  .pinrow { display:flex; gap:8px; } .pinrow input { font-family:ui-monospace,Menlo,Consolas,monospace; letter-spacing:.08em; }
  .fieldset { border:1px solid var(--line); border-radius:var(--r-m); padding:14px 14px 2px; margin-bottom:14px; }
  .fieldset > legend { font-size:12px; font-weight:700; color:var(--ink-2); padding:0 6px; }

  .card { background:var(--surface); border:1px solid var(--line); border-radius:var(--r-l); }
  .card-h { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; padding:14px 16px; border-bottom:1px solid var(--line); }
  .card-h h2 { font-size:14px; font-weight:650; }
  .card-b { padding:16px; }
  .stack { display:grid; gap:16px; }
  .cols { display:grid; grid-template-columns:minmax(0,3fr) minmax(0,2fr); gap:16px; }

  .kpis { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin-bottom:16px; }
  .kpi { background:var(--surface); border:1px solid var(--line); border-radius:var(--r-l); padding:16px; }
  .kpi span { color:var(--ink-2); font-size:13px; }
  .kpi b { display:block; font-size:28px; letter-spacing:-.02em; line-height:1.2; margin-top:4px; font-variant-numeric:tabular-nums; }
  .kpi small { color:var(--ink-3); font-size:12px; }

  .tw { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { padding:10px 14px; text-align:left; border-bottom:1px solid var(--line); vertical-align:middle; }
  th { font-weight:600; color:var(--ink-2); background:var(--raised); font-size:12px; white-space:nowrap; position:sticky; top:0; }
  tbody tr:last-child td { border-bottom:0; }
  tbody tr:hover td { background:var(--raised); }
  td.num,th.num { text-align:center; font-variant-numeric:tabular-nums; }
  td.act { text-align:right; white-space:nowrap; }
  .muted { color:var(--ink-3); } .small { font-size:12px; }
  code.pin { font-family:ui-monospace,Menlo,Consolas,monospace; font-weight:700; letter-spacing:.08em; background:var(--raised); border:1px solid var(--line); border-radius:var(--r-s); padding:2px 8px; }
  .tags { display:flex; gap:4px; flex-wrap:wrap; margin-top:4px; }

  .badge { display:inline-flex; align-items:center; gap:6px; padding:2px 10px; border-radius:99px; font-size:12px; font-weight:600; }
  .b-blue { background:var(--accent-soft); color:var(--accent); } .b-amber { background:var(--warn-soft); color:var(--warn); }
  .b-red { background:var(--bad-soft); color:var(--bad); } .b-green { background:var(--ok-soft); color:var(--ok); } .b-grey { background:var(--raised); color:var(--ink-2); }
  .switch { width:36px; height:20px; border-radius:99px; border:0; background:var(--line-2); position:relative; cursor:pointer; transition:background .15s; }
  .switch::after { content:''; position:absolute; top:2px; left:2px; width:16px; height:16px; border-radius:50%; background:#fff; transition:transform .15s; box-shadow:0 1px 2px rgba(0,0,0,.3); }
  .switch[aria-checked="true"] { background:var(--ok); } .switch[aria-checked="true"]::after { transform:translateX(16px); }

  .empty { text-align:center; padding:48px 20px; color:var(--ink-2); }
  .empty h3 { color:var(--ink); font-size:15px; margin-bottom:4px; }
  .empty .btn { margin-top:14px; }

  .q { display:grid; grid-template-columns:36px minmax(0,1fr) auto; gap:12px; padding:16px; border-bottom:1px solid var(--line); }
  .q:last-child { border-bottom:0; }
  .q.off { opacity:.55; }
  .q-n { width:28px; height:28px; border-radius:8px; background:var(--raised); color:var(--ink-2); display:grid; place-items:center; font-weight:650; font-size:12px; }
  .q-t { font-weight:550; margin-bottom:8px; }
  .q-img { display:block; max-width:220px; max-height:120px; object-fit:contain; border:1px solid var(--line); border-radius:var(--r-s); margin-bottom:8px; background:var(--raised); }
  .opts { display:grid; grid-template-columns:1fr 1fr; gap:6px 16px; font-size:13px; color:var(--ink-2); }
  .opts li { list-style:none; display:flex; gap:8px; }
  .opts b { color:var(--ink-3); width:14px; }
  .opts .right { color:var(--ok); font-weight:600; } .opts .right b { color:var(--ok); }
  .q-side { display:flex; flex-direction:column; align-items:flex-end; gap:8px; }

  .chips { display:flex; gap:8px; flex-wrap:wrap; }
  .chip { background:var(--raised); border:1px solid var(--line); border-radius:99px; padding:3px 12px; font-size:12px; font-weight:600; color:var(--ink-2); }
  .sheet td input { width:60px; height:32px; padding:0 4px; text-align:center; font-variant-numeric:tabular-nums; }
  .sheet td input.bad { border-color:var(--bad); background:var(--bad-soft); }
  .sheet td input:disabled { background:var(--raised); color:var(--ink-3); }
  .who b { display:block; font-weight:600; } .who span { font-size:12px; color:var(--ink-3); }
  .total { font-weight:700; font-size:15px; }
  .grade { display:inline-block; min-width:28px; padding:2px 8px; border-radius:6px; background:var(--accent-soft); color:var(--accent); font-weight:700; }
  .flowbar { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:16px; }
  .flowbar div { display:flex; gap:12px; align-items:center; padding:12px 14px; background:var(--surface); border:1px solid var(--line); border-radius:var(--r-l); }
  .flowbar b { width:24px; height:24px; border-radius:50%; background:var(--accent-soft); color:var(--accent); display:grid; place-items:center; font-size:12px; flex:none; }
  .flowbar span { font-weight:600; font-size:13px; line-height:1.3; } .flowbar small { display:block; font-weight:400; color:var(--ink-3); font-size:12px; }
  .savebar { position:sticky; bottom:16px; margin-top:16px; background:var(--surface); border:1px solid var(--line-2); border-radius:var(--r-l); box-shadow:var(--shadow-lg); padding:12px 16px; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; }
  .dirty { color:var(--warn); font-weight:600; }

  .pager { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:12px 16px; border-top:1px solid var(--line); color:var(--ink-2); font-size:13px; }

  .mgrid { display:grid; grid-template-columns:repeat(auto-fill,minmax(250px,1fr)); gap:16px; }
  .tile { background:var(--surface); border:1px solid var(--line); border-radius:var(--r-l); overflow:hidden; }
  .tile.quiet { border-color:var(--warn); }
  .feed { position:relative; aspect-ratio:4/3; background:#0d1117; display:grid; place-items:center; }
  .feed video { width:100%; height:100%; object-fit:cover; display:block; }
  .feed .ph { position:absolute; color:rgba(255,255,255,.55); font-size:12px; text-align:center; padding:0 12px; }
  .feed .tag { position:absolute; top:8px; left:8px; display:flex; align-items:center; gap:6px; background:rgba(0,0,0,.6); color:#fff; padding:3px 10px; border-radius:99px; font-size:11px; font-weight:700; }
  .feed .tag i { width:7px; height:7px; border-radius:50%; background:#9ca3af; } .feed .tag i.on { background:#22c55e; box-shadow:0 0 6px #22c55e; }
  .feed .full { position:absolute; right:8px; top:8px; background:rgba(0,0,0,.6); color:#fff; border:0; }
  .tile .info { padding:10px 14px; } .tile .info b { display:block; font-size:13px; } .tile .info span { color:var(--ink-3); font-size:12px; display:block; }
  .tile .info .m-idle { margin-top:4px; font-weight:600; } .tile .info .m-idle.warn { color:var(--warn); }

  dialog { border:0; border-radius:var(--r-l); padding:0; width:min(560px,calc(100vw - 32px)); max-height:calc(100vh - 32px); overflow:auto; background:var(--surface); color:var(--ink); box-shadow:var(--shadow-lg); margin:auto; }
  dialog::backdrop { background:rgba(10,10,16,.5); backdrop-filter:blur(2px); }
  .dlg-h { display:flex; align-items:center; justify-content:space-between; padding:16px 20px; border-bottom:1px solid var(--line); position:sticky; top:0; background:var(--surface); z-index:1; }
  .dlg-h h2 { font-size:16px; } .dlg-b { padding:20px; } .dlg-f { padding:14px 20px; border-top:1px solid var(--line); display:flex; justify-content:flex-end; gap:8px; background:var(--raised); border-radius:0 0 var(--r-l) var(--r-l); position:sticky; bottom:0; }
  .hint { color:var(--ink-3); font-size:12px; margin-top:6px; }
  #toasts { position:fixed; right:20px; bottom:20px; display:grid; gap:8px; z-index:99; }
  .toast { background:var(--ink); color:var(--canvas); padding:10px 16px; border-radius:var(--r-m); box-shadow:var(--shadow-lg); max-width:380px; font-weight:500; border-left:4px solid var(--ok); }
  .toast.error { border-color:var(--bad); } .toast.warn { border-color:#f0b04a; }

  @media (max-width:1000px) { .cols { grid-template-columns:1fr; } .kpis,.flowbar { grid-template-columns:1fr 1fr; } }
  @media (max-width:820px) {
    .app { grid-template-columns:1fr; }
    .side { position:static; height:auto; flex-direction:row; align-items:center; overflow-x:auto; padding:8px 12px; border-right:0; border-bottom:1px solid var(--line); gap:8px; }
    .brand span,.me,.nav a span:not(.n) { display:none; } .nav { flex-direction:row; }
    .main { padding:20px 16px 64px; } .grid2,.opts { grid-template-columns:1fr; } .q { grid-template-columns:28px minmax(0,1fr); } .q-side { grid-column:2; flex-direction:row; align-items:center; }
  }
  @media (prefers-reduced-motion:reduce) { * { transition:none !important; } }
  @media print {
    .side,.head .row,.savebar,.btn,.search,.flowbar { display:none !important; }
    .app { display:block; } .main { padding:0; } body { background:#fff; color:#000; } .card { border:0; }
    .sheet td input { border:0; background:none; width:auto; }
  }
</style>
</head>
<body>

<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <symbol id="i-home" viewBox="0 0 24 24"><path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/></symbol>
  <symbol id="i-book" viewBox="0 0 24 24"><path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M4 19V5M9 7h6"/></symbol>
  <symbol id="i-help" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 1-1 1.7M12 17h.01"/></symbol>
  <symbol id="i-list" viewBox="0 0 24 24"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></symbol>
  <symbol id="i-video" viewBox="0 0 24 24"><rect x="3" y="6" width="13" height="12" rx="2"/><path d="M16 10l5-3v10l-5-3z"/></symbol>
  <symbol id="i-clip" viewBox="0 0 24 24"><rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 4h6v3H9zM9 12h6M9 16h4"/></symbol>
  <symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
  <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/></symbol>
  <symbol id="i-down" viewBox="0 0 24 24"><path d="M12 4v11M7 11l5 5 5-5M5 20h14"/></symbol>
  <symbol id="i-up" viewBox="0 0 24 24"><path d="M12 16V5M7 9l5-5 5 5M5 20h14"/></symbol>
  <symbol id="i-trash" viewBox="0 0 24 24"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></symbol>
  <symbol id="i-edit" viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16z"/></symbol>
  <symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></symbol>
  <symbol id="i-x" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></symbol>
  <symbol id="i-send" viewBox="0 0 24 24"><path d="M21 3L10 14M21 3l-7 18-4-7-7-4z"/></symbol>
  <symbol id="i-moon" viewBox="0 0 24 24"><path d="M20 14A8 8 0 1 1 10 4a6 6 0 0 0 10 10z"/></symbol>
  <symbol id="i-expand" viewBox="0 0 24 24"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/></symbol>
  <symbol id="i-lock" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></symbol>
  <symbol id="i-gear" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/></symbol>
  <symbol id="i-key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/></symbol>
  <symbol id="i-eye" viewBox="0 0 24 24"><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></symbol>
</svg>

<div class="app">
  <aside class="side">
    <div class="brand"><i>CB</i><span>CBT panel</span></div>
    <nav class="nav" aria-label="Sections">
      <?php
      $navItems = ['overview' => ['home', 'Overview', null], 'exams' => ['book', 'Exams', count($exams)], 'questions' => ['help', 'Questions', $stats['questions']],
                   'sessions' => ['list', 'Sessions', null], 'monitor' => ['video', 'Live monitor', $liveCount], 'results' => ['clip', 'Results', null]];
      foreach ($navItems as $k => [$icon, $label, $count]): ?>
        <a href="<?= h(self_url($k, in_array($k, ['questions', 'results'], true) && $selId ? ['exam_id' => $selId] : [])) ?>" <?= $tab === $k ? 'aria-current="page"' : '' ?>>
          <?= ic($icon) ?><span><?= h($label) ?></span>
          <?php if ($count !== null): ?><span class="n <?= $k === 'monitor' && $count > 0 ? 'live' : '' ?>" <?= $k === 'monitor' ? 'id="liveCount"' : '' ?>><?= (int)$count ?></span><?php endif; ?>
        </a>
      <?php endforeach; ?>
    </nav>
    <div class="me">
      <div class="av"><?= h(mb_strtoupper(mb_substr((string)$teacher, 0, 1))) ?></div>
      <div><b><?= h($teacher) ?></b><small>Teacher</small></div>
      <button class="btn icon ghost" type="button" id="themeBtn" aria-label="Switch light or dark theme"><?= ic('moon') ?></button>
    </div>
  </aside>

  <main class="main" id="main">
    <header class="head">
      <div><h1><?= h($titles[$tab][0]) ?></h1><p><?= h($titles[$tab][1]) ?></p></div>
      <div class="row">
        <?php if ($tab === 'exams'): ?>
          <button class="btn primary" type="button" data-dialog="dlgExam"><?= ic('plus') ?>New exam</button>
        <?php elseif ($tab === 'questions' && $sel): ?>
          <button class="btn" type="button" data-dialog="dlgImport"><?= ic('up') ?>Import CSV</button>
          <a class="btn" href="<?= h(self_url('questions', ['exam_id' => $selId, 'export' => 'questions'])) ?>"><?= ic('down') ?>Export</a>
          <button class="btn primary" type="button" data-dialog="dlgQ" data-title="Add question" data-fill="<?= h(json_encode(['id' => 0, 'exam_id' => $selId, 'correct_answer' => 'A', 'marks' => 1, 'difficulty' => 'Medium', 'status' => 'Active'])) ?>"><?= ic('plus') ?>Add question</button>
        <?php elseif ($tab === 'sessions'): ?>
          <a class="btn" href="<?= h(self_url('sessions', array_filter(['status' => $fStatus, 'q' => $fQ]) + ['export' => 'sessions'])) ?>"><?= ic('down') ?>Download CSV</a>
        <?php elseif ($tab === 'results' && $sel): ?>
          <form method="post" data-confirm="<?= (int)$sel['results_released'] === 1 ? 'Hide scores from students? Students who submit after this will only see that their exam was received.' : 'Show scores to students? They will see their CBT score as soon as they submit.' ?>"><?= hidden('exam_release', 'results', ['exam_id' => $selId]) ?>
            <button class="btn"><?= ic('eye') ?><?= (int)$sel['results_released'] === 1 ? 'Scores shown to students: hide' : 'Scores hidden from students: show' ?></button></form>
          <a class="btn" href="<?= h(self_url('results', ['exam_id' => $selId, 'export' => 'results'])) ?>"><?= ic('down') ?>Download CSV</a>
          <button class="btn" type="button" data-print>Print</button>
        <?php endif; ?>
      </div>
    </header>

<?php /* ═════════ OVERVIEW ═════════ */ if ($tab === 'overview'):
    $needs = array_filter($exams, fn($e) => (int)$e['q_active'] === 0); ?>
    <section class="kpis" id="kpis" aria-label="Summary">
      <div class="kpi"><span>Active exams</span><b data-kpi="active"><?= (int)$stats['active'] ?></b><small>of <span data-kpi="exams"><?= (int)$stats['exams'] ?></span> created</small></div>
      <div class="kpi"><span>Active questions</span><b data-kpi="questions"><?= (int)$stats['questions'] ?></b><small>across all exams</small></div>
      <div class="kpi"><span>Sitting now</span><b data-kpi="in_progress"><?= (int)$stats['in_progress'] ?></b><small><a href="<?= h(self_url('monitor')) ?>">Open live monitor</a></small></div>
      <div class="kpi"><span>Average CBT score</span><b><span data-kpi="avg_score"><?= $stats['avg_score'] !== null ? h($stats['avg_score']) : '—' ?></span><small> /<?= MAX_CBT ?></small></b><small><span data-kpi="completed"><?= (int)$stats['completed'] ?></span> finished, <span data-kpi="timed_out"><?= (int)$stats['timed_out'] ?></span> timed out</small></div>
    </section>

    <div class="cols">
      <section class="card">
        <div class="card-h"><h2>Recent attempts</h2><a class="btn sm" href="<?= h(self_url('sessions')) ?>">See all</a></div>
        <?php if (!$recent): ?>
          <div class="empty"><h3>No attempts yet</h3><p>Attempts appear here as soon as a student starts an exam.</p></div>
        <?php else: ?>
        <div class="tw"><table>
          <thead><tr><th>Student</th><th>Subject</th><th class="num">Score</th><th>Status</th></tr></thead>
          <tbody><?php foreach ($recent as $r): ?>
            <tr><td><div class="who"><b><?= h($r['full_name'] ?: $r['student_username']) ?></b><span><?= h($r['class_level']) ?></span></div></td>
              <td><?= h($r['course_name']) ?></td><td class="num"><?= (int)$r['exam_score_60'] ?>/<?= MAX_CBT ?></td>
              <td><span class="badge <?= $badge($r['status']) ?>"><?= h(ucfirst(str_replace('_', ' ', $r['status']))) ?></span></td></tr>
          <?php endforeach; ?></tbody>
        </table></div>
        <?php endif; ?>
      </section>

      <section class="card">
        <div class="card-h"><h2>Needs attention</h2></div>
        <?php if (!$exams): ?>
          <div class="empty"><h3>Create your first exam</h3><p>Pick a subject, class and term, then add questions.</p><button class="btn primary" type="button" data-dialog="dlgExam"><?= ic('plus') ?>New exam</button></div>
        <?php elseif (!$needs): ?>
          <div class="empty"><h3>All caught up</h3><p>Every exam has active questions.</p></div>
        <?php else: ?>
          <div class="card-b stack">
            <?php foreach ($needs as $e): ?>
              <div class="row" style="justify-content:space-between">
                <div><b><?= h($e['course_name']) ?></b><div class="small muted"><?= h($e['class_level'] . ' · ' . $e['term']) ?> has no active questions</div></div>
                <a class="btn sm primary" href="<?= h(self_url('questions', ['exam_id' => (int)$e['id']])) ?>">Add questions</a>
              </div>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </section>
    </div>

<?php /* ═════════ EXAMS ═════════ */ elseif ($tab === 'exams'): ?>
    <section class="card">
      <div class="card-h"><h2><?= count($exams) ?> exam<?= count($exams) === 1 ? '' : 's' ?></h2>
        <div class="search"><?= ic('search') ?><input type="search" placeholder="Search exams" aria-label="Search exams" data-filter="#examTable"></div></div>
      <?php if (!$exams): ?>
        <div class="empty"><h3>No exams yet</h3><p>Create an exam to start adding questions.</p><button class="btn primary" type="button" data-dialog="dlgExam"><?= ic('plus') ?>New exam</button></div>
      <?php else: ?>
      <div class="tw"><table id="examTable">
        <thead><tr><th>Subject</th><th>Class and term</th><th>Exam PIN</th><th>Status and rules</th><th class="num">Questions</th><th>Open</th><th></th></tr></thead>
        <tbody>
        <?php foreach ($exams as $e): $id = (int)$e['id']; $on = (int)$e['is_active'] === 1; [$stLabel, $stCls] = exam_state($e);
            $perExam = (int)$e['max_questions'] > 0 ? (int)$e['max_questions'] : null; ?>
          <tr>
            <td><b><?= h($e['course_name']) ?></b></td>
            <td><?= h($e['class_level']) ?><div class="small muted"><?= h($e['term']) ?></div></td>
            <td>
              <?php if ($e['access_pin']): ?>
                <code class="pin"><?= h($e['access_pin']) ?></code>
                <button class="btn sm icon ghost" type="button" aria-label="Copy PIN" data-copy="<?= h($e['access_pin']) ?>"><?= ic('copy') ?></button>
              <?php else: ?><span class="muted small">No PIN</span><?php endif; ?>
              <form method="post" style="display:inline" data-confirm="Create a new PIN? The old PIN stops working for new sign-ins. Students already sitting the exam are not affected."><?= hidden('exam_pin', 'exams', ['exam_id' => $id]) ?>
                <button class="btn sm icon ghost" aria-label="New PIN"><?= ic('key') ?></button></form>
            </td>
            <td>
              <span class="badge <?= $stCls ?>"><?= h($stLabel) ?></span>
              <div class="tags">
                <span class="chip"><?= (int)($e['duration_minutes'] ?? 30) ?> min</span>
                <?php if ($perExam): ?><span class="chip"><?= $perExam ?> random Qs</span><?php endif; ?>
                <?php if ((int)$e['camera_required'] === 1): ?><span class="chip">Camera required</span><?php endif; ?>
                <?php if ((int)$e['allow_retake'] === 1): ?><span class="chip">Retake allowed</span><?php endif; ?>
                <span class="chip"><?= (int)$e['results_released'] === 1 ? 'Scores shown' : 'Scores hidden' ?></span>
              </div>
              <?php if ($e['start_at'] || $e['end_at']): ?><div class="small muted" style="margin-top:4px"><?= $e['start_at'] ? 'Opens ' . h($fmtDt($e['start_at'])) : '' ?><?= ($e['start_at'] && $e['end_at']) ? ' · ' : '' ?><?= $e['end_at'] ? 'Closes ' . h($fmtDt($e['end_at'])) : '' ?></div><?php endif; ?>
            </td>
            <td class="num"><a href="<?= h(self_url('questions', ['exam_id' => $id])) ?>" class="badge <?= (int)$e['q_active'] === 0 ? 'b-red' : 'b-blue' ?>"><?= (int)$e['q_active'] ?> active · <?= (int)$e['q_marks'] ?> marks</a>
              <?php if ((int)$e['q_count'] > (int)$e['q_active']): ?><div class="small muted"><?= (int)$e['q_count'] - (int)$e['q_active'] ?> inactive</div><?php endif; ?></td>
            <td>
              <form method="post" class="row"><?= hidden('exam_toggle', 'exams', ['exam_id' => $id]) ?>
                <button class="switch" role="switch" aria-checked="<?= $on ? 'true' : 'false' ?>" aria-label="<?= $on ? 'Close' : 'Open' ?> <?= h($e['course_name']) ?> for students"></button>
                <span class="small muted"><?= $on ? 'On' : 'Off' ?></span></form>
            </td>
            <td class="act">
              <a class="btn sm" href="<?= h(self_url('results', ['exam_id' => $id])) ?>">Results</a>
              <button class="btn sm icon" type="button" aria-label="Exam settings" data-dialog="dlgSet" data-fill="<?= h(json_encode([
                  'exam_id' => $id, 'duration_minutes' => (int)($e['duration_minutes'] ?? 30), 'access_pin' => (string)($e['access_pin'] ?? ''),
                  'max_questions' => (int)$e['max_questions'], 'camera_required' => (int)$e['camera_required'], 'allow_retake' => (int)$e['allow_retake'],
                  'results_released' => (int)$e['results_released'], 'start_at' => $inDt($e['start_at']), 'end_at' => $inDt($e['end_at']),
                  'class_level' => $e['class_level']], JSON_UNESCAPED_UNICODE)) ?>"><?= ic('gear') ?></button>
              <form method="post" style="display:inline" data-confirm="<?= (int)$e['s_count'] > 0 ? 'This exam already has student attempts, so it cannot be deleted. Close it instead.' : 'Delete ' . h($e['course_name'] . ' ' . $e['class_level'] . ' ' . $e['term']) . ' and all ' . (int)$e['q_count'] . ' of its questions? This cannot be undone.' ?>"><?= hidden('exam_delete', 'exams', ['exam_id' => $id]) ?>
                <button class="btn sm icon danger" aria-label="Delete exam"><?= ic('trash') ?></button></form>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table></div>
      <?php endif; ?>
    </section>

<?php /* ═════════ QUESTIONS ═════════ */ elseif ($tab === 'questions'): ?>
    <form method="get" class="card card-b" style="margin-bottom:16px">
      <input type="hidden" name="tab" value="questions">
      <label for="qExam">Exam</label>
      <select id="qExam" name="exam_id" data-autosubmit style="max-width:480px">
        <option value="">Choose an exam</option>
        <?php foreach ($exams as $e): ?><option value="<?= (int)$e['id'] ?>" <?= (int)$e['id'] === $selId ? 'selected' : '' ?>><?= h($e['course_name'] . ' · ' . $e['class_level'] . ' · ' . $e['term']) ?></option><?php endforeach; ?>
      </select>
    </form>

    <?php if (!$sel): ?>
      <div class="card empty"><h3>No exam selected</h3><p><?= $exams ? 'Choose an exam above to see and edit its questions.' : 'Create an exam first, then come back to add questions.' ?></p></div>
    <?php else:
        $activeQ = array_filter($questions, fn($q) => $q['status'] === 'Active');
        $limit = (int)$sel['max_questions']; ?>
    <section class="card">
      <div class="card-h"><div class="chips">
          <span class="chip"><?= count($activeQ) ?> active of <?= count($questions) ?></span>
          <span class="chip"><?= array_sum(array_map(fn($q) => (int)$q['marks'], $activeQ)) ?> marks (all active)</span>
          <?php if ($limit > 0): ?><span class="chip">Each student gets <?= min($limit, count($activeQ)) ?> random question<?= min($limit, count($activeQ)) === 1 ? '' : 's' ?></span><?php else: ?><span class="chip">Each student gets all active questions up to the default limit</span><?php endif; ?>
        </div>
        <a class="small" href="<?= h(self_url('questions', ['export' => 'template'])) ?>">CSV template for import</a></div>
      <?php if (!$questions): ?>
        <div class="empty"><h3>No questions yet</h3><p>Add them one at a time, or import many from a CSV file.</p>
          <div class="row" style="justify-content:center;margin-top:14px"><button class="btn primary" type="button" data-dialog="dlgQ" data-title="Add question" data-fill="<?= h(json_encode(['id' => 0, 'exam_id' => $selId, 'correct_answer' => 'A', 'marks' => 1, 'difficulty' => 'Medium', 'status' => 'Active'])) ?>">Add question</button><button class="btn" type="button" data-dialog="dlgImport">Import CSV</button></div></div>
      <?php else: foreach ($questions as $i => $q): $id = (int)$q['id']; $isOn = $q['status'] === 'Active'; ?>
        <article class="q <?= $isOn ? '' : 'off' ?>">
          <div class="q-n"><?= $i + 1 ?></div>
          <div>
            <?php if (!empty($q['question_image'])): ?><img class="q-img" src="<?= h($q['question_image']) ?>" alt="Picture for question <?= $i + 1 ?>" loading="lazy"><?php endif; ?>
            <div class="q-t"><?= nl2br(h($q['question_text'])) ?></div>
            <ul class="opts">
              <?php foreach (['A' => 'option_a', 'B' => 'option_b', 'C' => 'option_c', 'D' => 'option_d'] as $L => $col): ?>
                <li class="<?= $q['correct_answer'] === $L ? 'right' : '' ?>"><b><?= $L ?></b><span><?= h($q[$col]) ?></span></li>
              <?php endforeach; ?>
            </ul>
          </div>
          <div class="q-side">
            <div class="row" style="justify-content:flex-end">
              <span class="badge <?= $isOn ? 'b-green' : 'b-grey' ?>"><?= $isOn ? 'Active' : 'Inactive' ?></span>
              <span class="badge <?= ($q['difficulty'] ?? '') === 'Easy' ? 'b-green' : (($q['difficulty'] ?? '') === 'Hard' ? 'b-red' : 'b-amber') ?>"><?= h($q['difficulty'] ?: 'Medium') ?></span>
              <span class="badge b-grey"><?= (int)$q['marks'] ?> mark<?= (int)$q['marks'] === 1 ? '' : 's' ?></span>
            </div>
            <div class="row">
              <form method="post"><?= hidden('q_status', 'questions', ['exam_id' => $selId, 'id' => $id]) ?><button class="btn sm"><?= $isOn ? 'Turn off' : 'Turn on' ?></button></form>
              <button class="btn sm icon" type="button" aria-label="Edit question <?= $i + 1 ?>" data-dialog="dlgQ" data-title="Edit question" data-fill="<?= h(json_encode(['id' => $id, 'exam_id' => $selId, 'question_text' => $q['question_text'], 'option_a' => $q['option_a'], 'option_b' => $q['option_b'], 'option_c' => $q['option_c'], 'option_d' => $q['option_d'], 'correct_answer' => $q['correct_answer'], 'marks' => (int)$q['marks'], 'difficulty' => $q['difficulty'] ?: 'Medium', 'status' => $q['status'], 'question_image' => (string)($q['question_image'] ?? '')], JSON_UNESCAPED_UNICODE)) ?>"><?= ic('edit') ?></button>
              <form method="post"><?= hidden('q_duplicate', 'questions', ['exam_id' => $selId, 'id' => $id]) ?><button class="btn sm icon" aria-label="Duplicate question <?= $i + 1 ?>"><?= ic('copy') ?></button></form>
              <form method="post" data-confirm="Delete question <?= $i + 1 ?>?"><?= hidden('q_delete', 'questions', ['exam_id' => $selId, 'id' => $id]) ?><button class="btn sm icon danger" aria-label="Delete question <?= $i + 1 ?>"><?= ic('trash') ?></button></form>
            </div>
          </div>
        </article>
      <?php endforeach; endif; ?>
    </section>
    <?php endif; ?>

<?php /* ═════════ SESSIONS ═════════ */ elseif ($tab === 'sessions'): ?>
    <section class="card">
      <form method="get" class="card-h">
        <input type="hidden" name="tab" value="sessions">
        <div class="row">
          <div class="search"><?= ic('search') ?><input type="search" name="q" value="<?= h($fQ) ?>" placeholder="Search student or subject" aria-label="Search sessions"></div>
          <select name="status" aria-label="Status" data-autosubmit style="width:auto">
            <option value="">All statuses</option>
            <?php foreach (['completed' => 'Completed', 'in_progress' => 'In progress', 'timed_out' => 'Timed out'] as $k => $l): ?><option value="<?= $k ?>" <?= $fStatus === $k ? 'selected' : '' ?>><?= $l ?></option><?php endforeach; ?>
          </select>
          <button class="btn">Search</button>
        </div>
        <span class="small muted"><?= $sessionTotal ?> attempt<?= $sessionTotal === 1 ? '' : 's' ?></span>
      </form>
      <?php if (!$sessionRows): ?>
        <div class="empty"><h3>No attempts found</h3><p><?= ($fQ || $fStatus) ? 'Try a different search or clear the status filter.' : 'Attempts appear here once students start your exams.' ?></p></div>
      <?php else: ?>
      <div class="tw"><table>
        <thead><tr><th>Student</th><th>Subject</th><th>Class</th><th>Term</th><th class="num">Attempt</th><th class="num">Correct</th><th class="num">Score /<?= MAX_CBT ?></th><th>Status</th><th>Started</th><th>Ended</th></tr></thead>
        <tbody><?php foreach ($sessionRows as $s): ?>
          <tr>
            <td><div class="who"><b><?= h($s['full_name'] ?: $s['student_username']) ?></b><span><?= h($s['student_username']) ?></span></div></td>
            <td><?= h($s['course_name']) ?></td><td><?= h($s['class_level']) ?></td><td><?= h($s['term']) ?></td>
            <td class="num"><?= (int)($s['attempt_no'] ?? 1) ?></td>
            <td class="num"><?= (int)$s['raw_score'] ?>/<?= (int)$s['total_questions'] ?></td>
            <td class="num"><b><?= (int)$s['exam_score_60'] ?></b></td>
            <td><span class="badge <?= $badge($s['status']) ?>"><?= h(ucfirst(str_replace('_', ' ', $s['status']))) ?></span></td>
            <td class="small muted"><?= h($s['start_time']) ?></td><td class="small muted"><?= h($s['end_time'] ?? '—') ?></td>
          </tr>
        <?php endforeach; ?></tbody>
      </table></div>
      <div class="pager"><span>Page <?= $page ?> of <?= $pages ?></span>
        <div class="row">
          <?php $pq = array_filter(['status' => $fStatus, 'q' => $fQ]); ?>
          <a class="btn sm" <?= $page > 1 ? 'href="' . h(self_url('sessions', $pq + ['page' => $page - 1])) . '"' : 'aria-disabled="true" style="opacity:.5;pointer-events:none"' ?>>Previous</a>
          <a class="btn sm" <?= $page < $pages ? 'href="' . h(self_url('sessions', $pq + ['page' => $page + 1])) . '"' : 'aria-disabled="true" style="opacity:.5;pointer-events:none"' ?>>Next</a>
        </div></div>
      <?php endif; ?>
    </section>

<?php /* ═════════ LIVE MONITOR ═════════ */ elseif ($tab === 'monitor'): ?>
    <p class="small muted" style="margin-bottom:16px"><span id="liveText">Looking for students…</span> Video goes straight from the student’s browser to yours. Nothing is stored on the server. A tile turns amber when a student has not reported in for <?= IDLE_WARN ?> seconds.</p>
    <div class="mgrid" id="monitorGrid"></div>
    <div class="card empty" id="monitorEmpty" hidden><h3>No one is sitting an exam</h3><p>Students appear here automatically when they start. You don’t need to refresh.</p></div>
    <template id="tileTpl">
      <article class="tile">
        <div class="feed"><video autoplay playsinline muted></video><div class="ph">Connecting…</div>
          <span class="tag"><i></i><span class="st">Connecting</span></span>
          <button class="btn sm icon full" type="button" aria-label="Full screen"><?= ic('expand') ?></button></div>
        <div class="info"><b class="m-name"></b><span class="m-meta"></span><span class="m-idle muted"></span></div>
      </article>
    </template>

<?php /* ═════════ RESULTS ═════════ */ elseif ($tab === 'results'): ?>
    <div class="flowbar">
      <div><b>1</b><span>Choose exam<small>Subject, class and term</small></span></div>
      <div><b>2</b><span>Pick up CBT scores<small>Out of <?= MAX_CBT ?></small></span></div>
      <div><b>3</b><span>Enter CA scores<small>Up to <?= MAX_CA ?> each</small></span></div>
      <div><b>4</b><span>Send results<small>CA and CBT together</small></span></div>
    </div>

    <form method="get" class="card card-b" style="margin-bottom:16px">
      <input type="hidden" name="tab" value="results">
      <label for="rExam">Exam</label>
      <select id="rExam" name="exam_id" data-autosubmit style="max-width:480px">
        <option value="">Choose an exam</option>
        <?php foreach ($exams as $e): ?><option value="<?= (int)$e['id'] ?>" <?= (int)$e['id'] === $selId ? 'selected' : '' ?>><?= h($e['course_name'] . ' · ' . $e['class_level'] . ' · ' . $e['term']) ?></option><?php endforeach; ?>
      </select>
    </form>

    <?php if (!$sel): ?>
      <div class="card empty"><h3>No exam selected</h3><p><?= $exams ? 'Choose an exam above to start entering results.' : 'You have no exams yet. Create one in the Exams section first.' ?></p></div>
    <?php else: ?>
    <form method="post" id="sheetForm">
      <?= hidden('results_save', 'results', ['exam_id' => $selId]) ?>
      <section class="card">
        <div class="card-h">
          <div class="chips">
            <span class="chip"><?= h($sel['course_name'] . ' · ' . $sel['class_level']) ?></span>
            <span class="chip"><?= count($sheet) ?> student<?= count($sheet) === 1 ? '' : 's' ?></span>
            <?php if ($resStats): ?><span class="chip">Average <span id="avgTotal"><?= h($resStats['avg']) ?></span></span><span class="chip">Highest <?= (int)$resStats['max'] ?></span><span class="chip">Lowest <?= (int)$resStats['min'] ?></span><?php endif; ?>
            <?php if ($locked): ?><span class="chip"><?= ic('lock') ?> <?= $locked ?> locked by form master</span><?php endif; ?>
          </div>
          <div class="row">
            <?php if ($sheet): ?><div class="search"><?= ic('search') ?><input type="search" placeholder="Find a student" aria-label="Find a student" data-filter="#sheetTable"></div><?php endif; ?>
            <button class="btn primary" name="do" value="results_pull" formnovalidate><?= ic('down') ?>Pick up CBT scores</button>
          </div>
        </div>
        <?php if (!$sheet): ?>
          <div class="empty"><h3>No scores yet</h3><p>Select <b>Pick up CBT scores</b> to bring in every student who has finished this exam.</p></div>
        <?php else: ?>
        <div class="tw sheet"><table id="sheetTable">
          <thead><tr><th>Student</th><th class="num">Assignment 1<br><span class="muted">/<?= MAX_CA ?></span></th><th class="num">Assignment 2<br><span class="muted">/<?= MAX_CA ?></span></th><th class="num">Test 1<br><span class="muted">/<?= MAX_CA ?></span></th><th class="num">Test 2<br><span class="muted">/<?= MAX_CA ?></span></th><th class="num">CBT<br><span class="muted">/<?= MAX_CBT ?></span></th><th class="num">Total<br><span class="muted">/<?= MAX_CA * 4 + MAX_CBT ?></span></th><th class="num">Position</th><th class="num">Grade</th></tr></thead>
          <tbody>
          <?php foreach ($sheet as $r): $lock = (int)$r['fm_verified'] === 1; ?>
            <tr data-cbt="<?= (int)$r['exam'] ?>">
              <td><div class="who"><b><?= h($r['full_name']) ?></b><span><?= h($r['student_username']) ?></span></div></td>
              <?php foreach (['assignment1', 'assignment2', 'test1', 'test2'] as $f): ?>
                <td class="num"><input type="number" min="0" max="<?= MAX_CA ?>" step="1" inputmode="numeric" name="row[<?= (int)$r['id'] ?>][<?= $f ?>]" value="<?= (int)$r[$f] ?>" aria-label="<?= h($r['full_name'] . ' ' . $f) ?>" <?= $lock ? 'disabled' : '' ?>></td>
              <?php endforeach; ?>
              <td class="num"><b class="<?= $r['exam'] ? '' : 'muted' ?>"><?= $r['exam'] ? (int)$r['exam'] : '—' ?></b></td>
              <td class="num"><span class="total"><?= (int)$r['total'] ?></span></td>
              <td class="num muted"><?= (int)($rank[(int)$r['id']] ?? 0) ?></td>
              <td class="num"><?= $lock ? '<span class="badge b-blue">Verified</span>' : '<span class="grade">' . h($r['grade'] ?: '—') . '</span>' ?></td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table></div>
        <?php endif; ?>
      </section>

      <?php if ($sheet): ?>
      <div class="savebar">
        <p class="small muted" id="status" aria-live="polite">All changes saved. Use Tab or Enter to move down a column.</p>
        <div class="row">
          <button class="btn" name="do" value="results_save">Save draft</button>
          <button class="btn ok" name="do" value="results_send" data-send><?= ic('send') ?>Send results</button>
        </div>
      </div>
      <?php endif; ?>
    </form>
    <?php endif; ?>
<?php endif; ?>
  </main>
</div>

<!-- ═════════ Dialogs ═════════ -->
<dialog id="dlgExam" aria-labelledby="dlgExamT">
  <form method="post"><?= hidden('exam_add', 'exams') ?>
    <div class="dlg-h"><h2 id="dlgExamT">New exam</h2><button class="btn icon ghost" type="button" data-close aria-label="Close"><?= ic('x') ?></button></div>
    <div class="dlg-b">
      <div class="grid2">
        <div class="field"><label for="ne_c">Subject</label><input id="ne_c" type="text" name="course_name" maxlength="100" placeholder="Mathematics" required></div>
        <div class="field"><label for="ne_d">Duration (minutes)</label><input id="ne_d" type="number" name="duration_minutes" value="30" min="5" max="180" required></div>
        <div class="field"><label for="ne_l">Class</label><select id="ne_l" name="class_level" required><option value="">Choose class</option><?php foreach (CLASSES as $c): ?><option><?= h($c) ?></option><?php endforeach; ?></select></div>
        <div class="field"><label for="ne_t">Term</label><select id="ne_t" name="term" required><option value="">Choose term</option><?php foreach (TERMS as $t): ?><option><?= h($t) ?></option><?php endforeach; ?></select></div>
      </div>
      <p class="hint">A PIN is created for you and the exam opens to students straight away. Open the settings (gear icon) to set a schedule, camera rule, question limit or retakes.</p>
    </div>
    <div class="dlg-f"><button class="btn" type="button" data-close>Cancel</button><button class="btn primary">Create exam</button></div>
  </form>
</dialog>

<dialog id="dlgSet" aria-labelledby="dlgSetT">
  <form method="post"><?= hidden('exam_settings', 'exams') ?><input type="hidden" name="exam_id" value="">
    <div class="dlg-h"><h2 id="dlgSetT">Exam settings</h2><button class="btn icon ghost" type="button" data-close aria-label="Close"><?= ic('x') ?></button></div>
    <div class="dlg-b">
      <fieldset class="fieldset"><legend>Sign-in</legend>
        <div class="field"><label for="es_pin">Exam PIN</label>
          <div class="pinrow"><input id="es_pin" type="text" name="access_pin" maxlength="12" pattern="[A-Za-z0-9]{4,12}" required autocomplete="off" spellcheck="false"><button class="btn" type="button" id="genPin">Generate</button></div>
          <p class="hint">Students type their username and this PIN. It must be different from every other open exam in the same class.</p></div>
      </fieldset>
      <fieldset class="fieldset"><legend>Timing</legend>
        <div class="grid2">
          <div class="field"><label for="es_dur">Duration (minutes)</label><input id="es_dur" type="number" name="duration_minutes" min="5" max="180" required></div>
          <div class="field"><label for="es_max">Questions per student</label><input id="es_max" type="number" name="max_questions" min="0" max="200"><p class="hint">0 uses the portal default. Each student gets a random pick.</p></div>
          <div class="field"><label for="es_start">Opens at (optional)</label><input id="es_start" type="datetime-local" name="start_at"></div>
          <div class="field"><label for="es_end">Closes at (optional)</label><input id="es_end" type="datetime-local" name="end_at"></div>
        </div>
        <p class="hint" style="margin:-6px 0 14px">Students cannot start outside this window. Anyone already sitting the exam can finish.</p>
      </fieldset>
      <fieldset class="fieldset"><legend>Rules</legend>
        <div class="grid2">
          <div class="field"><label for="es_cam">Camera</label><select id="es_cam" name="camera_required"><option value="0">Optional</option><option value="1">Required to sit the exam</option></select></div>
          <div class="field"><label for="es_retake">Retake</label><select id="es_retake" name="allow_retake"><option value="0">One attempt only</option><option value="1">Students may sit it again</option></select></div>
          <div class="field"><label for="es_rel">Scores</label><select id="es_rel" name="results_released"><option value="0">Hidden from students</option><option value="1">Shown when they submit</option></select></div>
        </div>
      </fieldset>
    </div>
    <div class="dlg-f"><button class="btn" type="button" data-close>Cancel</button><button class="btn primary">Save settings</button></div>
  </form>
</dialog>

<dialog id="dlgQ" aria-labelledby="dlgQT">
  <form method="post"><?= hidden('q_save', 'questions') ?><input type="hidden" name="id" value="0"><input type="hidden" name="exam_id" value="<?= $selId ?>">
    <div class="dlg-h"><h2 id="dlgQT" class="dlg-title">Add question</h2><button class="btn icon ghost" type="button" data-close aria-label="Close"><?= ic('x') ?></button></div>
    <div class="dlg-b">
      <div class="field"><label for="q_t">Question</label><textarea id="q_t" name="question_text" required></textarea></div>
      <div class="grid2">
        <?php foreach (['a', 'b', 'c', 'd'] as $L): ?><div class="field"><label for="q_<?= $L ?>">Option <?= strtoupper($L) ?></label><input id="q_<?= $L ?>" type="text" name="option_<?= $L ?>" required></div><?php endforeach; ?>
        <div class="field"><label for="q_ans">Correct answer</label><select id="q_ans" name="correct_answer"><?php foreach (['A', 'B', 'C', 'D'] as $L): ?><option><?= $L ?></option><?php endforeach; ?></select></div>
        <div class="field"><label for="q_m">Marks</label><input id="q_m" type="number" name="marks" value="1" min="1" max="10"></div>
        <div class="field"><label for="q_diff">Difficulty</label><select id="q_diff" name="difficulty"><?php foreach (LEVELS as $L): ?><option><?= $L ?></option><?php endforeach; ?></select></div>
        <div class="field"><label for="q_stat">Status</label><select id="q_stat" name="status"><option>Active</option><option>Inactive</option></select></div>
      </div>
      <div class="field"><label for="q_img">Picture (optional)</label><input id="q_img" type="text" name="question_image" maxlength="255" placeholder="images/figure1.png" autocomplete="off"><p class="hint">A file path on this site, or an https link. Only Active questions are given to students.</p></div>
    </div>
    <div class="dlg-f"><button class="btn" type="button" data-close>Cancel</button><button class="btn primary">Save question</button></div>
  </form>
</dialog>

<dialog id="dlgImport" aria-labelledby="dlgImpT">
  <form method="post" enctype="multipart/form-data"><?= hidden('q_import', 'questions', ['exam_id' => $selId]) ?>
    <div class="dlg-h"><h2 id="dlgImpT">Import questions</h2><button class="btn icon ghost" type="button" data-close aria-label="Close"><?= ic('x') ?></button></div>
    <div class="dlg-b"><div class="field"><label for="imp">CSV file</label><input id="imp" type="file" name="csv" accept=".csv,text/csv" required></div>
      <p class="hint">Columns: question, option A, B, C and D, correct answer (A–D), marks, difficulty (Easy, Medium or Hard), picture path. The last three are optional. Up to 500 rows, imported as Active. <a href="<?= h(self_url('questions', ['export' => 'template'])) ?>">Download the template</a>.</p></div>
    <div class="dlg-f"><button class="btn" type="button" data-close>Cancel</button><button class="btn primary">Import</button></div>
  </form>
</dialog>

<dialog id="dlgConfirm" aria-labelledby="dlgCT">
  <div class="dlg-h"><h2 id="dlgCT">Are you sure?</h2></div>
  <div class="dlg-b"><p id="confirmText"></p></div>
  <div class="dlg-f"><button class="btn" type="button" id="confirmNo">Cancel</button><button class="btn primary" type="button" id="confirmYes">Continue</button></div>
</dialog>

<div id="toasts" role="status" aria-live="polite"></div>
<script type="application/json" id="flash"><?= json_encode($flash, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>

<script nonce="<?= h($nonce) ?>">
(() => {
  'use strict';
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const SELF = <?= json_encode(basename($_SERVER['SCRIPT_NAME'])) ?>;
  const MAX_CA = <?= MAX_CA ?>;
  const IDLE_WARN = <?= IDLE_WARN ?>;

  /* Theme */
  const root = document.documentElement;
  try { const t = localStorage.getItem('cbt-theme'); if (t) root.dataset.theme = t; } catch (e) {}
  $('#themeBtn').addEventListener('click', () => {
    const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem('cbt-theme', root.dataset.theme); } catch (e) {}
  });

  /* Toast */
  function toast(text, type = 'ok') {
    const el = document.createElement('div');
    el.className = 'toast ' + type; el.textContent = text;
    $('#toasts').appendChild(el);
    setTimeout(() => el.remove(), type === 'error' ? 8000 : 4500);
  }
  try { const f = JSON.parse($('#flash').textContent); if (f) toast(f.text, f.type); } catch (e) {}

  /* Dialogs: open with data-dialog, fill fields from data-fill */
  document.addEventListener('click', e => {
    const open = e.target.closest('[data-dialog]');
    if (open) {
      const d = document.getElementById(open.dataset.dialog), form = $('form', d);
      if (form) form.reset();
      if (open.dataset.fill && form) {
        const data = JSON.parse(open.dataset.fill);
        for (const k in data) { const f = form.elements[k]; if (f) f.value = data[k]; }
      }
      if (open.dataset.title && $('.dlg-title', d)) $('.dlg-title', d).textContent = open.dataset.title;
      d.showModal();
      const first = $('input:not([type=hidden]),textarea,select', d); if (first) first.focus();
    }
    if (e.target.closest('[data-close]')) e.target.closest('dialog').close();
    if (e.target.matches('dialog')) e.target.close();
    if (e.target.closest('[data-print]')) window.print();
    const cp = e.target.closest('[data-copy]');
    if (cp) navigator.clipboard?.writeText(cp.dataset.copy).then(() => toast('PIN copied.'), () => toast('Could not copy. Select the PIN and copy it by hand.', 'warn'));
  });

  /* PIN generator (the server still checks the PIN is free) */
  const gen = $('#genPin');
  if (gen) gen.addEventListener('click', () => {
    const a = new Uint32Array(1); crypto.getRandomValues(a);
    $('#es_pin').value = String(100000 + (a[0] % 900000));
  });

  /* Confirm before destructive or sending actions */
  const dlgC = $('#dlgConfirm'); let pending = null;
  function ask(text, yes) { $('#confirmText').textContent = text; pending = yes; dlgC.showModal(); $('#confirmYes').focus(); }
  $('#confirmNo').onclick = () => { pending = null; dlgC.close(); };
  $('#confirmYes').onclick = () => { const fn = pending; pending = null; dlgC.close(); fn && fn(); };
  document.addEventListener('submit', e => {
    const f = e.target;
    if (f.dataset.confirm && !f.dataset.ok) {
      e.preventDefault();
      const by = e.submitter;
      ask(f.dataset.confirm, () => { f.dataset.ok = '1'; f.requestSubmit(by); });
    }
  });

  /* Auto-submit pickers, live table filters */
  $$('[data-autosubmit]').forEach(s => s.addEventListener('change', () => s.form.submit()));
  $$('[data-filter]').forEach(inp => inp.addEventListener('input', () => {
    const q = inp.value.trim().toLowerCase();
    $$('tbody tr', $(inp.dataset.filter)).forEach(tr => tr.hidden = q && !tr.textContent.toLowerCase().includes(q));
  }));

  /* Overview: refresh numbers every 30s (server answers 304 when nothing changed) */
  if ($('#kpis')) setInterval(async () => {
    if (document.hidden) return;
    try {
      const d = await (await fetch(SELF + '?api=stats', { headers: { Accept: 'application/json' } })).json();
      $$('[data-kpi]').forEach(el => { const v = d[el.dataset.kpi]; el.textContent = v === null || v === undefined ? '—' : v; });
    } catch (e) {}
  }, 30000);

  /* Results sheet */
  const form = $('#sheetForm');
  if (form && $('#status')) {
    const status = $('#status');
    let dirty = false;
    const recalc = tr => {
      let sum = +tr.dataset.cbt || 0, bad = false;
      $$('input', tr).forEach(i => {
        const v = Number(i.value), wrong = i.value === '' || v < 0 || v > MAX_CA || !Number.isInteger(v);
        i.classList.toggle('bad', wrong); bad = bad || wrong;
        if (!wrong) sum += v;
      });
      $('.total', tr).textContent = sum;
      return bad;
    };
    const rows = $$('tbody tr', form);
    form.addEventListener('input', e => {
      if (!e.target.matches('td input')) return;
      recalc(e.target.closest('tr'));
      const totals = rows.map(r => +$('.total', r).textContent);
      const avg = $('#avgTotal'); if (avg) avg.textContent = (totals.reduce((a, b) => a + b, 0) / totals.length).toFixed(1);
      dirty = true;
      status.innerHTML = '<span class="dirty">Unsaved changes.</span> Position and grade update after you save.';
    });
    form.addEventListener('focusin', e => { if (e.target.matches('td input')) e.target.select(); });
    form.addEventListener('keydown', e => {   // Enter moves down the column like a spreadsheet
      if (e.key !== 'Enter' || !e.target.matches('td input')) return;
      e.preventDefault();
      const td = e.target.closest('td'), idx = td.cellIndex;
      let tr = td.parentElement;
      do { tr = e.shiftKey ? tr.previousElementSibling : tr.nextElementSibling; } while (tr && (tr.hidden || $$('input', tr)[idx - 1]?.disabled));
      const next = tr && $$('input', tr)[idx - 1]; if (next) next.focus();
    });
    form.addEventListener('submit', e => {
      const action = e.submitter && e.submitter.value;
      if (action === 'results_pull') { dirty = false; return; }
      const invalid = rows.filter(recalc).length;
      if (invalid) { e.preventDefault(); toast(invalid + ' row(s) have a score that is empty or above ' + MAX_CA + '. Fix the red boxes.', 'error'); return; }
      if (action === 'results_send' && !form.dataset.ok) {
        e.preventDefault();
        const by = e.submitter;
        ask('Send results for ' + rows.length + ' students, with CA and CBT scores together? The form master will see them straight away.', () => { form.dataset.ok = '1'; dirty = false; form.requestSubmit(by); });
        return;
      }
      dirty = false;
    });
    window.addEventListener('beforeunload', e => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
    rows.forEach(recalc);
  }

  /* Live monitor: WebRTC video straight from the student's browser.
     camera_signal.php only relays the connection handshake text. */
  const grid = $('#monitorGrid');
  if (grid) {
    const ICE = [{ urls: 'stun:stun.l.google.com:19302' }];
    // STUN-only works on most networks. A strict school firewall can need a TURN relay.
    const tiles = new Map();
    const send = (id, type, payload) => fetch('camera_signal.php', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: Number(id), role: 'teacher', type, payload })
    }).catch(() => {});

    function setState(t, live, label) {
      $('.tag i', t.node).classList.toggle('on', live);
      $('.st', t.node).textContent = label;
      $('.ph', t.node).hidden = live;
      if (!live) $('.ph', t.node).textContent = label === 'Connecting' ? 'Connecting…' : 'Disconnected';
    }
    function drop(t) {
      if (t.pc) { t.pc.close(); t.pc = null; }
      $('video', t.node).srcObject = null;
      setState(t, false, 'Offline');
    }
    async function onOffer(t, offer) {
      const pc = t.pc = new RTCPeerConnection({ iceServers: ICE });
      pc.onicecandidate = e => e.candidate && send(t.id, 'candidate', JSON.stringify(e.candidate));
      pc.ontrack = e => { $('video', t.node).srcObject = e.streams[0]; setState(t, true, 'LIVE'); };
      pc.onconnectionstatechange = () => {
        if (['failed', 'closed'].includes(pc.connectionState)) drop(t);
        if (pc.connectionState === 'disconnected') setTimeout(() => { if (t.pc === pc && pc.connectionState === 'disconnected') drop(t); }, 6000);
      };
      await pc.setRemoteDescription(new RTCSessionDescription(offer));
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      send(t.id, 'answer', JSON.stringify(answer));
    }
    async function poll(t) {
      if (!t.alive) return;
      try {
        const d = await (await fetch(`camera_signal.php?session_id=${t.id}&role=teacher&after_id=${t.after}`)).json();
        if (d.ok && d.messages.length) {
          t.after = d.max_id;
          for (const m of d.messages) {
            if (m.type === 'offer' && !t.pc) await onOffer(t, JSON.parse(m.payload));
            else if (m.type === 'candidate' && t.pc) { try { await t.pc.addIceCandidate(JSON.parse(m.payload)); } catch (e) {} }
            else if (m.type === 'bye') drop(t);
          }
        }
      } catch (e) {}
      setTimeout(() => poll(t), document.hidden ? 5000 : 1500);
    }
    const mm = s => String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
    function paintInfo(t, s) {
      const el = $('.m-idle', t.node), quiet = typeof s.idle === 'number' && s.idle > IDLE_WARN;
      t.node.classList.toggle('quiet', quiet);
      el.classList.toggle('warn', quiet);
      el.classList.toggle('muted', !quiet);
      el.textContent = (typeof s.left === 'number' ? mm(s.left) + ' left · ' : '') + (typeof s.idle === 'number' ? (quiet ? 'quiet for ' + s.idle + 's' : 'active') : '');
    }
    function add(s) {
      if (tiles.has(s.session_id)) { const t = tiles.get(s.session_id); $('.m-meta', t.node).textContent = s.meta; paintInfo(t, s); return; }
      const node = $('#tileTpl').content.firstElementChild.cloneNode(true);
      $('.m-name', node).textContent = s.name; $('.m-meta', node).textContent = s.meta;
      $('.full', node).onclick = () => $('video', node).requestFullscreen?.();
      grid.appendChild(node);
      const t = { id: s.session_id, node, pc: null, after: 0, alive: true };
      paintInfo(t, s);
      tiles.set(s.session_id, t); poll(t);
    }
    async function refresh() {
      try {
        const d = await (await fetch(SELF + '?api=live', { headers: { Accept: 'application/json' }, cache: 'no-store' })).json();
        const ids = new Set(d.sessions.map(s => s.session_id));
        d.sessions.forEach(add);
        for (const [id, t] of tiles) if (!ids.has(id)) { t.alive = false; drop(t); t.node.remove(); tiles.delete(id); }
        $('#monitorEmpty').hidden = tiles.size > 0;
        $('#liveText').textContent = tiles.size + ' student(s) sitting an exam now.';
        const n = $('#liveCount'); if (n) { n.textContent = tiles.size; n.classList.toggle('live', tiles.size > 0); }
      } catch (e) {}
    }
    refresh(); setInterval(refresh, 12000);   // tiles are added and removed in place; connections are never reloaded
  }
})();
</script>
</body>
</html>