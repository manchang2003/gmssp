<?php
declare(strict_types=1);

/* ════════════════════════════════════════════════════════════════
   GMSSP CBT portal: shared settings and helpers
   Loaded by cbtexam1.php and cbt_api.php.
   Needs PHP 8.0+, MySQL/MariaDB and configure.php (creates $conn = mysqli).
   Run cbt_migration.sql once before using this version.
════════════════════════════════════════════════════════════════ */

/* ── SETTINGS: change these here ──────────────────────────────── */
const CBT_LOGO                  = 'GMSS Pankshin ICT Globe Emblem (1).png'; // file sits next to cbtexam1.php
const CBT_DEFAULT_MAX_QUESTIONS = 50;   // used when an exam has no max_questions value
const CBT_SECS_PER_QUESTION     = 59;   // per-question countdown ring; 0 = switch it off
const CBT_FALLBACK_SECS_PER_Q   = 59;   // only used when an exam has no duration_minutes
const CBT_SUBMIT_GRACE_SECS     = 15;   // allowance for slow networks after the deadline
const CBT_LOGIN_WINDOW_SECS     = 600;  // look-back window for failed logins
const CBT_LOGIN_MAX_FAILS_USER  = 5;    // wrong PINs allowed per username in that window
const CBT_LOGIN_MAX_FAILS_IP    = 80;   // per school/network address (many students may share one)
const CBT_CAMERA_GRACE_SECS     = 90;   // compulsory camera: how long it may be off before answers are refused
const CBT_PING_SECS             = 30;   // how often the page syncs the server clock
const CBT_LOG_CAP_PER_SESSION   = 400;  // stops a broken browser from flooding the activity log
const CBT_STUN_URLS             = ['stun:stun.l.google.com:19302'];
/* TURN relays help on strict school networks. Example:
   [['urls' => 'turn:turn.example.com:3478', 'username' => 'user', 'credential' => 'secret']]
   (the browser needs these values, so use a dedicated low-privilege TURN account) */
const CBT_TURN_SERVERS          = [];

const CBT_SESSION_KEYS = ['cbt_student', 'cbt_fullname', 'cbt_teacher', 'cbt_course', 'cbt_class', 'cbt_term', 'cbt_exam_id', 'cbt_session_id'];

/* ── Errors: log them, never show them to students ────────────── */
ini_set('display_errors', '0');
ini_set('log_errors', '1');
set_exception_handler(static function (Throwable $t): void {
    error_log('[CBT] ' . get_class($t) . ': ' . $t->getMessage() . ' in ' . $t->getFile() . ':' . $t->getLine());
    if (!headers_sent()) http_response_code(500);
    if (defined('CBT_API')) {
        if (!headers_sent()) header('Content-Type: application/json; charset=utf-8');
        echo '{"ok":false,"code":"server"}';
    } else {
        if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GMSSP CBT portal</title>'
           . '<body style="font:16px/1.5 system-ui,sans-serif;max-width:480px;margin:15vh auto;padding:0 20px;text-align:center">'
           . '<h1 style="font-size:22px">Something went wrong</h1><p>Please wait a moment and reload the page. If it keeps happening, tell your teacher.</p></body>';
    }
    exit;
});

require_once __DIR__ . '/configure.php';
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
if (!isset($conn) || !($conn instanceof mysqli)) {
    throw new RuntimeException('configure.php did not create a mysqli connection in $conn');
}
$conn->set_charset('utf8mb4');

/* ── Small helpers ────────────────────────────────────────────── */
function e($v): string { return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function db_all(mysqli $c, string $sql, string $types = '', array $p = []): array {
    $st = $c->prepare($sql);
    if ($types !== '') $st->bind_param($types, ...$p);
    $st->execute();
    $rs   = $st->get_result();
    $rows = $rs ? $rs->fetch_all(MYSQLI_ASSOC) : [];
    $st->close();
    return $rows;
}
function db_one(mysqli $c, string $sql, string $types = '', array $p = []): ?array { return db_all($c, $sql, $types, $p)[0] ?? null; }
function db_run(mysqli $c, string $sql, string $types = '', array $p = []): int {
    $st = $c->prepare($sql);
    if ($types !== '') $st->bind_param($types, ...$p);
    $st->execute();
    $n = (int)$st->affected_rows;
    $st->close();
    return $n;
}
function db_insert(mysqli $c, string $sql, string $types = '', array $p = []): int {
    $st = $c->prepare($sql);
    if ($types !== '') $st->bind_param($types, ...$p);
    $st->execute();
    $id = (int)$st->insert_id;
    $st->close();
    return $id;
}
function json_out(array $data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}
function client_ip(): string { return substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45); }
function cbt_https(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}
function cbt_ice(): array {
    $o = [];
    foreach (CBT_STUN_URLS as $u) $o[] = ['urls' => $u];
    foreach (CBT_TURN_SERVERS as $t) $o[] = $t;
    return $o;
}

/* ── Session + CSRF ───────────────────────────────────────────── */
function cbt_session_start(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    ini_set('session.use_strict_mode', '1');     // refuses session IDs the server did not create
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax', 'secure' => cbt_https()]);
    session_start();
}
function csrf_token(): string {
    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function csrf_ok($t): bool {
    return is_string($t) && !empty($_SESSION['csrf']) && is_string($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $t);
}
function cbt_send_headers(string $nonce): void {
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');                 // questions must never be cached
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: camera=(self), microphone=(), geolocation=()');
    if (cbt_https()) header('Strict-Transport-Security: max-age=15552000');
    header("Content-Security-Policy: default-src 'self'; script-src 'nonce-$nonce'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'");
}

/* ── Activity log (never allowed to break an exam) ────────────── */
function cbt_log(mysqli $c, ?int $session_id, ?string $student, string $type, string $desc = ''): void {
    try {
        db_run($c, "INSERT INTO cbt_activity_log (session_id, student_username, event_type, description, ip_address, user_agent, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, NOW())", 'isssss', [
            $session_id, $student, mb_substr($type, 0, 40), mb_substr($desc, 0, 255),
            client_ip(), mb_substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255),
        ]);
    } catch (Throwable $t) {
        error_log('[CBT] log failed: ' . $t->getMessage());
    }
}
function cbt_log_room(mysqli $c, int $session_id): bool {
    $r = db_one($c, "SELECT COUNT(*) AS n FROM cbt_activity_log WHERE session_id = ?", 'i', [$session_id]);
    return (int)($r['n'] ?? 0) < CBT_LOG_CAP_PER_SESSION;
}

/* ── Login rate limiting ──────────────────────────────────────── */
function login_blocked(mysqli $c, string $username, string $ip): bool {
    $u = db_one($c, "SELECT COUNT(*) AS n FROM cbt_login_attempts WHERE student_username = ? AND success = 0 AND attempted_at > DATE_SUB(NOW(), INTERVAL ? SECOND)", 'si', [$username, CBT_LOGIN_WINDOW_SECS]);
    if ((int)($u['n'] ?? 0) >= CBT_LOGIN_MAX_FAILS_USER) return true;
    $i = db_one($c, "SELECT COUNT(*) AS n FROM cbt_login_attempts WHERE ip_address = ? AND success = 0 AND attempted_at > DATE_SUB(NOW(), INTERVAL ? SECOND)", 'si', [$ip, CBT_LOGIN_WINDOW_SECS]);
    return (int)($i['n'] ?? 0) >= CBT_LOGIN_MAX_FAILS_IP;
}
function record_attempt(mysqli $c, string $username, string $ip, bool $ok): void {
    db_run($c, "INSERT INTO cbt_login_attempts (student_username, ip_address, success, attempted_at) VALUES (?, ?, ?, NOW())", 'ssi', [$username, $ip, $ok ? 1 : 0]);
    if (random_int(1, 100) === 1) db_run($c, "DELETE FROM cbt_login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 2 DAY)");
}

/* ── Attempt state (the server clock is the only clock that counts) ──
   left_secs = seconds until the official deadline (negative once it has passed). */
function load_attempt(mysqli $c, int $sid, ?string $student): ?array {
    $fallback = (int)CBT_FALLBACK_SECS_PER_Q;
    $sql = "SELECT s.id, s.student_username, s.status, s.exam_id, s.course_name, s.class_level, s.term, s.total_questions,
                   TIMESTAMPDIFF(SECOND, s.start_time, NOW()) AS elapsed,
                   COALESCE(TIMESTAMPDIFF(SECOND, NOW(), s.deadline_at),
                            COALESCE(NULLIF(e.duration_minutes, 0) * 60, s.total_questions * $fallback) - TIMESTAMPDIFF(SECOND, s.start_time, NOW())) AS left_secs,
                   e.camera_required, e.results_released
            FROM cbt_sessions s LEFT JOIN cbt_exams e ON e.id = s.exam_id
            WHERE s.id = ?";
    $types = 'i'; $p = [$sid];
    if ($student !== null) { $sql .= " AND s.student_username = ?"; $types .= 's'; $p[] = $student; }
    $row = db_one($c, $sql . " LIMIT 1", $types, $p);
    if ($row) { $row['left_secs'] = (int)$row['left_secs']; $row['elapsed'] = (int)$row['elapsed']; }
    return $row;
}

/* Marks the attempt finished and scores it on the server. Safe to call twice:
   only the first call changes anything. $trigger is 'student' or 'sweeper'. */
function finalize_session(mysqli $c, int $sid, string $trigger): ?array {
    $c->begin_transaction();
    try {
        $lock = db_one($c, "SELECT status FROM cbt_sessions WHERE id = ? FOR UPDATE", 'i', [$sid]);
        if (!$lock || $lock['status'] !== 'in_progress') { $c->rollback(); return null; }
        $a = load_attempt($c, $sid, null);
        if (!$a) { $c->rollback(); return null; }

        $rows = db_all($c, "SELECT q.marks, q.correct_answer, a.selected_option
                            FROM cbt_session_questions sq
                            JOIN cbt_questions q ON q.id = sq.question_id
                            LEFT JOIN cbt_answers a ON a.session_id = sq.session_id AND a.question_id = sq.question_id
                            WHERE sq.session_id = ?", 'i', [$sid]);
        $raw = 0; $total = 0; $answered = 0;
        foreach ($rows as $r) {
            $marks = (int)$r['marks']; $total += $marks;
            $given = $r['selected_option'];
            if ($given !== null && $given !== '') {
                $answered++;
                if (strtoupper((string)$given) === strtoupper((string)$r['correct_answer'])) $raw += $marks;
            }
        }
        $count      = count($rows) ?: (int)$a['total_questions'];
        $unanswered = max(0, $count - $answered);
        $score60    = $total > 0 ? round(($raw / $total) * 60, 1) : 0.0;
        $pct        = $total > 0 ? round(($raw / $total) * 100, 2) : 0.0;

        $left = (int)$a['left_secs'];
        if ($trigger === 'sweeper' || $left < -CBT_SUBMIT_GRACE_SECS) $method = 'timeout';
        elseif ($left <= 3)                                            $method = 'auto';
        else                                                           $method = 'manual';
        $status = $method === 'manual' ? 'completed' : 'timed_out';
        $taken  = max(0, $left < 0 ? (int)$a['elapsed'] + $left : (int)$a['elapsed']);

        db_run($c, "UPDATE cbt_sessions SET status = ?, end_time = NOW(), raw_score = ?, exam_score_60 = ?, total_marks = ?,
                           answered_count = ?, unanswered_count = ?, percentage = ?, submission_method = ?, time_taken_secs = ?
                    WHERE id = ? AND status = 'in_progress'",
            'sidiiidsii', [$status, $raw, $score60, $total, $answered, $unanswered, $pct, $method, $taken, $sid]);
        $c->commit();
    } catch (Throwable $t) {
        try { $c->rollback(); } catch (Throwable $ignore) {}
        throw $t;
    }

    $event = ['manual' => 'exam_submitted', 'auto' => 'exam_auto_submitted', 'timeout' => 'exam_timed_out'][$method];
    cbt_log($c, $sid, (string)$a['student_username'], $event, "Score $raw/$total, answered $answered of $count ($method)");

    return [
        'course' => (string)$a['course_name'], 'class' => (string)$a['class_level'], 'term' => (string)$a['term'],
        'raw_score' => $raw, 'total_marks' => $total, 'score_60' => $score60, 'percentage' => $pct,
        'answered' => $answered, 'question_count' => $count, 'status' => $status, 'method' => $method,
        'released' => $a['results_released'] === null ? true : (int)$a['results_released'] === 1,
    ];
}

/* Finishes attempts whose time ran out and whose student never came back. */
function sweep_expired(mysqli $c, int $limit = 15): void {
    $rows = db_all($c, "SELECT id FROM cbt_sessions WHERE status = 'in_progress' AND deadline_at IS NOT NULL
                        AND deadline_at < DATE_SUB(NOW(), INTERVAL ? SECOND) LIMIT ?", 'ii', [CBT_SUBMIT_GRACE_SECS + 30, $limit]);
    foreach ($rows as $r) {
        try { finalize_session($c, (int)$r['id'], 'sweeper'); }
        catch (Throwable $t) { error_log('[CBT] sweep failed for ' . $r['id'] . ': ' . $t->getMessage()); }
    }
}
