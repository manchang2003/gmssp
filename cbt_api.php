<?php
declare(strict_types=1);

/* ════════════════════════════════════════════════════════════════
   GMSSP CBT portal: JSON endpoint used by the exam page
   POST only. Actions: save (autosave answers/flags), ping (clock sync),
   event (connection and camera events).

   The student and the attempt always come from the PHP session, never
   from the request body, so one student cannot write to another's exam.
════════════════════════════════════════════════════════════════ */

const CBT_API = true;
require_once __DIR__ . '/cbt_bootstrap.php';

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') json_out(['ok' => false, 'code' => 'method'], 405);

cbt_session_start();
$student = $_SESSION['cbt_student'] ?? null;
$sid     = (int)($_SESSION['cbt_session_id'] ?? 0);
$csrfOk  = csrf_ok($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
session_write_close();   // release the session lock so camera and other requests are not blocked

if (!$student || $sid <= 0) json_out(['ok' => false, 'code' => 'auth'], 401);

$raw = file_get_contents('php://input', false, null, 0, 65536);
$in  = json_decode($raw === false ? '' : $raw, true);
if (!is_array($in)) json_out(['ok' => false, 'code' => 'bad_request'], 400);

if (!$csrfOk) {
    cbt_log($conn, $sid, (string)$student, 'suspicious', 'Request without a valid security token');
    json_out(['ok' => false, 'code' => 'csrf'], 403);
}

$att = load_attempt($conn, $sid, (string)$student);   // filtered by the student in the session
if (!$att) {
    cbt_log($conn, $sid, (string)$student, 'suspicious', 'Attempt does not belong to this student');
    json_out(['ok' => false, 'code' => 'auth'], 403);
}
$left = (int)$att['left_secs'];
if ($att['status'] !== 'in_progress') json_out(['ok' => false, 'code' => 'closed', 'left' => 0]);

$action = (string)($in['action'] ?? '');

/* ── Event log: only known event types, descriptions are fixed text ── */
if ($action === 'event') {
    $map = [
        'offline'             => 'Internet connection lost',
        'online'              => 'Internet connection restored',
        'camera_connected'    => 'Camera started',
        'camera_disconnected' => 'Camera disconnected',
        'camera_reconnected'  => 'Camera reconnected',
        'camera_denied'       => 'Camera permission denied',
    ];
    $type = (string)($in['type'] ?? '');
    if (!isset($map[$type])) json_out(['ok' => false, 'code' => 'bad_event', 'left' => $left]);
    $detail = preg_replace('/[^A-Za-z0-9 .,_-]/', '', mb_substr((string)($in['detail'] ?? ''), 0, 40)) ?? '';
    if (cbt_log_room($conn, $sid)) cbt_log($conn, $sid, (string)$student, $type, $map[$type] . ($detail !== '' ? " ($detail)" : ''));
    json_out(['ok' => true, 'left' => $left]);
}

/* ── Clock sync ── */
if ($action === 'ping') {
    db_run($conn, "UPDATE cbt_sessions SET last_seen_at = NOW() WHERE id = ? AND status = 'in_progress'", 'i', [$sid]);
    if ($left < -CBT_SUBMIT_GRACE_SECS) json_out(['ok' => false, 'code' => 'expired', 'left' => $left]);
    json_out(['ok' => true, 'left' => max(0, $left)]);
}

/* ── Autosave ── */
if ($action === 'save') {
    if ($left < -CBT_SUBMIT_GRACE_SECS) json_out(['ok' => false, 'code' => 'expired', 'left' => $left]);

    // Compulsory camera: refuse answers when the camera has been off for too long
    if ((int)$att['camera_required'] === 1) {
        $ev = db_one($conn, "SELECT event_type, TIMESTAMPDIFF(SECOND, created_at, NOW()) AS age FROM cbt_activity_log
                             WHERE session_id = ? AND event_type IN ('camera_connected','camera_reconnected','camera_disconnected','camera_denied')
                             ORDER BY id DESC LIMIT 1", 'i', [$sid]);
        $bad = $ev ? in_array($ev['event_type'], ['camera_disconnected', 'camera_denied'], true) : true;
        $age = $ev ? (int)$ev['age'] : (int)$att['elapsed'];
        if ($bad && $age > CBT_CAMERA_GRACE_SECS) {
            json_out(['ok' => false, 'code' => 'camera_required', 'left' => max(0, $left)]);
        }
    }

    $changes = $in['changes'] ?? null;
    if (!is_array($changes) || !$changes || count($changes) > 60) json_out(['ok' => false, 'code' => 'bad_request'], 400);

    $ids = [];
    foreach ($changes as $ch) { if (is_array($ch) && isset($ch['q']) && is_numeric($ch['q'])) $ids[(int)$ch['q']] = true; }
    $ids = array_keys($ids);
    if (!$ids) json_out(['ok' => false, 'code' => 'bad_request'], 400);

    // Only questions assigned to THIS attempt are accepted
    $in_marks = implode(',', array_fill(0, count($ids), '?'));
    $valid = [];
    foreach (db_all($conn, "SELECT q.id, q.option_a, q.option_b, q.option_c, q.option_d
                            FROM cbt_session_questions sq JOIN cbt_questions q ON q.id = sq.question_id
                            WHERE sq.session_id = ? AND sq.question_id IN ($in_marks)",
                    'i' . str_repeat('i', count($ids)), array_merge([$sid], $ids)) as $r) {
        $valid[(int)$r['id']] = $r;
    }

    $stA = $conn->prepare("INSERT INTO cbt_answers (session_id, student_username, question_id, selected_option, is_flagged, answered_at, updated_at)
                           VALUES (?, ?, ?, ?, 0, NOW(), NOW())
                           ON DUPLICATE KEY UPDATE selected_option = VALUES(selected_option), answered_at = NOW(), updated_at = NOW()");
    $stF = $conn->prepare("INSERT INTO cbt_answers (session_id, student_username, question_id, selected_option, is_flagged, answered_at, updated_at)
                           VALUES (?, ?, ?, NULL, ?, NOW(), NOW())
                           ON DUPLICATE KEY UPDATE is_flagged = VALUES(is_flagged), updated_at = NOW()");

    $saved = 0; $rejected = 0;
    $conn->begin_transaction();
    try {
        foreach ($changes as $ch) {
            if (!is_array($ch) || !isset($ch['q']) || !is_numeric($ch['q'])) { $rejected++; continue; }
            $qid = (int)$ch['q'];
            if (!isset($valid[$qid])) { $rejected++; continue; }

            if (array_key_exists('a', $ch)) {
                $opt = $ch['a'];
                if ($opt !== null) {
                    $opt = is_string($opt) ? strtoupper($opt) : '';
                    if (!in_array($opt, ['A', 'B', 'C', 'D'], true) || trim((string)$valid[$qid]['option_' . strtolower($opt)]) === '') { $rejected++; continue; }
                }
                $stA->bind_param('isis', $sid, $student, $qid, $opt);
                $stA->execute(); $saved++;
            }
            if (array_key_exists('f', $ch)) {
                $flag = ((int)$ch['f']) === 1 ? 1 : 0;
                $stF->bind_param('isii', $sid, $student, $qid, $flag);
                $stF->execute(); $saved++;
            }
        }
        $conn->commit();
    } catch (Throwable $t) {
        try { $conn->rollback(); } catch (Throwable $ignore) {}
        throw $t;
    }
    $stA->close(); $stF->close();

    if ($rejected > 0 && cbt_log_room($conn, $sid)) {
        cbt_log($conn, $sid, (string)$student, 'suspicious', "$rejected answer change(s) rejected (invalid question or option)");
    }
    json_out(['ok' => true, 'saved' => $saved, 'rejected' => $rejected, 'left' => max(0, $left)]);
}

json_out(['ok' => false, 'code' => 'bad_action'], 400);
