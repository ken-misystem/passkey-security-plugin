<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Doctrine\DBAL\Connection;

/** Read-only presentation. Never returns codes, credential IDs, hashes or secret payloads. */
final class EnrollmentOverview
{
    public function __construct(private Connection $db, private Store $store) {}

    public function forStaff(string $subject, int $now): array
    {
        if (!preg_match('/^member:[1-9][0-9]*$/D', $subject)) throw new \InvalidArgumentException('staff_subject_required');
        $f = $this->store->factor($subject);
        $lastIssue = $this->db->fetchOne("SELECT MAX(created) FROM plg_ps_audit WHERE subject=? AND action IN ('initial_enrollment_code_issued','enrollment_ticket_issued')", [$subject]);
        $recovery = $this->db->fetchAssociative('SELECT created,completed,status FROM plg_ps_recovery WHERE subject=? ORDER BY created DESC,id DESC LIMIT 1', [$subject]);
        $issued = max((int)$lastIssue, (int)($recovery['created'] ?? 0));
        $claimed = (int)$this->db->fetchOne("SELECT MAX(created) FROM plg_ps_audit WHERE subject=? AND action='enrollment_ticket_claimed'", [$subject]);
        $firstTotp = $this->db->fetchAssociative("SELECT id,created FROM plg_ps_audit WHERE subject=? AND action='totp_verified' AND created>=? ORDER BY created,id LIMIT 1", [$subject,max($issued,$claimed)]);
        $passkeyAt = (int)$this->db->fetchOne('SELECT MIN(created) FROM plg_ps_credential WHERE subject=? AND revoked=0 AND created>0', [$subject]);
        $hasPasskey = (int)$this->db->fetchOne('SELECT COUNT(*) FROM plg_ps_credential WHERE subject=? AND revoked=0', [$subject]) > 0;
        $hasTotp = (int)($f['confirmed'] ?? 0) === 1;
        $registered = $hasPasskey || $hasTotp;
        $resetRequired = $this->store->resetRequired($subject);
        $knownCredential = (int)$this->db->fetchOne('SELECT COUNT(*) FROM plg_ps_credential WHERE subject=?', [$subject]) > 0;
        $expired = $f && $f['ticket'] !== '' && (int)$f['expires'] < $now;
        $state = match (true) {
            $registered && !$resetRequired => 'complete',
            $registered => 'password_pending',
            $f && $f['ticket'] !== '' && $expired => 'expired',
            $f && $f['ticket'] !== '' => 'issued',
            $f && $f['secret'] !== '' => 'factor_pending',
            $recovery && $recovery['status'] === 'claimed' && $claimed >= (int)$recovery['created'] => 'claimed',
            $knownCredential || ($recovery && $recovery['status'] !== 'completed') => 'recovery_required',
            $claimed > 0 => 'claimed',
            $f && (int)$f['expires'] > 0 => 'unknown',
            default => 'not_issued',
        };
        $labels = ['complete'=>'登録完了', 'password_pending'=>'追加認証登録済み・パスワード変更待ち',
            'expired'=>'登録リンク・コードの有効期限切れ', 'issued'=>'登録リンク・コード発行済み・本人の操作待ち',
            'factor_pending'=>'登録リンク・コード使用済み・認証アプリの登録途中', 'claimed'=>'登録リンク・コード使用済み・ログイン方法の登録待ち',
            'recovery_required'=>'本人確認を伴う復旧が必要', 'unknown'=>'登録の許可は使用済みまたは無効（記録不足）', 'not_issued'=>'未発行'];
        $next = match ($state) {
            'complete'=>'初回登録コードの再発行は不要です。登録済みの方法でログインできます。',
            'password_pending'=>'スタッフ本人が画面の案内に従ってパスワードを変更してください。',
            'issued'=>'本人が最新のメールの登録リンクを開くか、受け取ったコードを入力してパスキーか認証アプリを登録します。',
            'expired'=>'本人確認のうえ、新しい登録リンクまたはコードを発行してください。古いものは使えません。',
            'claimed','factor_pending'=>'本人が登録中の画面で続けてください。確認期限が切れて再開できない場合は、本人確認を伴う復旧が必要です。',
            'not_issued'=>'本人確認のうえ、渡し方を選んで登録リンク・コードを発行してください。',
            default=>'初回登録コードで既存の認証器は解除できません。管理担当者の本人確認を伴う復旧手順を利用してください。',
        };
        // Records lack per-code IDs. Show factual events, not invented per-issue outcomes.
        $records = $this->db->fetchAllAssociative("SELECT action,created FROM plg_ps_audit WHERE subject=? AND (action IN ('initial_enrollment_code_issued','enrollment_ticket_issued','enrollment_ticket_claimed','passkey_registered','staff_enrollment_completed','staff_recovery_completed','initial_link_claimed','staff_initial_request_notified','staff_initial_request_no_new_notice') OR action LIKE 'staff_mail_initial_%_by:%' OR action LIKE 'staff_recovery_started:%' OR id=?) ORDER BY created DESC,id DESC LIMIT 31", [$subject,$firstTotp['id'] ?? '']);
        $events = [];
        $eventLabels = ['initial_enrollment_code_issued'=>'初回登録の許可を発行', 'enrollment_ticket_issued'=>'登録コードを発行',
            'enrollment_ticket_claimed'=>'登録用の許可を確認（リンク・コード使用済み）', 'initial_link_claimed'=>'本人が登録リンクから登録を開始', 'passkey_registered'=>'パスキーを登録',
            'totp_verified'=>'認証アプリのコード確認が完了', 'staff_enrollment_completed'=>'ログイン方法の登録が完了',
            'staff_recovery_completed'=>'本人確認を伴う復旧が完了', 'staff_initial_request_notified'=>'スタッフから登録リンク・コード発行／再開の依頼',
            'staff_initial_request_no_new_notice'=>'スタッフから発行・再開の依頼（重複通知などは抑止）'];
        foreach (array_slice($records,0,30) as $row) {
            $action = $row['action']; $label = $eventLabels[$action] ?? null;
            if (preg_match('/^staff_mail_initial_(email|display)_by:([1-9][0-9]*)$/D', $action, $m))
                $label = ($m[1] === 'email' ? 'コードを本人メールへ予約' : 'コードを一度だけ画面に表示').'（管理者ID '.$m[2].'）';
            if(preg_match('/^staff_mail_initial_link_by:([1-9][0-9]*)$/D',$action,$m))$label='登録リンクを本人メールへ予約（管理者ID '.$m[1].'）';
            if (str_starts_with($action,'staff_recovery_started:')) $label = '本人確認後に復旧コードを発行';
            if ($label !== null) $events[] = ['at'=>(int)$row['created'], 'label'=>$label];
        }
        $completed = (int)$this->db->fetchOne("SELECT MAX(created) FROM plg_ps_audit WHERE subject=? AND action IN ('staff_enrollment_completed','staff_recovery_completed') AND created>=?", [$subject,$issued]);
        if ($registered && !$completed) {
            $candidates = array_filter([$hasPasskey ? $passkeyAt : 0,$hasTotp ? (int)($firstTotp['created'] ?? 0) : 0]);
            $completed = $candidates ? min($candidates) : 0;
        }
        return ['state'=>$state, 'label'=>$labels[$state], 'next'=>$next, 'issued_at'=>$issued ?: null,
            'expires_at'=>(int)($f['expires'] ?? 0) ?: null, 'claimed_at'=>$claimed ?: null,
            'completed_at'=>$registered && !$resetRequired ? ($completed ?: null) : null,
            'code_unused'=>$f && $f['ticket'] !== '', 'events'=>$events, 'history_truncated'=>count($records)>30,
            'as_of'=>$now, 'passkey_registered'=>$hasPasskey, 'totp_registered'=>$hasTotp];
    }
}
