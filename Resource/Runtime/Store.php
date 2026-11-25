<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Doctrine\DBAL\Connection;

final class Store
{
    /** Classify only known transient lock failures; PostgreSQL DBAL 3 reports 55P03 as DriverException. */
    public static function isTransientDatabaseFailure(\Throwable $error): bool
    {
        return $error instanceof \Doctrine\DBAL\Exception\LockWaitTimeoutException
            || $error instanceof \Doctrine\DBAL\Exception\DeadlockException
            || ($error instanceof \Doctrine\DBAL\Exception\DriverException && $error->getSQLState()==='55P03');
    }
    public function __construct(private Connection $db, private Config $config) {}
    public function install(): void
    {
        // Dedicated tables only. No ALTER, UPDATE or deletion of EC-CUBE business tables.
        $sql = [
            'CREATE TABLE IF NOT EXISTS plg_ps_meta (name VARCHAR(64) PRIMARY KEY, value VARCHAR(128) NOT NULL)',
            'CREATE TABLE IF NOT EXISTS plg_ps_reset (subject VARCHAR(64) PRIMARY KEY, required INTEGER NOT NULL, baseline VARCHAR(64) NOT NULL)',
            'CREATE TABLE IF NOT EXISTS plg_ps_factor (subject VARCHAR(64) PRIMARY KEY, secret TEXT NOT NULL, confirmed INTEGER NOT NULL, last_step BIGINT NOT NULL, generation INTEGER NOT NULL, ticket VARCHAR(64) NOT NULL, expires BIGINT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS plg_ps_credential (id VARCHAR(64) PRIMARY KEY, subject VARCHAR(64) NOT NULL, credential TEXT NOT NULL, public_key TEXT NOT NULL, counter BIGINT NOT NULL, revision BIGINT NOT NULL, backup_eligible INTEGER NOT NULL, revoked INTEGER NOT NULL)',
            'CREATE TABLE IF NOT EXISTS plg_ps_limit (bucket VARCHAR(64) PRIMARY KEY, starts BIGINT NOT NULL, attempts INTEGER NOT NULL)',
            'CREATE TABLE IF NOT EXISTS plg_ps_audit (id VARCHAR(64) PRIMARY KEY, subject VARCHAR(64) NOT NULL, action VARCHAR(64) NOT NULL, created BIGINT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS plg_ps_recovery (id VARCHAR(64) PRIMARY KEY, subject VARCHAR(64) NOT NULL, case_digest VARCHAR(64) NOT NULL UNIQUE, operator_digest VARCHAR(64) NOT NULL, prior_factor_digest VARCHAR(64) NOT NULL, generation INTEGER NOT NULL, status VARCHAR(32) NOT NULL, created BIGINT NOT NULL, expires BIGINT NOT NULL, completed BIGINT NOT NULL)',
        ];
        foreach ($sql as $s) $this->db->executeStatement($s);
        $columns = $this->db->createSchemaManager()->listTableColumns('plg_ps_credential');
        foreach (['label'=>"VARCHAR(80) NOT NULL DEFAULT ''", 'created'=>'BIGINT NOT NULL DEFAULT 0',
            'revoked_at'=>'BIGINT NOT NULL DEFAULT 0', 'revoked_reason'=>"VARCHAR(32) NOT NULL DEFAULT ''"] as $name=>$type) {
            if (!isset($columns[$name])) $this->db->executeStatement('ALTER TABLE plg_ps_credential ADD '.$name.' '.$type);
        }
    }
    public function active(): bool
    {
        return $this->db->fetchOne("SELECT value FROM plg_ps_meta WHERE name='epoch'") !== false;
    }
    public function epoch(): string
    {
        $v = $this->db->fetchOne("SELECT value FROM plg_ps_meta WHERE name='epoch'");
        if (!is_string($v)) throw new \RuntimeException('security_policy_not_activated');
        return $v;
    }
    /** Deliberate one-time reopening snapshot. Call only on an approved target. */
    public function activate(array $customers, array $members=[]): int
    {
        $this->config->data();
        return $this->db->transactional(function () use ($customers, $members): int {
            if ($this->active()) throw new \RuntimeException('security_policy_already_active');
            foreach ($customers as $id => $hash) {
                $this->db->insert('plg_ps_reset', ['subject'=>'customer:'.$id, 'required'=>1,
                    'baseline'=>$this->config->digest((string)$hash)]);
            }
            foreach ($members as $id => $hash) {
                $this->db->insert('plg_ps_reset', ['subject'=>'member:'.$id, 'required'=>1,
                    'baseline'=>$this->config->digest((string)$hash)]);
            }
            $this->db->insert('plg_ps_meta', ['name'=>'epoch', 'value'=>bin2hex(random_bytes(16))]);
            $this->audit('system', 'policy_activated');
            return count($customers);
        });
    }
    public function resetRequired(string $subject): bool
    {
        $this->epoch();
        return (int)$this->db->fetchOne('SELECT required FROM plg_ps_reset WHERE subject=?', [$subject]) === 1;
    }
    public function passwordReset(string $subject, string $newHash, ?int $expectedGeneration=null): int
    {
        return $this->db->transactional(function () use ($subject, $newHash,$expectedGeneration): int {
            $factor=$this->lockSubject($subject);
            if ($expectedGeneration!==null && (int)$factor['generation']!==$expectedGeneration) throw new \RuntimeException('security_generation_changed');
            $old = $this->db->fetchAssociative('SELECT * FROM plg_ps_reset WHERE subject=?', [$subject]);
            if ($old && hash_equals($old['baseline'], $this->config->digest($newHash))) {
                throw new \RuntimeException('security_password_not_changed');
            }
            $this->db->executeStatement('UPDATE plg_ps_reset SET required=0 WHERE subject=?', [$subject]);
            $this->db->executeStatement("UPDATE plg_ps_credential SET revoked=1, revoked_at=?, revoked_reason='password_reset' WHERE subject=? AND revoked=0", [time(),$subject]);
            $this->db->executeStatement('UPDATE plg_ps_factor SET generation=generation+1 WHERE subject=?', [$subject]);
            $this->audit($subject, 'password_reset_credentials_revoked');
            return (int)$factor['generation']+1;
        });
    }
    public function credentials(string $subject): array
    {
        return $this->db->fetchAllAssociative('SELECT * FROM plg_ps_credential WHERE subject=? AND revoked=0', [$subject]);
    }
    public function credential(string $raw): array
    {
        $c = $this->db->fetchAssociative('SELECT * FROM plg_ps_credential WHERE id=? AND revoked=0', [hash('sha256', $raw)]);
        if (!$c || !hash_equals($c['credential'], Ceremony::encode($raw))) throw new \RuntimeException('security_credential_rejected');
        return $c;
    }
    public function register(string $subject, object $data, ?int $generation=null, string $label=''): int
    {
        $label = trim($label);
        if (mb_strlen($label)>80 || preg_match('/[\x00-\x1F\x7F]/u', $label)!==0) throw new \RuntimeException('security_label_invalid');
        $raw = $data->credentialId;
        return $this->db->transactional(function () use ($subject, $data, $raw, $generation, $label): int {
            $f = $this->lockSubject($subject);
            if ($generation !== null && (int)$f['generation'] !== $generation) throw new \RuntimeException('security_generation_changed');
            if (count($this->credentials($subject)) >= 10) throw new \RuntimeException('security_credential_limit');
            $this->db->insert('plg_ps_credential', ['id'=>hash('sha256', $raw), 'subject'=>$subject,
                'credential'=>Ceremony::encode($raw), 'public_key'=>$data->credentialPublicKey,
                'counter'=>(int)$data->signatureCounter, 'revision'=>0, 'backup_eligible'=>(int)$data->isBackupEligible, 'revoked'=>0,
                'label'=>$label, 'created'=>time(), 'revoked_at'=>0, 'revoked_reason'=>'']);
            $this->audit($subject, 'passkey_registered');
            return (int)$f['generation'];
        });
    }
    public function counter(array $c, int $counter, ?int $generation=null): int
    {
        return $this->db->transactional(function () use ($c,$counter,$generation): int {
            $f=$this->lockSubject($c['subject']);
            if ($generation!==null && (int)$f['generation']!==$generation) throw new \RuntimeException('security_generation_changed');
            $n = $this->db->executeStatement('UPDATE plg_ps_credential SET counter=?, revision=revision+1 WHERE id=? AND revision=? AND revoked=0',
                [$counter, $c['id'], (int)$c['revision']]);
            if ($n !== 1) throw new \RuntimeException('security_credential_concurrent_change');
            return (int)$f['generation'];
        });
    }
    public function factor(string $subject): ?array
    {
        return $this->db->fetchAssociative('SELECT * FROM plg_ps_factor WHERE subject=?', [$subject]) ?: null;
    }
    public function issueTicket(string $subject, int $now): string
    {
        if (!preg_match('/^member:[1-9][0-9]*$/D', $subject)) throw new \RuntimeException('security_staff_required');
        $f=$this->factor($subject);
        if ($f && ($f['ticket']!=='' || $f['secret']!=='' || (int)$f['confirmed']!==0 || (int)$f['expires']!==0)) throw new \RuntimeException('security_factor_exists_no_automatic_recovery');
        $ticket = Ceremony::encode(random_bytes(32));
        $this->ensureSubject($subject);
        $n=$this->db->executeStatement("UPDATE plg_ps_factor SET ticket=?, expires=? WHERE subject=? AND ticket='' AND secret='' AND confirmed=0 AND expires=0", [$this->config->digest($ticket),$now+3600,$subject]);
        if ($n!==1) throw new \RuntimeException('security_ticket_issue_race');
        $this->audit($subject, 'enrollment_ticket_issued');
        return $ticket;
    }
    public function claimTicket(string $subject, string $ticket, int $now): int
    {
        $ticket=trim($ticket);
        if(!preg_match('/^[A-Za-z0-9_-]{43}$/D',$ticket))throw new \RuntimeException('security_ticket_rejected');
        return $this->db->transactional(function () use ($subject,$ticket,$now): int {
        $f = $this->factor($subject);
        if (!$f || $f['ticket'] === '' || (int)$f['expires'] < $now
            || !hash_equals($f['ticket'], $this->config->digest($ticket))) throw new \RuntimeException('security_ticket_rejected');
        $n = $this->db->executeStatement("UPDATE plg_ps_factor SET ticket='' WHERE subject=? AND ticket=?", [$subject, $f['ticket']]);
        if ($n !== 1) throw new \RuntimeException('security_ticket_already_claimed');
        $this->db->executeStatement("UPDATE plg_ps_recovery SET status='claimed' WHERE subject=? AND generation=? AND status='issued'", [$subject,(int)$f['generation']]);
        $this->audit($subject, 'enrollment_ticket_claimed');
        return (int)$f['generation'];
        });
    }
    /** Initial enrollment only. Never turn an established factor into initial enrollment. */
    public function initialEligible(string $subject,bool $locked=false): bool
    {
        if(!preg_match('/^member:[1-9][0-9]*$/D',$subject))return false;
        $lock=$locked&&$this->db->getDatabasePlatform()->getName()==='mysql'?' FOR UPDATE':'';
        if($this->db->fetchOne('SELECT id FROM plg_ps_credential WHERE subject=? LIMIT 1'.$lock,[$subject])!==false
            ||$this->db->fetchOne('SELECT id FROM plg_ps_recovery WHERE subject=? LIMIT 1'.$lock,[$subject])!==false)return false;
        $f=$this->factor($subject);
        return !$f||($f['secret']===''&&(int)$f['confirmed']===0&&(int)$f['last_step']===-1);
    }
    /** Public edition: a pending TOTP may resume, but a prior/revoked factor never becomes initial. */
    public function publicInitialEligible(string $subject): bool
    {
        if(!preg_match('/^member:[1-9][0-9]*$/D',$subject))return false;
        if($this->db->fetchOne('SELECT id FROM plg_ps_credential WHERE subject=? LIMIT 1',[$subject])!==false
            ||$this->db->fetchOne('SELECT id FROM plg_ps_recovery WHERE subject=? LIMIT 1',[$subject])!==false)return false;
        $f=$this->factor($subject);
        return !$f||((int)$f['confirmed']===0&&(int)$f['last_step']===-1&&$f['ticket']==='');
    }
    public function issueInitialTicket(string $subject,int $now): string
    {
        return $this->db->transactional(function()use($subject,$now):string{
            if(!preg_match('/^member:([1-9][0-9]*)$/D',$subject,$id)
                ||(int)$this->db->fetchOne('SELECT work_id FROM dtb_member WHERE id=?',[(int)$id[1]])!==1)throw new \RuntimeException('security_staff_required');
            $f=$this->lockSubject($subject);
            if($f['secret']!==''||(int)$f['confirmed']!==0||(int)$f['last_step']!==-1
                ||!$this->initialEligible($subject,true))throw new \RuntimeException('security_initial_only');
            $ticket=Ceremony::encode(random_bytes(32));
            // Explicit reissue invalidates earlier codes and unfinished enrollment grants.
            $n=$this->db->executeStatement('UPDATE plg_ps_factor SET ticket=?,expires=?,generation=generation+1 WHERE subject=? AND generation=?',
                [$this->config->digest($ticket),$now+3600,$subject,(int)$f['generation']]);
            if($n!==1)throw new \RuntimeException('security_ticket_issue_race');
            $this->audit($subject,'initial_enrollment_code_issued');
            return $ticket;
        });
    }
    public function setPendingTotp(string $subject, string $secret, ?int $generation=null): void
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $enc = base64_encode($nonce.sodium_crypto_secretbox($secret, $nonce, $this->config->key()));
        $f=$this->factor($subject);
        $generation ??= (int)($f['generation']??-1);
        if ($this->db->executeStatement('UPDATE plg_ps_factor SET secret=? WHERE subject=? AND confirmed=0 AND generation=? AND secret=?', [$enc, $subject,$generation,$f['secret']??'']) !== 1) {
            throw new \RuntimeException('security_totp_already_confirmed');
        }
    }
    public function totpSecret(array $f): string
    {
        $b = base64_decode($f['secret'], true);
        if ($b === false || strlen($b) < 41) throw new \RuntimeException('security_totp_missing');
        $s = sodium_crypto_secretbox_open(substr($b, 24), substr($b, 0, 24), $this->config->key());
        if ($s === false) throw new \RuntimeException('security_totp_decryption_failed');
        return $s;
    }
    public function consumeTotp(string $subject, string $code, int $now, ?int $generation=null): int
    {
        Config::dependencies();
        $f = $this->factor($subject);
        if (!$f || ($generation!==null && (int)$f['generation']!==$generation) || !preg_match('/^[0-9]{6}$/D', $code)) throw new \RuntimeException('security_totp_rejected');
        $otp = \OTPHP\TOTP::createFromSecret($this->totpSecret($f));
        $step = intdiv($now, 30);
        foreach ([$step, $step-1, $step+1] as $s) {
            if ($s > (int)$f['last_step'] && hash_equals($otp->at($s*30), $code)) {
                $n = $this->db->executeStatement('UPDATE plg_ps_factor SET last_step=?, confirmed=1 WHERE subject=? AND last_step=? AND generation=? AND secret=?', [$s, $subject, $f['last_step'],$f['generation'],$f['secret']]);
                if ($n !== 1) throw new \RuntimeException('security_totp_replay');
                $this->audit($subject, 'totp_verified');
                return (int)$f['generation'];
            }
        }
        throw new \RuntimeException('security_totp_rejected');
    }
    public function ensureSubject(string $subject): void
    {
        if (!preg_match('/^(customer|member):[1-9][0-9]*$/D',$subject)) throw new \RuntimeException('security_subject_invalid');
        if ($this->factor($subject)) return;
        if ($this->db->getDatabasePlatform()->getName()==='postgresql') {
            $this->db->executeStatement('INSERT INTO plg_ps_factor (subject,secret,confirmed,last_step,generation,ticket,expires) VALUES (?,?,?,?,?,?,?) ON CONFLICT (subject) DO NOTHING',[$subject,'',0,-1,1,'',0]);
        } else {
            try { $this->db->insert('plg_ps_factor',['subject'=>$subject,'secret'=>'','confirmed'=>0,'last_step'=>-1,'generation'=>1,'ticket'=>'','expires'=>0]); }
            catch (\Doctrine\DBAL\Exception\UniqueConstraintViolationException $e) {}
        }
    }
    public function generation(string $subject): int { $this->ensureSubject($subject); return (int)$this->factor($subject)['generation']; }
    /** Recheck a proof against a current read, not a repeatable-read snapshot. */
    public function generationForProofRecheck(string $subject): ?int
    {
        if (!preg_match('/^(customer|member):[1-9][0-9]*$/D',$subject)) throw new \RuntimeException('security_subject_invalid');
        // Unsupported platforms fail closed rather than rely on snapshot semantics.
        if (!in_array($this->db->getDatabasePlatform()->getName(),['mysql','postgresql'],true)) return null;
        $generation=$this->db->fetchOne('SELECT generation FROM plg_ps_factor WHERE subject=? FOR UPDATE',[$subject]);
        return $generation===false?null:(int)$generation;
    }
    private function lockSubject(string $subject): array
    {
        $this->ensureSubject($subject);
        $lock=in_array($this->db->getDatabasePlatform()->getName(),['mysql','postgresql'],true)?' FOR UPDATE':'';
        return $this->db->fetchAssociative('SELECT * FROM plg_ps_factor WHERE subject=?'.$lock,[$subject]);
    }
    /** Public UI inventory deliberately omits raw IDs, keys and any TOTP/ticket information. */
    public function inventory(string $subject): array
    {
        return $this->db->fetchAllAssociative('SELECT id,label,created,revoked,revoked_at,revoked_reason FROM plg_ps_credential WHERE subject=? ORDER BY created,id',[$subject]);
    }
    public function revokeOwn(string $subject, string $id, int $expectedGeneration, int $now): int
    {
        return $this->db->transactional(function () use ($subject,$id,$expectedGeneration,$now): int {
            $f=$this->lockSubject($subject);
            if ((int)$f['generation']!==$expectedGeneration || !preg_match('/^[a-f0-9]{64}$/D',$id)) throw new \RuntimeException('security_revoke_rejected');
            $row=$this->db->fetchAssociative('SELECT id FROM plg_ps_credential WHERE id=? AND subject=? AND revoked=0',[$id,$subject]);
            if (!$row) throw new \RuntimeException('security_revoke_rejected');
            if (str_starts_with($subject,'member:') && count($this->credentials($subject))<=1 && (int)$f['confirmed']!==1) throw new \RuntimeException('security_last_staff_factor_requires_recovery');
            $this->db->executeStatement("UPDATE plg_ps_credential SET revoked=1, revoked_at=?, revoked_reason='self_revoke' WHERE id=? AND subject=? AND revoked=0",[$now,$id,$subject]);
            $this->db->executeStatement('UPDATE plg_ps_factor SET generation=generation+1 WHERE subject=?',[$subject]);
            $this->audit($subject,'passkey_revoked_self:'.substr($id,0,16));
            return (int)$f['generation']+1;
        });
    }
    /** Offline operator action only, after an independently recorded identity check. */
    public function recoverStaff(string $subject, string $currentPasswordHash, array $evidence, int $now): array
    {
        $keys=array_keys($evidence);sort($keys);
        if (!preg_match('/^member:[1-9][0-9]*$/D',$subject) || $keys!==['case_id','method','operator','subject','verified_at']
            || $evidence['subject']!==$subject || !in_array($evidence['method'],['in_person','known_channel_callback'],true)
            || !is_int($evidence['verified_at']) || $evidence['verified_at']>$now || $evidence['verified_at']<$now-900
            || !is_string($evidence['case_id']) || !preg_match('/^[A-Za-z0-9_-]{8,80}$/D',$evidence['case_id'])
            || !is_string($evidence['operator']) || !preg_match('/^[A-Za-z0-9_-]{3,80}$/D',$evidence['operator'])) throw new \RuntimeException('security_recovery_identity_check_required');
        return $this->db->transactional(function () use ($subject,$currentPasswordHash,$evidence,$now): array {
            $f=$this->lockSubject($subject);$generation=(int)$f['generation']+1;
            $id=bin2hex(random_bytes(16));$ticket=Ceremony::encode(random_bytes(32));
            $case=$this->config->digest('case:'.$evidence['case_id']);
            $this->db->insert('plg_ps_recovery',['id'=>$id,'subject'=>$subject,'case_digest'=>$case,
                'operator_digest'=>$this->config->digest('operator:'.$evidence['operator']),
                'prior_factor_digest'=>$this->config->digest(json_encode($f,JSON_THROW_ON_ERROR)),
                'generation'=>$generation,'status'=>'issued','created'=>$now,'expires'=>$now+3600,'completed'=>0]);
            $this->db->executeStatement("UPDATE plg_ps_recovery SET status='superseded' WHERE subject=? AND id<>? AND status IN ('issued','claimed')",[$subject,$id]);
            $this->db->executeStatement("UPDATE plg_ps_credential SET revoked=1, revoked_at=?, revoked_reason='staff_recovery' WHERE subject=? AND revoked=0",[$now,$subject]);
            $this->db->executeStatement('UPDATE plg_ps_factor SET secret=?,confirmed=0,last_step=-1,generation=?,ticket=?,expires=? WHERE subject=?',
                ['', $generation,$this->config->digest($ticket),$now+3600,$subject]);
            $reset=['required'=>1,'baseline'=>$this->config->digest($currentPasswordHash)];
            if ($this->db->fetchOne('SELECT subject FROM plg_ps_reset WHERE subject=?',[$subject])!==false) $this->db->update('plg_ps_reset',$reset,['subject'=>$subject]);
            else $this->db->insert('plg_ps_reset',['subject'=>$subject]+$reset);
            $this->audit($subject,'staff_recovery_started:'.$id);
            return ['subject'=>$subject,'recovery_id'=>$id,'ticket'=>$ticket,'expires'=>$now+3600];
        });
    }
    public function finishRecovery(string $subject, int $generation, int $now): void
    {
        $this->db->transactional(function () use ($subject,$generation,$now): void {
            $f=$this->lockSubject($subject);
            if ((int)$f['generation']!==$generation || $this->resetRequired($subject)
                || ((int)$f['confirmed']!==1 && !$this->credentials($subject))) throw new \RuntimeException('security_recovery_not_complete');
            // Password reset increments the generation after claim, hence match the latest pending record.
            $n=$this->db->executeStatement("UPDATE plg_ps_recovery SET status='completed',completed=? WHERE subject=? AND status='claimed'",[$now,$subject]);
            if ($n) $this->audit($subject,'staff_recovery_completed');
        });
    }
    public function limit(string $identity, int $now, int $maximum=10): void
    {
        $bucket = $this->config->digest('limit:'.$identity.':'.intdiv($now, 300));
        if ($this->db->getDatabasePlatform()->getName()==='postgresql') {
            $this->db->executeStatement('INSERT INTO plg_ps_limit (bucket,starts,attempts) VALUES (?,?,?) ON CONFLICT (bucket) DO NOTHING',[$bucket,$now,0]);
        } else {
            try { $this->db->insert('plg_ps_limit', ['bucket'=>$bucket, 'starts'=>$now, 'attempts'=>0]); }
            catch (\Doctrine\DBAL\Exception\UniqueConstraintViolationException $e) {}
        }
        $n = $this->db->executeStatement('UPDATE plg_ps_limit SET attempts=attempts+1 WHERE bucket=? AND attempts<?', [$bucket, $maximum]);
        if ($n !== 1) throw new \RuntimeException('security_rate_limited');
    }
    public function audit(string $subject, string $action): void
    {
        $this->db->insert('plg_ps_audit', ['id'=>bin2hex(random_bytes(16)), 'subject'=>$subject, 'action'=>$action, 'created'=>time()]);
    }
}
