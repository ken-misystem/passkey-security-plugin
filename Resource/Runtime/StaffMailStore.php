<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Symfony\Component\Mime\Address;

/** Dedicated encrypted records. Never copies addresses into dtb_member or logs. */
final class StaffMailStore
{
    public function __construct(private Connection $db, private Config $config, private Store $security) {}
    /** Independent autocommit connection: EC-CUBE keeps an ambient request transaction. */
    public function deliveryStore(): self
    {
        $db=DriverManager::getConnection($this->db->getParams());
        $db->setAutoCommit(true);
        return new self($db,$this->config,new Store($db,$this->config));
    }
    public function close(): void { $this->db->close(); }
    public function install(): void
    {
        $mailbox='CREATE TABLE IF NOT EXISTS plg_ps_staff_mailbox (subject VARCHAR(64) NOT NULL, slot VARCHAR(16) NOT NULL DEFAULT \'primary\', address TEXT NOT NULL, address_digest VARCHAR(64) NOT NULL UNIQUE, revision INTEGER NOT NULL, verified_at BIGINT NOT NULL, last_reset_mail_at BIGINT NOT NULL, PRIMARY KEY(subject,slot))';
        $this->db->executeStatement($mailbox);
        $columns=$this->db->createSchemaManager()->listTableColumns('plg_ps_staff_mailbox');
        if (!isset($columns['slot'])) {
            if ($this->db->getDatabasePlatform()->getName()==='mysql') {
                $this->db->executeStatement("ALTER TABLE plg_ps_staff_mailbox ADD slot VARCHAR(16) NOT NULL DEFAULT 'primary', DROP PRIMARY KEY, ADD PRIMARY KEY(subject,slot)");
            } else {
                $this->db->transactional(function() use($mailbox):void {
                    $this->db->executeStatement(str_replace('plg_ps_staff_mailbox','plg_ps_staff_mailbox_v050',$mailbox));
                    $this->db->executeStatement("INSERT INTO plg_ps_staff_mailbox_v050 SELECT subject,'primary',address,address_digest,revision,verified_at,last_reset_mail_at FROM plg_ps_staff_mailbox");
                    $this->db->executeStatement('DROP TABLE plg_ps_staff_mailbox');
                    $this->db->executeStatement('ALTER TABLE plg_ps_staff_mailbox_v050 RENAME TO plg_ps_staff_mailbox');
                });
            }
        }
        $this->db->executeStatement("CREATE TABLE IF NOT EXISTS plg_ps_staff_mail_token (id VARCHAR(64) PRIMARY KEY, subject VARCHAR(64) NOT NULL, slot VARCHAR(16) NOT NULL DEFAULT 'primary', purpose VARCHAR(16) NOT NULL, address TEXT NOT NULL, address_digest VARCHAR(64) NOT NULL, mailbox_revision INTEGER NOT NULL, generation INTEGER NOT NULL, baseline VARCHAR(64) NOT NULL, created BIGINT NOT NULL, expires BIGINT NOT NULL, consumed BIGINT NOT NULL)");
        if (!isset($this->db->createSchemaManager()->listTableColumns('plg_ps_staff_mail_token')['slot'])) $this->db->executeStatement("ALTER TABLE plg_ps_staff_mail_token ADD slot VARCHAR(16) NOT NULL DEFAULT 'primary'");
        $this->db->executeStatement('CREATE TABLE IF NOT EXISTS plg_ps_staff_mail_job (id VARCHAR(64) PRIMARY KEY, kind VARCHAR(16) NOT NULL, payload TEXT NOT NULL, status VARCHAR(16) NOT NULL, created BIGINT NOT NULL, updated BIGINT NOT NULL)');
        $this->db->executeStatement('CREATE TABLE IF NOT EXISTS plg_ps_staff_mail_enrollment (subject VARCHAR(64) NOT NULL, slot VARCHAR(16) NOT NULL, address TEXT NOT NULL, address_digest VARCHAR(64) NOT NULL, revision INTEGER NOT NULL, created BIGINT NOT NULL, PRIMARY KEY(subject,slot))');
    }
    public static function slot(string $slot): string
    {
        if (!in_array($slot,['primary','backup'],true)) throw new \RuntimeException('staff_mail_slot_invalid');
        return $slot;
    }
    public static function address(string $value): string
    {
        $value=trim($value);
        if (strlen($value)>254 || preg_match('/[\x00-\x20\x7f]/', $value) || substr_count($value,'@')!==1) throw new \RuntimeException('staff_mail_invalid_address');
        try { $a=new Address($value); } catch (\Throwable $e) { throw new \RuntimeException('staff_mail_invalid_address'); }
        if ($a->getAddress()!==$value) throw new \RuntimeException('staff_mail_invalid_address');
        // Treat mailbox case consistently. IDNs must be entered as their ASCII address.
        if (preg_match('/[^\x21-\x7e]/', $value)) throw new \RuntimeException('staff_mail_invalid_address');
        return strtolower($value);
    }
    private function seal(array $value): string
    {
        $nonce=random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return base64_encode($nonce.sodium_crypto_secretbox(json_encode($value,JSON_THROW_ON_ERROR),$nonce,$this->config->shopEncryptionKey()));
    }
    private function open(string $value): array
    {
        $raw=base64_decode($value,true);
        if ($raw===false || strlen($raw)<41) throw new \RuntimeException('staff_mail_record_invalid');
        $plain=sodium_crypto_secretbox_open(substr($raw,24),substr($raw,0,24),$this->config->shopEncryptionKey());
        if ($plain===false) throw new \RuntimeException('staff_mail_record_invalid');
        return json_decode($plain,true,8,JSON_THROW_ON_ERROR);
    }
    private function lock(): string { return $this->db->getDatabasePlatform()->getName()==='mysql'?' FOR UPDATE':''; }
    private function member(string $subject): array
    {
        if (!preg_match('/^member:([1-9][0-9]*)$/D',$subject,$m)) throw new \RuntimeException('staff_mail_rejected');
        $u=$this->db->fetchAssociative('SELECT id,password,work_id FROM dtb_member WHERE id=?'.$this->lock(),[(int)$m[1]]);
        if (!$u || (int)$u['work_id']!==1) throw new \RuntimeException('staff_mail_rejected');
        return $u;
    }
    public function mailbox(string $subject,string $slot='primary'): ?array
    {
        $v=$this->db->fetchAssociative('SELECT * FROM plg_ps_staff_mailbox WHERE subject=? AND slot=?',[$subject,self::slot($slot)]);
        return $v?:null;
    }
    public function displayAddress(string $subject,string $slot='primary'): ?string
    {
        $m=$this->mailbox($subject,$slot); return $m?$this->open($m['address'])['address']:null;
    }
    public function queue(string $kind,array $payload,int $now): string
    {
        if (!in_array($kind,['request','verify','notice','initial','enrollrequest','enrollnotice'],true)) throw new \RuntimeException('staff_mail_job_invalid');
        $id=bin2hex(random_bytes(24));
        $this->db->insert('plg_ps_staff_mail_job',['id'=>$id,'kind'=>$kind,'payload'=>$this->seal($payload),'status'=>'queued','created'=>$now,'updated'=>$now]);
        return $id;
    }
    public function pending(int $limit=10): array
    {
        return $this->db->fetchFirstColumn("SELECT id FROM plg_ps_staff_mail_job WHERE status='queued' ORDER BY created,id LIMIT ".max(1,min(10,$limit)));
    }
    /** Request processing resolves current active system administrators, never a fixed address list. */
    public function initialRequestNotifications(string $login,string $requestId,int $requestedAt,int $now,string $requestKind='initial'): array
    {
        return $this->db->transactional(function()use($login,$requestId,$requestedAt,$now,$requestKind):array{
            if(!in_array($requestKind,['initial','resume'],true))return [];
            if(!preg_match('/^[a-f0-9]{48}$/D',$requestId)||$requestedAt>$now||$requestedAt<$now-900)return [];
            $member=$this->db->fetchAssociative('SELECT id FROM dtb_member WHERE login_id=? AND work_id=1',[$login]);
            if(!$member)return [];
            $subject='member:'.$member['id'];$ids=[];
            $admins=$this->db->fetchFirstColumn('SELECT id FROM dtb_member WHERE work_id=1 AND authority_id=0 ORDER BY id');
            foreach($admins as$admin){
                foreach(['primary','backup']as$slot){
                    $box=$this->mailbox('member:'.$admin,$slot);
                    if(!$box||(int)$box['verified_at']<=0)continue;
                    $address=self::address($this->open($box['address'])['address']);
                    if(!hash_equals($box['address_digest'],$this->config->digest($address)))continue;
                    // At most one notification per requester/admin/mailbox in each 15-minute window.
                    $id=$this->config->digest('initial-request:'.$subject.':'.$admin.':'.$slot.':'.$box['revision'].':'.$box['address_digest'].':'.intdiv($now,900).($requestKind==='resume'?':resume':''));
                    $payload=['requester'=>$subject,'recipient'=>'member:'.$admin,'slot'=>$slot,'address'=>$address,
                        'address_digest'=>$box['address_digest'],'revision'=>(int)$box['revision'],'requested_at'=>$requestedAt,'request_id'=>$requestId,'request_kind'=>$requestKind];
                    try{
                        $this->db->insert('plg_ps_staff_mail_job',['id'=>$id,'kind'=>'enrollnotice','payload'=>$this->seal($payload),'status'=>'queued','created'=>$now,'updated'=>$now]);
                        $ids[]=$id;
                    }catch(\Doctrine\DBAL\Exception\UniqueConstraintViolationException){}
                }
            }
            $this->security->audit($subject,$ids?'staff_initial_request_notified':'staff_initial_request_no_new_notice');
            return $ids;
        });
    }
    /** Revalidate authority and verified mailbox immediately before local mail-queue admission. */
    public function initialRequestNotice(array $p,int $now): ?array
    {
        if(!preg_match('/^member:([1-9][0-9]*)$/D',(string)($p['recipient']??''),$id)
            ||!preg_match('/^member:([1-9][0-9]*)$/D',(string)($p['requester']??''),$requester)
            ||($p['requested_at']??PHP_INT_MAX)>$now||($p['requested_at']??0)<$now-900)return null;
        $admin=$this->db->fetchOne('SELECT COUNT(*) FROM dtb_member WHERE id=? AND work_id=1 AND authority_id=0',[(int)$id[1]]);
        $member=$this->db->fetchAssociative('SELECT id,name,login_id FROM dtb_member WHERE id=? AND work_id=1',[(int)$requester[1]]);
        $box=$this->mailbox($p['recipient'],self::slot($p['slot']));
        if(!$admin||!$member||!$box||(int)$box['verified_at']<=0||(int)$box['revision']!==$p['revision']
            ||!hash_equals($box['address_digest'],$p['address_digest'])
            ||!hash_equals($box['address_digest'],$this->config->digest(self::address($p['address']))))return null;
        return $p+['member_id'=>(int)$member['id'],'member_name'=>mb_substr(preg_replace('/[\x00-\x1f\x7f]/u',' ',$member['name']),0,80),
            'member_login'=>mb_substr(preg_replace('/[\x00-\x1f\x7f]/u',' ',$member['login_id']),0,50)];
    }
    /** The destination is chosen from verified records, never from a submitted email field. */
    public function initialDelivery(string $subject,string $ticket,int $now): ?string
    {
        $this->member($subject);
        foreach(['primary','backup']as$slot){
            $box=$this->mailbox($subject,$slot);
            if(!$box||(int)$box['verified_at']<=0)continue;
            return $this->queue('initial',['subject'=>$subject,'slot'=>$slot,'address'=>$this->open($box['address'])['address'],
                'address_digest'=>$box['address_digest'],'revision'=>(int)$box['revision'],
                'generation'=>$this->security->generation($subject),'ticket'=>$ticket,'link_version'=>1],$now);
        }
        return null;
    }
    public function initialMessage(array $p,int $now): ?array
    {
        try{
            $this->member($p['subject']);$box=$this->mailbox($p['subject'],self::slot($p['slot']));
            $f=$this->security->factor($p['subject']);
            if(!$box||!$f||(int)$box['verified_at']<=0||(int)$box['revision']!==$p['revision']
                ||!hash_equals($box['address_digest'],$p['address_digest'])
                ||!hash_equals($box['address_digest'],$this->config->digest(self::address($p['address'])))
                ||!$this->security->initialEligible($p['subject'])
                ||(int)$f['generation']!==$p['generation']||(int)$f['expires']<=$now
                ||$f['ticket']===''||!hash_equals($f['ticket'],$this->config->digest($p['ticket'])))return null;
            return $p+['expires'=>(int)$f['expires']];
        }catch(\RuntimeException){return null;}
    }
    /** Use the delivery connection throughout: never acquire a request-transaction read lock. */
    public function initialLinkToken(array $message,int $now):string
    {
        return (new InitialLink($this->db,$this->config,$this->security,$this))->issue($message,$now);
    }
    /** Commit processing before calling any delivery code. Interrupted jobs are never replayed. */
    public function claim(string $id,int $now): ?array
    {
        if ($this->db->executeStatement("UPDATE plg_ps_staff_mail_job SET status='processing',updated=? WHERE id=? AND status='queued'",[$now,$id])!==1) return null;
        $j=$this->db->fetchAssociative('SELECT kind,payload FROM plg_ps_staff_mail_job WHERE id=?',[$id]);
        return ['kind'=>$j['kind'],'payload'=>$this->open($j['payload'])];
    }
    public function finish(string $id,string $status,int $now): void
    {
        if (!in_array($status,['sent','ignored','uncertain'],true)) throw new \RuntimeException('staff_mail_status_invalid');
        $this->db->executeStatement("UPDATE plg_ps_staff_mail_job SET status=?,updated=? WHERE id=? AND status='processing'",[$status,$now,$id]);
    }
    public function addresses(string $subject): array
    {
        $out=[];
        foreach (['primary','backup'] as $slot) {
            $pending=$this->db->fetchAssociative('SELECT address FROM plg_ps_staff_mail_enrollment WHERE subject=? AND slot=?',[$subject,$slot]);
            $out[$slot]=['verified'=>$this->displayAddress($subject,$slot),'pending'=>$pending?$this->open($pending['address'])['address']:null];
        }
        return $out;
    }
    public function initialEmailVerified(string $subject): bool
    {
        foreach(['primary','backup']as$slot){$box=$this->mailbox($subject,$slot);if($box&&(int)$box['verified_at']>0)return true;}
        return false;
    }
    /** Only a pre-registered address may receive an initial registration verification. */
    public function initialEmailAddress(string $subject): ?array
    {
        foreach(['primary','backup']as$slot){
            $box=$this->db->fetchAssociative('SELECT address FROM plg_ps_staff_mail_enrollment WHERE subject=? AND slot=?',[$subject,$slot]);
            if($box)return ['slot'=>$slot,'address'=>$this->open($box['address'])['address']];
        }
        return null;
    }
    public function initialEmailVerification(string $subject,string $expected,int $now): string
    {
        return $this->withState($subject,$expected,function()use($subject,$now):string{
            if($this->initialEmailVerified($subject))throw new \RuntimeException('staff_email_already_verified');
            $box=$this->initialEmailAddress($subject);if(!$box)throw new \RuntimeException('staff_email_not_registered');
            return $this->verification($subject,$box['address'],$now,$box['slot'],true);
        });
    }
    public function stateDigest(string $subject,bool $locked=false): string
    {
        $a=$this->db->fetchAllAssociative('SELECT slot,address_digest,revision FROM plg_ps_staff_mailbox WHERE subject=? ORDER BY slot'.($locked?$this->lock():''),[$subject]);
        $b=$this->db->fetchAllAssociative('SELECT slot,address_digest,revision FROM plg_ps_staff_mail_enrollment WHERE subject=? ORDER BY slot'.($locked?$this->lock():''),[$subject]);
        return $this->config->digest(json_encode([$subject,$a,$b],JSON_THROW_ON_ERROR));
    }
    /** Lock the target before checking a submitted revision; never overwrite a concurrent change. */
    public function withState(string $subject,string $expected,callable $apply): mixed
    {
        return $this->db->transactional(function()use($subject,$expected,$apply):mixed{
            $this->member($subject);
            if(!hash_equals($this->stateDigest($subject,true),$expected))throw new \RuntimeException('staff_mail_state_changed');
            return $apply();
        });
    }
    public function validateEnrollment(string $subject,string $address,string $slot): void
    {
        $slot=self::slot($slot);$address=self::address($address);$digest=$this->config->digest($address);
        foreach(['plg_ps_staff_mailbox','plg_ps_staff_mail_enrollment']as$table){
            $rows=$this->db->fetchAllAssociative('SELECT subject,slot FROM '.$table.' WHERE address_digest=?',[$digest]);
            foreach($rows as$row)if($row['subject']!==$subject||$row['slot']!==$slot)throw new \RuntimeException('staff_mail_address_in_use');
        }
    }
    /** Persist an unverified operator/user proposal; no token, queue or transport action. */
    public function stageEnrollment(string $subject,string $address,int $now,string $slot='primary'): void
    {
        $address=self::address($address);$slot=self::slot($slot);
        $this->db->transactional(function()use($subject,$address,$now,$slot):void {
            $this->member($subject);
            $this->validateEnrollment($subject,$address,$slot);
            $digest=$this->config->digest($address);
            $existing=$this->db->fetchAssociative('SELECT subject,slot FROM plg_ps_staff_mailbox WHERE address_digest=?',[$digest]);
            if ($existing && ($existing['subject']!==$subject || $existing['slot']!==$slot)) throw new \RuntimeException('staff_mail_address_in_use');
            $same=$this->db->fetchOne('SELECT COUNT(*) FROM plg_ps_staff_mail_enrollment WHERE subject=? AND slot<>? AND address_digest=?',[$subject,$slot,$digest]);
            if ($same) throw new \RuntimeException('staff_mail_duplicate_slot');
            $old=$this->db->fetchAssociative('SELECT revision FROM plg_ps_staff_mail_enrollment WHERE subject=? AND slot=?',[$subject,$slot]);
            $row=['address'=>$this->seal(['address'=>$address]),'address_digest'=>$digest,'revision'=>(int)($old['revision']??0)+1,'created'=>$now];
            if ($old) $this->db->update('plg_ps_staff_mail_enrollment',$row,['subject'=>$subject,'slot'=>$slot]);
            else $this->db->insert('plg_ps_staff_mail_enrollment',['subject'=>$subject,'slot'=>$slot]+$row);
            $this->db->executeStatement("UPDATE plg_ps_staff_mail_token SET consumed=? WHERE subject=? AND slot=? AND purpose='verify' AND consumed=0",[$now,$subject,$slot]);
            $this->security->audit($subject,'staff_mail_enrollment_staged');
        });
    }
    private function token(string $subject,string $purpose,string $address,int $now,string $slot='primary'): string
    {
        $slot=self::slot($slot);$user=$this->member($subject);$box=$this->mailbox($subject,$slot);
        $raw=Ceremony::encode(random_bytes(32));
        $this->db->insert('plg_ps_staff_mail_token',['id'=>$this->config->digest($raw),'subject'=>$subject,'slot'=>$slot,'purpose'=>$purpose,
            'address'=>$this->seal(['address'=>$address]),'address_digest'=>$this->config->digest($address),'mailbox_revision'=>(int)($box['revision']??0),
            'generation'=>$this->security->generation($subject),'baseline'=>$this->config->digest($user['password']),
            'created'=>$now,'expires'=>$now+1800,'consumed'=>0]);
        return $raw;
    }
    public function verification(string $subject,string $address,int $now,string $slot='primary',bool $initial=false): string
    {
        $address=self::address($address);$slot=self::slot($slot);
        return $this->db->transactional(function() use($subject,$address,$now,$slot,$initial): string {
            $this->stageEnrollment($subject,$address,$now,$slot);
            $raw=$this->token($subject,'verify',$address,$now,$slot);
            return $this->queue('verify',['address'=>$address,'token'=>$raw,'initial_registration'=>$initial],$now);
        });
    }
    public function revoke(string $subject,string $slot,int $now): array
    {
        $slot=self::slot($slot);
        return $this->db->transactional(function()use($subject,$slot,$now):array {
            $this->member($subject);$old=$this->mailbox($subject,$slot);
            $this->db->delete('plg_ps_staff_mailbox',['subject'=>$subject,'slot'=>$slot]);
            $this->db->delete('plg_ps_staff_mail_enrollment',['subject'=>$subject,'slot'=>$slot]);
            $this->db->executeStatement('UPDATE plg_ps_staff_mail_token SET consumed=? WHERE subject=? AND slot=? AND consumed=0',[$now,$subject,$slot]);
            $this->security->audit($subject,'staff_mail_address_revoked');
            return $old?[$this->queue('notice',['address'=>$this->open($old['address'])['address'],'text'=>'スタッフの再設定用メールアドレス登録が解除されました。心当たりがなければ管理担当者へ連絡してください。'],$now)]:[];
        });
    }
    public function resetMessage(string $address,int $now): ?array
    {
        return $this->db->transactional(function() use($address,$now): ?array {
            $box=$this->db->fetchAssociative('SELECT subject,slot FROM plg_ps_staff_mailbox WHERE address_digest=?',[$this->config->digest($address)]);
            if (!$box) return null;
            try { $this->member($box['subject']); } catch (\RuntimeException $e) { return null; }
            $box=$this->mailbox($box['subject'],$box['slot']);
            if (!$box || !hash_equals($box['address_digest'],$this->config->digest($address))) return null;
            $last=(int)$this->db->fetchOne('SELECT MAX(last_reset_mail_at) FROM plg_ps_staff_mailbox WHERE subject=?',[$box['subject']]);
            if ($last>0 && $last>$now-300) return null;
            $raw=$this->token($box['subject'],'reset',$address,$now,$box['slot']);
            $this->db->update('plg_ps_staff_mailbox',['last_reset_mail_at'=>$now],['subject'=>$box['subject']]);
            $this->security->audit($box['subject'],'staff_mail_reset_requested');
            return ['address'=>$address,'token'=>$raw];
        });
    }
    private function checkedToken(string $raw,string $purpose,int $now): array
    {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/D',$raw)) throw new \RuntimeException('staff_mail_token_rejected');
        // Read subject first, then lock Member in the same order as token issuance.
        $id=$this->config->digest($raw);$t=$this->db->fetchAssociative('SELECT * FROM plg_ps_staff_mail_token WHERE id=?',[$id]);
        if (!$t) throw new \RuntimeException('staff_mail_token_rejected');
        $u=$this->member($t['subject']);
        $t=$this->db->fetchAssociative('SELECT * FROM plg_ps_staff_mail_token WHERE id=?'.$this->lock(),[$id]);
        $box=$this->mailbox($t['subject'],$t['slot']);
        if ($t['purpose']!==$purpose || (int)$t['consumed']!==0 || (int)$t['expires']<=$now || (int)$t['created']>$now
            || (int)$t['generation']!==$this->security->generation($t['subject'])
            || !hash_equals($t['baseline'],$this->config->digest($u['password']))
            || (int)$t['mailbox_revision']!==(int)($box['revision']??0)
            || ($purpose==='reset' && (!$box || !hash_equals($box['address_digest'],$t['address_digest'])))) throw new \RuntimeException('staff_mail_token_rejected');
        return $t+['password'=>$u['password']];
    }
    public function confirm(string $raw,int $now): array
    {
        return $this->db->transactional(function() use($raw,$now): array {
            $t=$this->checkedToken($raw,'verify',$now);
            $old=$this->mailbox($t['subject'],$t['slot']);
            $row=['address'=>$t['address'],'address_digest'=>$t['address_digest'],'revision'=>(int)$t['mailbox_revision']+1,'verified_at'=>$now,'last_reset_mail_at'=>0];
            if ($old) $this->db->update('plg_ps_staff_mailbox',$row,['subject'=>$t['subject'],'slot'=>$t['slot']]);
            else $this->db->insert('plg_ps_staff_mailbox',['subject'=>$t['subject'],'slot'=>$t['slot']]+$row);
            $this->db->update('plg_ps_staff_mail_token',['consumed'=>$now],['id'=>$t['id']]);
            $notice=null;
            if ($old && !hash_equals($old['address_digest'],$t['address_digest'])) $notice=$this->queue('notice',['address'=>$this->open($old['address'])['address'],'text'=>'スタッフのパスワード再設定用メールアドレスが変更されました。心当たりがなければ管理担当者へ連絡してください。'],$now);
            $this->db->delete('plg_ps_staff_mail_enrollment',['subject'=>$t['subject'],'slot'=>$t['slot']]);
            $this->security->audit($t['subject'],'staff_mail_address_verified');
            return $notice?[$notice]:[];
        });
    }
    /** Only new assignments use these rules; current/legacy credentials remain usable. */
    public function passwordAllowed(string $subject,mixed $password):bool
    {
        $emails=[];foreach($this->addresses($subject)as$slot)foreach(['verified','pending']as$key)if(is_string($slot[$key]??null))$emails[]=$slot[$key];
        return PasswordRules::valid($password,$emails);
    }
    /** Hasher callbacks use the real Member salt/algorithm; no auto-login or factor changes. */
    public function reset(string $raw,string $password,int $now,callable $isOld,callable $hash): string
    {
        if (!PasswordRules::valid($password)) throw new \RuntimeException('staff_mail_password_invalid');
        return $this->db->transactional(function() use($raw,$password,$now,$isOld,$hash): string {
            $t=$this->checkedToken($raw,'reset',$now);
            if(!$this->passwordAllowed($t['subject'],$password))throw new \RuntimeException('staff_mail_password_invalid');
            if ($isOld($t['subject'],$password)) throw new \RuntimeException('staff_mail_password_unchanged');
            $new=$hash($t['subject'],$password);
            if (!is_string($new) || $new==='' || hash_equals($t['password'],$new)) throw new \RuntimeException('staff_mail_password_invalid');
            $id=(int)substr($t['subject'],7);
            if ($this->db->executeStatement('UPDATE dtb_member SET password=? WHERE id=? AND password=? AND work_id=1',[$new,$id,$t['password']])!==1) throw new \RuntimeException('staff_mail_password_race');
            // Password change satisfies this member's mandatory change only. Never revoke MFA.
            $this->db->update('plg_ps_reset',['required'=>0,'baseline'=>$this->config->digest($new)],['subject'=>$t['subject']]);
            $this->db->executeStatement('UPDATE plg_ps_staff_mail_token SET consumed=? WHERE subject=? AND consumed=0',[$now,$t['subject']]);
            $notice=$this->queue('notice',['address'=>$this->open($t['address'])['address'],'text'=>'スタッフのパスワードが変更されました。心当たりがなければ管理担当者へ連絡してください。パスキー・認証アプリの確認は引き続き必要です。'],$now);
            $this->security->audit($t['subject'],'staff_mail_password_reset');
            return $notice;
        });
    }
}
