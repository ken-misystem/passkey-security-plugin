<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Doctrine\DBAL\Connection;

/** A mailbox-bound initial enrollment permit, never a general login/recovery token. */
final class InitialLink
{
    public function __construct(private Connection $db, private Config $config, private Store $security, private StaffMailStore $mail) {}

    public function issue(array $message, int $now): string
    {
        $p=$this->mail->initialMessage($message,$now);
        if(!$p)throw new \RuntimeException('initial_link_invalid');
        $f=$this->security->factor($p['subject']);
        $hash=$this->db->fetchOne('SELECT password FROM dtb_member WHERE id=? AND work_id=1',[(int)substr($p['subject'],7)]);
        if(!is_string($hash))throw new \RuntimeException('initial_link_invalid');
        $payload=['version'=>1,'purpose'=>'staff_initial_link','origin'=>$this->config->origin(),
            'subject'=>$p['subject'],'slot'=>$p['slot'],'address_digest'=>$p['address_digest'],'revision'=>$p['revision'],
            'generation'=>$p['generation'],'baseline'=>$this->config->digest($hash),'ticket'=>$p['ticket'],
            'created'=>$now,'expires'=>(int)$f['expires']];
        $nonce=random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return Ceremony::encode($nonce.sodium_crypto_secretbox(json_encode($payload,JSON_THROW_ON_ERROR),$nonce,$this->config->shopEncryptionKey()));
    }

    /** GET callers may inspect; only Store::claimTicket can consume the permit. */
    public function inspect(string $raw,int $now,?string $expectedSubject=null): array
    {
        if(!preg_match('/^[A-Za-z0-9_-]{100,2048}$/D',$raw))throw new \RuntimeException('initial_link_invalid');
        $bytes=base64_decode(strtr($raw,'-_','+/'),true);
        if($bytes===false||strlen($bytes)<41)throw new \RuntimeException('initial_link_invalid');
        $plain=sodium_crypto_secretbox_open(substr($bytes,24),substr($bytes,0,24),$this->config->shopEncryptionKey());
        if($plain===false)throw new \RuntimeException('initial_link_invalid');
        $p=json_decode($plain,true,8,JSON_THROW_ON_ERROR);
        if(!is_array($p)||($p['version']??null)!==1||($p['purpose']??null)!=='staff_initial_link'
            ||($p['origin']??null)!==$this->config->origin()||!preg_match('/^member:([1-9][0-9]*)$/D',(string)($p['subject']??''),$id)
            ||!is_int($p['created']??null)||!is_int($p['expires']??null)||$p['created']>$now
            ||$p['expires']<$p['created']||$p['expires']>$p['created']+3600
            ||!preg_match('/^[A-Za-z0-9_-]{43}$/D',(string)($p['ticket']??'')))throw new \RuntimeException('initial_link_invalid');
        if($expectedSubject!==null&&!hash_equals($expectedSubject,$p['subject']))throw new \RuntimeException('initial_link_other_account');
        $lock=$this->db->getDatabasePlatform()->getName()==='mysql'&&$this->db->isTransactionActive()?' FOR UPDATE':'';
        $member=$this->db->fetchAssociative('SELECT password,work_id FROM dtb_member WHERE id=?'.$lock,[(int)$id[1]]);
        $box=$this->mail->mailbox($p['subject'],StaffMailStore::slot((string)($p['slot']??'')));
        $f=$this->security->factor($p['subject']);
        if(!$member||(int)$member['work_id']!==1
            ||!$box||(int)$box['verified_at']<=0||(int)$box['revision']!==($p['revision']??null)
            ||!hash_equals($box['address_digest'],(string)($p['address_digest']??''))||!$f)throw new \RuntimeException('initial_link_invalid');
        if($f['ticket']==='')throw new \RuntimeException('initial_link_used');
        if((int)$f['generation']!==($p['generation']??null))throw new \RuntimeException('initial_link_replaced');
        if(!hash_equals($this->config->digest($member['password']),(string)($p['baseline']??'')))throw new \RuntimeException('initial_link_invalid');
        if(!hash_equals($f['ticket'],$this->config->digest($p['ticket'])))throw new \RuntimeException('initial_link_replaced');
        if($p['expires']<$now||(int)$f['expires']<$now)throw new \RuntimeException('initial_link_expired');
        if(!$this->security->initialEligible($p['subject']))throw new \RuntimeException('initial_link_invalid');
        return $p;
    }
}
