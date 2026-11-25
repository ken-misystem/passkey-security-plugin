<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Eccube\Entity\Customer;
use Eccube\Entity\Member;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

final class Policy
{
    public function __construct(private Store $store, private Config $config) {}
    public static function subject(object $user): string
    {
        if (!$user->getId()) throw new \RuntimeException('security_persisted_user_required');
        if ($user instanceof Member) return 'member:'.$user->getId();
        if ($user instanceof Customer) return 'customer:'.$user->getId();
        throw new \RuntimeException('security_unsupported_user');
    }
    public function stamp(object $user, ?int $generation=null): string
    {
        $subject = self::subject($user);
        return hash_hmac('sha256', $subject.':'.$this->store->epoch().':'.$user->getPassword().':'.
            ($generation ?? $this->store->generation($subject)), $this->config->key());
    }
    /** A request timestamp is not a decision timestamp after hashing or database work. */
    public static function decisionTime(int $previous,string $point='proof_check'):int
    {
        $current=time();
        if($current<$previous)throw new ClockRollbackException($previous,$current,$point);
        return $current;
    }
    public static function isClockFailure(\Throwable $error):bool
    {
        return $error instanceof \UnexpectedValueException && $error->getMessage()==='security_clock_rollback';
    }
    public function fresh(SessionInterface $s, object $user, string $name, int $now, int $ttl=1800): bool
    {
        $now=self::decisionTime($now);
        $proof = $s->get('ps_'.$name);
        if (!is_array($proof) || !is_int($proof['at'] ?? null) || $proof['at'] < $now-$ttl
            || $proof['at'] > $now+1 || !hash_equals($this->stamp($user), (string)($proof['stamp'] ?? ''))) return false;
        if ($proof['at'] > $now) {
            // Never accept a future proof: allow a bounded wait for a one-second clock rollback.
            $deadline=hrtime(true)+1200000000;
            do {
                $now=time();
                if ($now >= $proof['at']) break;
                usleep(20000);
            } while (hrtime(true)<$deadline);
            if ($proof['at'] > $now || $proof['at'] < $now-$ttl) return false;
            // A locking read sees committed changes even under MySQL repeatable read.
            $generation=$this->store->generationForProofRecheck(self::subject($user));
            $now=time(); // The DB lock can outlast the proof's validity window.
            return $generation!==null && $proof['at'] <= $now && $proof['at'] >= $now-$ttl
                && hash_equals($this->stamp($user,$generation), (string)$proof['stamp']);
        }
        return $proof['at'] <= $now && $proof['at'] >= $now-$ttl;
    }
    public function prove(SessionInterface $s, object $user, string $name, int $now, ?int $generation=null): void
    {
        $generation ??= $this->store->generation(self::subject($user));
        $s->set('ps_'.$name, ['at'=>$now, 'stamp'=>$this->stamp($user,$generation),'generation'=>$generation]);
    }
    /** Password proof for initial registration survives code issuance, but not password/epoch changes. */
    public function proveInitialPassword(SessionInterface $s,Member $user,int $now): void
    {
        $s->set('ps_initial_password',['at'=>$now,'stamp'=>hash_hmac('sha256','initial-password:'.self::subject($user).':'.$this->store->epoch().':'.$user->getPassword(),$this->config->key())]);
    }
    public function initialPassword(SessionInterface $s,Member $user,int $now): bool
    {
        $now=self::decisionTime($now);
        if($user->getWork()?->getId()!==1)return false;
        if($this->fresh($s,$user,'password',$now,1800))return true;
        $now=self::decisionTime($now);
        $p=$s->get('ps_initial_password');
        return is_array($p)&&($p['at']??0)>=$now-1800&&($p['at']??PHP_INT_MAX)<=$now
            &&hash_equals(hash_hmac('sha256','initial-password:'.self::subject($user).':'.$this->store->epoch().':'.$user->getPassword(),$this->config->key()),(string)($p['stamp']??''));
    }
    public function proofGeneration(SessionInterface $s, object $user, string $name, int $now, int $ttl=300): int
    {
        if (!$this->fresh($s,$user,$name,$now,$ttl)) throw new \RuntimeException('security_recent_proof_required');
        return (int)($s->get('ps_'.$name)['generation']??-1);
    }
    public function complete(SessionInterface $s, object $user, int $now): bool
    {
        if ($user instanceof Customer) return !$this->store->resetRequired(self::subject($user)) && $this->fresh($s,$user,'session',$now,86400);
        $subject = self::subject($user);
        $factor = $this->store->factor($subject);
        if (!$factor || $this->store->resetRequired($subject)) {
            return false;
        }
        $ttl = $this->config->staffSessionTtl();
        return (count($this->store->credentials($subject)) > 0 && $this->fresh($s,$user,'passkey',$now,$ttl))
            || ((int)$factor['confirmed']===1 && $this->fresh($s,$user,'password',$now,$ttl) && $this->fresh($s,$user,'totp',$now,$ttl)
        );
    }
    public function staffAccess(SessionInterface $session, Member $user, int $now): bool
    {
        if (!$this->config->staffPasskeyRequired()) {
            return $this->complete($session, $user, $now);
        }
        $subject = self::subject($user);
        return !$this->store->resetRequired($subject) && $this->store->credentials($subject) !== []
            && $this->fresh($session, $user, 'passkey', $now, $this->config->staffSessionTtl());
    }

    public function staffProof(SessionInterface $s, object $user, int $now, int $ttl=300): string
    {
        if (!($user instanceof Member) || !$this->complete($s,$user,$now)) throw new \RuntimeException('security_staff_authentication_required');
        if ($this->fresh($s,$user,'passkey',$now,$ttl)) return 'passkey';
        if ($this->fresh($s,$user,'password',$now,$ttl) && $this->fresh($s,$user,'totp',$now,$ttl)) return 'totp';
        throw new \RuntimeException('security_recent_proof_required');
    }
    public static function clear(SessionInterface $s): void
    {
        foreach (['passkey','totp','password','enroll','reauth','ceremony','session','initial_password'] as $n) $s->remove('ps_'.$n);
    }
}
