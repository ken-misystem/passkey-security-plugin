<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Eccube\Entity\Member;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/** Optional enrollment never disables an already registered account's protection. */
final class PublicPolicy
{
    public function __construct(private Store $store,private PublicSettings $settings,private Policy $policy){}
    public function enrolled(object $u):bool
    {
        $subject=Policy::subject($u);
        return count($this->store->credentials($subject))>0||(int)($this->store->factor($subject)['confirmed']??0)===1;
    }
    public function mustAuthenticate(object $u):bool
    {
        return $u instanceof Member&&($this->enrolled($u)||$this->settings->required()||$this->settings->staffPasskeyRequired()
            ||$this->store->resetRequired(Policy::subject($u)));
    }
    public function enrollment(SessionInterface $session,object $u,int $now):int
    {
        $subject=Policy::subject($u);
        if($this->store->resetRequired($subject))throw new \RuntimeException('public_password_change_required');
        // New optional users may enroll after a fresh password check. Established factors
        // still require their original MFA or a separately issued recovery ticket.
        $name=$u instanceof Member?'password':'reauth';
        if($u instanceof Member&&($this->settings->migrated()||$this->enrolled($u)||!$this->store->publicInitialEligible($subject))){
            if($this->policy->fresh($session,$u,'enroll',$now,600))$name='enroll';
            else $name=$this->policy->staffProof($session,$u,$now);
        }
        return $this->policy->proofGeneration($session,$u,$name,$now,$name==='enroll'?600:300);
    }
}
