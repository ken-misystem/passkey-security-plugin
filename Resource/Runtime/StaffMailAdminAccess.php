<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;
use Eccube\Entity\Member;
use Eccube\Entity\Master\Work;
use Symfony\Component\HttpFoundation\Request;
final class StaffMailAdminAccess
{
    public function __construct(private Policy $policy){}
    public function view(mixed $u,?Request $r):bool
    {
        return $u instanceof Member && $u->getWork()?->getId()===Work::ACTIVE && $u->getAuthority()?->getId()===0
            && $r!==null && $r->hasSession() && $this->policy->complete($r->getSession(),$u,time());
    }
    public function edit(mixed $u,?Request $r):bool
    {
        if(!$this->view($u,$r))return false;
        try{$this->policy->staffProof($r->getSession(),$u,time());return true;}catch(\RuntimeException){return false;}
    }
}
