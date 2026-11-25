<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Eccube\Entity\Member;
use Eccube\Entity\Master\Work;

/** Read-only presentation of the mandatory plugin policy, not the unrelated native TOTP flag. */
final class StaffMfaState
{
    public function __construct(private Store $store,private Config $config){}
    public function forMember(?Member $member): array
    {
        $state=['known'=>true,'ready'=>false,'passkey_count'=>0,'totp'=>false,'password_change_required'=>false,'new'=>!$member?->getId(),
            'inactive'=>$member?->getWork()!==null&&$member->getWork()->getId()!==Work::ACTIVE];
        if($state['new'])return $state;
        try{
            $this->config->data();$this->store->epoch();$subject=Policy::subject($member);
            $state['passkey_count']=count($this->store->credentials($subject));$state['totp']=(int)($this->store->factor($subject)['confirmed']??0)===1;
            $state['ready']=$state['passkey_count']>0||$state['totp'];$state['password_change_required']=$this->store->resetRequired($subject);
        }catch(\Throwable){$state['known']=false;}
        return $state;
    }
}
