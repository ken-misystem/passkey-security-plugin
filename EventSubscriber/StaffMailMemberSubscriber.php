<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\EventSubscriber;
use Eccube\Event\{EventArgs,EccubeEvents,TemplateEvent};
use Plugin\PasskeySecurity\Resource\Runtime\{StaffMailStore,StaffMailAdminAccess,Policy,Store};
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
final class StaffMailMemberSubscriber implements EventSubscriberInterface
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private StaffMailStore $mail,private StaffMailAdminAccess $access,private TokenStorageInterface $tokens,private Store $security){}
    public static function getSubscribedEvents():array{return ['@admin/Setting/System/member_edit.twig'=>'view',EccubeEvents::ADMIN_SETTING_SYSTEM_MEMBER_EDIT_COMPLETE=>'saved'];}
    public function view(TemplateEvent $e):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $anchor='{# エンティティ拡張の自動出力 #}';$s=$e->getSource();if(substr_count($s,$anchor)!==1)return;
        $e->setSource(str_replace($anchor,"{% include '@PasskeySecurity/staff_mail_member.twig' %}\n".$anchor,$s));
    }
    public function saved(EventArgs $e):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $f=$e->getArgument('form');if(!$f->getConfig()->getAttribute('ps_mail_admin',false))return;
        $actor=$this->tokens->getToken()?->getUser();if(!$this->access->edit($actor,$e->getRequest()))return;
        $member=$e->getArgument('Member');if($member->getWork()?->getId()!==1)return;$subject=Policy::subject($member);$expected=$f->get('ps_mail_revision')->getData();if($expected==='new')$expected=$this->mail->stateDigest($subject);
        $this->mail->withState($subject,$expected,function()use($subject,$actor,$f):void{$before=$this->mail->addresses($subject);
        foreach(['primary','backup']as$slot){$value=trim((string)$f->get('ps_mail_'.$slot)->getData());if($value==='')continue;$value=StaffMailStore::address($value);if($value===($before[$slot]['pending']??$before[$slot]['verified']))continue;$this->mail->stageEnrollment($subject,$value,time(),$slot);$this->security->audit($subject,'staff_mail_admin_staged_by:'.$actor->getId());}
        });
    }
}
