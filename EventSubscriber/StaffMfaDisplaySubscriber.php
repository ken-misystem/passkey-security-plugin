<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\EventSubscriber;

use Eccube\Event\TemplateEvent;
use Eccube\Entity\Member;
use Plugin\PasskeySecurity\Resource\Runtime\StaffMfaState;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

final class StaffMfaDisplaySubscriber implements EventSubscriberInterface
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private StaffMfaState $state){}
    public static function getSubscribedEvents():array
    {
        return ['@admin/Setting/System/member_edit.twig'=>'edit','@admin/Setting/System/member.twig'=>'listing'];
    }
    public function edit(TemplateEvent $event):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $source=$event->getSource();
        $old="{{ form_widget(form.two_factor_auth_enabled) }}";
        if(substr_count($source,$old)!==1)return;
        $source=str_replace($old,"{% include '@PasskeySecurity/staff_mfa_state.twig' with {'ps_staff_mfa':form.vars.ps_staff_mfa,'ps_staff_mfa_edit':true} %}{% do form.two_factor_auth_enabled.setRendered() %}",$source);
        $source=str_replace("{{ 'admin.setting.system.member.two_factor_auth_enabled'|trans }}",'追加認証（必須）',$source);
        $source=str_replace("{{ 'tooltip.setting.system.member.two_factor_auth_enabled'|trans }}",'パスキーまたは認証アプリの登録が完了すると自動で有効です。別の有効化操作は不要です。',$source);
        $event->setSource($source);
    }
    public function listing(TemplateEvent $event):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $states=[];foreach($event->getParameter('Members') as $member)if($member instanceof Member)$states[$member->getId()]=$this->state->forMember($member);
        $event->setParameter('ps_staff_mfa_states',$states);$source=$event->getSource();
        $pattern='~{%\s*if Member\.two_factor_auth_enabled\s*%}.*?{%\s*endif\s*%}~s';
        $source=preg_replace($pattern,"{% include '@PasskeySecurity/staff_mfa_state.twig' with {'ps_staff_mfa':ps_staff_mfa_states[Member.id],'ps_staff_mfa_edit':false} %}",$source,1,$count);
        if($count!==1)return;
        $source=str_replace("{{ 'admin.setting.system.member.two_factor_auth_enabled'|trans }}",'追加認証（必須）',$source);$event->setSource($source);
    }
}
