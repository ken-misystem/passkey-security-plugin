<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Form;
use Eccube\Entity\Member;
use Eccube\Form\Type\Admin\MemberType;
use Plugin\PasskeySecurity\Resource\Runtime\{StaffMailStore,StaffMailAdminAccess,Policy};
use Symfony\Component\Form\{AbstractTypeExtension,FormBuilderInterface,FormInterface,FormView,FormEvent,FormEvents,FormError};
use Symfony\Component\Form\Extension\Core\Type\{EmailType,HiddenType};
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
final class StaffMailAdminTypeExtension extends AbstractTypeExtension
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private StaffMailStore $mail,private StaffMailAdminAccess $access,private RequestStack $requests,private TokenStorageInterface $tokens){}
    public static function getExtendedTypes():iterable{return [MemberType::class];}
    public function buildForm(FormBuilderInterface $b,array $o):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $actor=$this->tokens->getToken()?->getUser();$r=$this->requests->getCurrentRequest();if(!$this->access->view($actor,$r))return;
        $member=$b->getData();if(!$member instanceof Member)return;
        $subject=$member->getId()?Policy::subject($member):null;$a=$subject?$this->mail->addresses($subject):['primary'=>['verified'=>null,'pending'=>null],'backup'=>['verified'=>null,'pending'=>null]];
        $editable=$this->access->edit($actor,$r)&&(!$subject||$member->getWork()?->getId()===1);$revision=$subject?$this->mail->stateDigest($subject):'new';
        $b->setAttribute('ps_mail_admin',true);$b->setAttribute('ps_mail_addresses',$a);
        foreach(['primary'=>'主アドレス','backup'=>'予備アドレス']as$slot=>$label)$b->add('ps_mail_'.$slot,EmailType::class,['mapped'=>false,'required'=>false,'disabled'=>!$editable,'label'=>'再設定用'.$label,'data'=>$a[$slot]['pending']??$a[$slot]['verified']??'','attr'=>['maxlength'=>254,'autocomplete'=>'off'],'eccube_form_options'=>['auto_render'=>true]]);
        $b->add('ps_mail_revision',HiddenType::class,['mapped'=>false,'data'=>$revision]);
        $b->addEventListener(FormEvents::POST_SUBMIT,function(FormEvent $e):void{
            $f=$e->getForm();if(!$f->isValid())return;$member=$f->getData();$actor=$this->tokens->getToken()?->getUser();$r=$this->requests->getCurrentRequest();

            $subject=$member->getId()?Policy::subject($member):null;
            if(($subject?$this->mail->stateDigest($subject):'new')!==$f->get('ps_mail_revision')->getData()){$f->addError(new FormError('メール設定が更新されています。画面を開き直してください。'));return;}
            $before=$subject?$this->mail->addresses($subject):[];$changed=false;$values=[];foreach(['primary','backup']as$slot){$value=trim((string)$f->get('ps_mail_'.$slot)->getData());if($value==='')continue;try{$value=StaffMailStore::address($value);$this->mail->validateEnrollment($subject??'member:0',$value,$slot);$values[$slot]=$value;if($value!==($before[$slot]['pending']??$before[$slot]['verified']??''))$changed=true;}catch(\RuntimeException){$f->get('ps_mail_'.$slot)->addError(new FormError('形式、重複、他スタッフへの登録をご確認ください。'));}}
            if(isset($values['primary'],$values['backup'])&&$values['primary']===$values['backup'])$f->get('ps_mail_backup')->addError(new FormError('主アドレスと異なるアドレスを入力してください。'));
            $active=$member->getWork()?->getId()===1;
            if(!$subject&&$active&&!isset($values['primary']))$f->get('ps_mail_primary')->addError(new FormError('新規の稼働スタッフには主アドレスを登録してください。'));
            if($changed&&!$this->access->edit($actor,$r))$f->addError(new FormError('メール設定を変更するには追加認証をやり直してください。'));
            if(!$active&&$changed)$f->addError(new FormError('非稼働スタッフのメール設定は変更できません。'));
        },-1024);
    }
    public function buildView(FormView $v,FormInterface $f,array $o):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $v->vars['ps_staff_mail_admin']=$f->getConfig()->getAttribute('ps_mail_admin',false);
        $v->vars['ps_staff_mail_addresses']=$f->getConfig()->getAttribute('ps_mail_addresses',[]);
    }
}
