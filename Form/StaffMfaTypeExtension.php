<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Form;

use Eccube\Entity\Member;
use Eccube\Form\Type\Admin\MemberType;
use Plugin\PasskeySecurity\Resource\Runtime\StaffMfaState;
use Symfony\Component\Form\{AbstractTypeExtension,FormBuilderInterface,FormInterface,FormView};

/** No second, misleading enable switch; the native column and native secret remain untouched. */
final class StaffMfaTypeExtension extends AbstractTypeExtension
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private StaffMfaState $state){}
    public static function getExtendedTypes():iterable{return [MemberType::class];}
    public function buildForm(FormBuilderInterface $builder,array $options):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        if($builder->has('two_factor_auth_enabled'))$builder->get('two_factor_auth_enabled')->setDisabled(true);
    }
    public function buildView(FormView $view,FormInterface $form,array $options):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $member=$form->getData();$view->vars['ps_staff_mfa']=$this->state->forMember($member instanceof Member?$member:null);
    }
}
