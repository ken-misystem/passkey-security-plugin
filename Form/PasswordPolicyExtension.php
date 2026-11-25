<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Form;
use Eccube\Form\Type\RepeatedPasswordType;
use Eccube\Request\Context;
use Plugin\PasskeySecurity\Resource\Runtime\PasswordRules;
use Symfony\Component\Form\AbstractTypeExtension;
use Symfony\Component\OptionsResolver\{Options,OptionsResolver};
use Symfony\Component\Validator\Constraints as Assert;

/** Use identical server constraints and HTML attributes for native EC-CUBE forms. */
final class PasswordPolicyExtension extends AbstractTypeExtension
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private Context $context) {}
    public static function getExtendedTypes():iterable{return[RepeatedPasswordType::class];}
    public function configureOptions(OptionsResolver $resolver):void
    {
        $resolver->addNormalizer('options',function(Options $options,array $value):array{
            if (!$this->compatibility->shopEditionActive()) return $value;
            $keep=array_values(array_filter($value['constraints']??[],static fn($c)=>!$c instanceof Assert\Length&&!$c instanceof Assert\Regex));
            $value['trim']=false; // Reject spaces instead of silently changing a submitted password.
            if($this->context->isFront())$value['purify_html']=false; // A password is a secret string, never HTML to normalize.
            $value['constraints']=[...$keep,new Assert\Length(['min'=>PasswordRules::MIN_LENGTH,'max'=>PasswordRules::MAX_LENGTH]),
                new Assert\Regex(['pattern'=>PasswordRules::PATTERN,'message'=>PasswordRules::MESSAGE])];return$value;
        });
        foreach(['first_options','second_options']as$name)$resolver->addNormalizer($name,function(Options $options,array $value):array{
            if (!$this->compatibility->shopEditionActive()) return $value;
            $value['attr']=array_replace($value['attr']??[],['minlength'=>PasswordRules::MIN_LENGTH,'maxlength'=>PasswordRules::MAX_LENGTH,'pattern'=>PasswordRules::HTML_PATTERN]);return$value;
        });
    }
}
