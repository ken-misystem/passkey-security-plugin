<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Form;

use Plugin\PasskeySecurity\Resource\Runtime\Mailbox;
use Eccube\Form\Type\RepeatedEmailType;
use Symfony\Component\Form\AbstractTypeExtension;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\Callback;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\Context\ExecutionContextInterface;

final class MailboxTypeExtension extends AbstractTypeExtension
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility) {}

    // RepeatedEmailType's combined value must be validated too: do not depend on its child type.
    public static function getExtendedTypes(): iterable { return [EmailType::class, RepeatedEmailType::class]; }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->addNormalizer('constraints', function (Options $options, $existing) {
            if (!$this->compatibility->shopEditionActive()) return $existing;
            $constraints = $existing instanceof Constraint ? [$existing] : (array)$existing;
            $constraints[] = new Callback(static function ($value, ExecutionContextInterface $context): void {
                // Keep required/length/duplicate/type checks supplied by EC-CUBE.
                if ($value === null || $value === '') return;
                if (!is_string($value) || !Mailbox::accepts($value)) {
                    $context->buildViolation('この形式のメールアドレスは使用できません。受信可能な別のメールアドレスを入力してください。')->addViolation();
                }
            });
            return $constraints;
        });
    }
}
