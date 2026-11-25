<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Form;

use Eccube\Form\Type\Front\PasswordResetType;
use Plugin\PasskeySecurity\Resource\Runtime\PasswordRules;
use Eccube\Repository\CustomerRepository;
use Symfony\Component\Form\AbstractTypeExtension;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormEvent;
use Symfony\Component\Form\FormEvents;
use Symfony\Component\Form\FormError;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

final class PasswordResetExtension extends AbstractTypeExtension
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private CustomerRepository $customers, private RequestStack $requests,
        private UserPasswordHasherInterface $hasher) {}
    public static function getExtendedTypes(): iterable { return [PasswordResetType::class]; }
    public function buildForm(FormBuilderInterface $b, array $options): void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $b->addEventListener(FormEvents::POST_SUBMIT, function (FormEvent $e): void {
            $form = $e->getForm(); $new = $form->get('password')->getData();
            if (!is_string($new)) return;
            $key = $this->requests->getCurrentRequest()?->attributes->get('reset_key');
            $u = is_string($key) ? $this->customers->getRegularCustomerByResetKey($key) : null;
            $valid = PasswordRules::valid($new, $u ? [$u->getEmail()] : []);
            $samePassword = $valid && $u && $this->hasher->isPasswordValid($u, $new);
            if (!$valid || $samePassword) {
                // EC-CUBE renders errors on the repeated field's first/second children.
                $message = $samePassword
                    ? '現在と同じパスワードは使用できません。別のパスワードを入力してください。'
                    : PasswordRules::MESSAGE;
                $form->get('password')->get('first')->addError(new FormError($message));
            }
        }, -64);
    }
}
