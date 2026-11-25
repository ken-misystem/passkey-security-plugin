<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\EventSubscriber;

use Eccube\Common\EccubeConfig;
use Plugin\PasskeySecurity\Resource\Runtime\PasswordRules;
use Eccube\Event\TemplateEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

final class PasswordHelpSubscriber implements EventSubscriberInterface
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private EccubeConfig $config) {}
    public static function getSubscribedEvents(): array
    {
        return ['Entry/index.twig'=>'help','Mypage/change.twig'=>'help','Forgot/reset.twig'=>'help'];
    }
    public function help(TemplateEvent $event): void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $source=$event->getSource();
        if(str_contains($source,'@PasskeySecurity/password_help.twig'))return;
        $event->setParameter('password_context',$event->getView()==='Forgot/reset.twig'?'customer_reset':'customer_entry');
        $event->setParameter('password_min',PasswordRules::MIN_LENGTH);
        $event->setParameter('password_max',PasswordRules::MAX_LENGTH);
        $source=preg_replace('~(?=\{\{\s*form_widget\(form\.(?:plain_password|password)\.first)~',
            "{% include '@PasskeySecurity/password_help.twig' %}\n",$source,1);
        $event->setSource($source);
    }
}
