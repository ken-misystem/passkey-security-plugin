<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\EventSubscriber;

use Plugin\PasskeySecurity\Resource\Runtime\StaffMail;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\TerminateEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final class StaffMailSubscriber implements EventSubscriberInterface
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private StaffMail $mail) {}
    public static function getSubscribedEvents(): array { return [KernelEvents::TERMINATE=>['finish',-1024]]; }
    public function finish(TerminateEvent $event): void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        foreach ($event->getRequest()->attributes->get('_ps_staff_mail_jobs',[]) as $id) $this->mail->process($id,time());
    }
}
