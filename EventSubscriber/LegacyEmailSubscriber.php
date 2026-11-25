<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\EventSubscriber;

use Plugin\PasskeySecurity\Resource\Runtime\Mailbox;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/** Format-based advice, identical for existing and nonexistent accounts. */
final class LegacyEmailSubscriber implements EventSubscriberInterface
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private UrlGeneratorInterface $urls, private CsrfTokenManagerInterface $csrf) {}

    public static function getSubscribedEvents(): array
    {
        // After routing/session, before the native firewall (priority 8).
        return [KernelEvents::REQUEST => ['advise', 9]];
    }

    public function advise(RequestEvent $event): void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $request = $event->getRequest();
        if (!$event->isMainRequest() || !$request->isMethod('POST') || $request->attributes->get('_route') !== 'mypage_login') return;
        $input = $request->request->all();
        $email = $input['login_email'] ?? null; $token = $input['_csrf_token'] ?? null;
        if (!is_string($email) || !Mailbox::needsHelp(trim($email))) return;
        // Leave bad CSRF requests to the normal firewall; do not bypass CSRF or login checks.
        if (!is_string($token) || !$this->csrf->isTokenValid(new CsrfToken('authenticate', $token))) return;
        $response = new RedirectResponse($this->urls->generate('ps_email_help'), 303);
        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $event->setResponse($response);
    }
}
