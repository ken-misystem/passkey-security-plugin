<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\EventSubscriber;

use Eccube\Entity\Member;
use Eccube\Event\EccubeEvents;
use Eccube\Event\EventArgs;
use Eccube\Form\Type\Admin\LoginType;
use Plugin\PasskeySecurity\Resource\Runtime\Config;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Twig\Environment;

/** Keep the native password entry accessible even when a partial staff login remains. */
final class StaffPasswordLoginSubscriber implements EventSubscriberInterface
{
    public function __construct(private TokenStorageInterface $tokens, private Config $config,
        private FormFactoryInterface $forms, private EventDispatcherInterface $events,
        private AuthenticationUtils $authentication, private Environment $twig) {}

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::CONTROLLER => ['passwordForm', 32]];
    }

    public function passwordForm(ControllerEvent $event): void
    {
        if(!$this->config->ready())return; // Incomplete setup leaves the native password page unchanged.
        $r = $event->getRequest();
        if (!$event->isMainRequest() || $r->attributes->get('_route') !== 'admin_login'
            || !in_array($r->getMethod(), ['GET', 'HEAD'], true)
            || !($this->tokens->getToken()?->getUser() instanceof Member)) return;

        // No logout or proof mutation on GET. The native firewall still handles every POST,
        // including its CSRF, password check, throttling and the mandatory additional factor.
        $event->setController(function (Request $request): Response {
            $headers = ['Cache-Control'=>'no-store, private', 'Pragma'=>'no-cache',
                'Referrer-Policy'=>'same-origin', 'X-Content-Type-Options'=>'nosniff',
                'X-Frame-Options'=>'DENY'];
            if (!$request->isSecure() || $request->getSchemeAndHttpHost() !== $this->config->origin()) {
                return new Response('HTTPSのログインURLからアクセスしてください。', 403, $headers);
            }
            $builder = $this->forms->createNamedBuilder('', LoginType::class);
            $this->events->dispatch(new EventArgs(['builder'=>$builder], $request),
                EccubeEvents::ADMIN_ADMIM_LOGIN_INITIALIZE);
            return new Response($this->twig->render('@admin/login.twig', [
                'form'=>$builder->getForm()->createView(),
                'error'=>$this->authentication->getLastAuthenticationError(),
            ]), 200, $headers);
        });
    }
}
