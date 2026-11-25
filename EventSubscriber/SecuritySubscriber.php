<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\EventSubscriber;

use Eccube\Entity\Customer;
use Eccube\Entity\Member;
use Eccube\Event\EccubeEvents;
use Eccube\Event\EventArgs;
use Eccube\Service\TwoFactorAuthService;
use Plugin\PasskeySecurity\Resource\Runtime\Config;
use Plugin\PasskeySecurity\Resource\Runtime\Policy;
use Plugin\PasskeySecurity\Resource\Runtime\Store;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

final class SecuritySubscriber implements EventSubscriberInterface
{
    public function __construct(private Store $store, private Policy $policy, private Config $config,
        private TokenStorageInterface $tokens, private UrlGeneratorInterface $urls, private TwoFactorAuthService $twoFactorAuth) {}
    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST=>['guard', 7], CheckPassportEvent::class=>['passport', -512],
            KernelEvents::RESPONSE=>['expireLegacyRememberCookie',-4096],
            // Native PasswordMigratingListener runs at 0. Stamp the final hash, not the pre-upgrade hash.
            LoginSuccessEvent::class=>['login', -1024], LogoutEvent::class=>'logout',
            EccubeEvents::FRONT_FORGOT_RESET_COMPLETE=>'reset'];
    }
    public function passport(CheckPassportEvent $event): void
    {
        if (!$this->config->shopEditionActive()) return;
        $user = $event->getPassport()->getUser();
        if ($user instanceof Customer && $this->store->resetRequired(Policy::subject($user))) {
            throw new CustomUserMessageAuthenticationException('サイト再開に伴いパスワードの再設定が必要です。「パスワードをお忘れの方」からお手続きください。');
        }
    }
    public function login(LoginSuccessEvent $event): void
    {
        if (!$this->config->shopEditionActive()) return;
        $r = $event->getRequest(); Policy::clear($r->getSession());
        $user = $event->getUser();
        // An old remember-me cookie carries no revocation generation: require explicit login again.
        if ($user instanceof Customer && !($event->getAuthenticatedToken() instanceof \Symfony\Component\Security\Core\Authentication\Token\RememberMeToken)) {
            $this->policy->prove($r->getSession(),$user,'session',time());
        }
        if ($user instanceof Member) {
            // A programmatic passkey login uses SelfValidatingPassport, never password proof.
            $badge=\Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials::class;
            if ($event->getPassport()->hasBadge($badge) && $event->getPassport()->getBadge($badge)->isResolved()) {
                $this->policy->prove($r->getSession(),$user,'password',time());
                $this->policy->proveInitialPassword($r->getSession(),$user,time());
                $hint=$r->getSession()->get('ps_staff_initial_hint');
                if(is_array($hint)&&($hint['at']??0)>=time()-1800&&($hint['at']??PHP_INT_MAX)<=time()
                    &&hash_equals((string)$user->getLoginId(),(string)($hint['login']??'')))
                    $r->getSession()->set('ps_staff_initial_requested',['at'=>time(),'stamp'=>$this->policy->stamp($user)]);
            }
            $event->setResponse(new RedirectResponse($this->urls->generate('ps_member')));
        }
    }
    public function logout(LogoutEvent $event): void
    {
        if (!$this->config->shopEditionActive()) return;
        if ($event->getRequest()->hasSession()) Policy::clear($event->getRequest()->getSession());
    }
    public function expireLegacyRememberCookie(ResponseEvent $event):void
    {
        if (!$this->config->shopEditionActive()) return;
        $r=$event->getRequest();
        // Run after the native remember-me response listener, including failed cookie authentication.
        if($event->isMainRequest()&&$r->cookies->has('eccube_remember_me')) {
            $event->getResponse()->headers->clearCookie('eccube_remember_me',$r->getBasePath()?:'/');
        }
    }
    public function reset(EventArgs $event): void
    {
        if (!$this->config->shopEditionActive()) return;
        $u = $event->getArgument('Customer');
        $this->store->passwordReset(Policy::subject($u), (string)$u->getPassword());
    }
    public function guard(RequestEvent $event): void
    {
        if (!$this->config->shopEditionActive()) return;
        $r = $event->getRequest();
        // Runs after the firewall and before any controller; includes subrequests.
        // Every enabled-plugin request fails closed if configuration/activation is incomplete.
        try { $this->config->data(); $this->store->epoch(); }
        catch (\Throwable $e) {
            $event->setResponse(new Response('認証設定の準備中です。', 503, ['Cache-Control'=>'no-store'])); return;
        }
        $u = $this->tokens->getToken()?->getUser();
        if (!($u instanceof Member) && !($u instanceof Customer)) return;
        $route = $r->attributes->get('_route');
        // The settings controller checks authorization and resumes its own MFA-protected operation.
        if ($route === 'passkey_security_admin_config' && $u instanceof Member) return;
        // Authentication entry only: allow the native password form, never admin content.
        // StaffPasswordLoginSubscriber renders it without the core's signed-in redirect.
        if ($u instanceof Member && $route === 'admin_login'
            && in_array($r->getMethod(), ['GET', 'HEAD'], true)) return;
        if (in_array($route, ['ps_customer','ps_member','logout','admin_logout','ps_staff_password_reset','ps_staff_password_confirm','ps_staff_email_confirm','ps_staff_initial_request','ps_staff_initial_email','ps_staff_initial_link'], true)) return;
        if ($u instanceof Member
            && ($route === 'admin_two_factor_auth' || ($route === 'admin_two_factor_auth_set' && !$u->getTwoFactorAuthKey()))
            && $u->isTwoFactorAuthEnabled() && $this->twoFactorAuth->isEnabled() && !$this->twoFactorAuth->isAuth($u)) return;
        $complete = $r->hasSession() && ($u instanceof Member
            ? $this->policy->staffAccess($r->getSession(), $u, time())
            : $this->policy->complete($r->getSession(), $u, time()));
        if (!$complete) {
            if ($u instanceof Customer) {
                $this->tokens->setToken(null);
                if ($r->hasSession()) $r->getSession()->invalidate();
                $target = $this->urls->generate($this->store->resetRequired(Policy::subject($u))?'forgot':'mypage_login');
            } else $target = $this->urls->generate('ps_member');
            if($u instanceof Member&&$route==='ps_staff_email_manage'&&$u->getWork()?->getId()===1
                &&(in_array($r->getMethod(),['GET','HEAD'],true)||$r->headers->get('Origin')===$this->config->origin())){
                $response=new RedirectResponse($this->urls->generate('ps_member',['staff_mail_self'=>1]),303);
                $response->headers->set('Cache-Control','no-store, private');$event->setResponse($response);return;
            }
            if($u instanceof Member&&$route==='admin_ps_staff_mail'&&$u->getWork()?->getId()===1
                &&$u->getAuthority()?->getId()===0&&preg_match('/^[1-9][0-9]{0,8}$/D',(string)$r->attributes->get('id',''))
                &&(in_array($r->getMethod(),['GET','HEAD'],true)||$r->headers->get('Origin')===$this->config->origin())){
                $response=new RedirectResponse($this->urls->generate('ps_member',['staff_mail_return'=>(int)$r->attributes->get('id')]),303);
                $response->headers->set('Cache-Control','no-store');$event->setResponse($response);return;
            }
            $response = in_array($r->getMethod(), ['GET','HEAD'], true)
                ? new RedirectResponse($target)
                : new Response('追加の認証が必要です。', 403);
            $response->headers->set('Cache-Control', 'no-store'); $event->setResponse($response);
            if ($u instanceof Customer) $response->headers->clearCookie('eccube_remember_me',$r->getBasePath()?:'/');
        }
    }
}
