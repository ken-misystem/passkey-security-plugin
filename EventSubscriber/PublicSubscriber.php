<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\EventSubscriber;

use Eccube\Entity\{Customer,Member};
use Eccube\Event\{TemplateEvent,EccubeEvents,EventArgs};
use Eccube\Service\TwoFactorAuthService;
use Plugin\PasskeySecurity\Resource\Runtime\{Config,Store,Policy,PublicSettings,PublicPolicy,ClockEventLog};
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\{KernelEvents,Event\RequestEvent};
use Symfony\Component\HttpFoundation\{RedirectResponse,Response};
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Event\{LoginSuccessEvent,CheckPassportEvent,LogoutEvent};

final class PublicSubscriber implements EventSubscriberInterface
{
    public function __construct(private PublicSettings $settings,private Config $config,private Store $store,
        private Policy $policy,private PublicPolicy $publicPolicy,private TokenStorageInterface $tokens,private UrlGeneratorInterface $urls,
        private ClockEventLog $clockLog,private TwoFactorAuthService $twoFactorAuth){}
    public static function getSubscribedEvents():array
    {
        return [KernelEvents::REQUEST=>['guard',7],CheckPassportEvent::class=>['passport',-512],LoginSuccessEvent::class=>['login',-1024],
            LogoutEvent::class=>'logout',EccubeEvents::FRONT_FORGOT_RESET_COMPLETE=>'reset',
            'Mypage/navi.twig'=>'navigation','Mypage/login.twig'=>'navigation','@admin/login.twig'=>'navigation'];
    }
    public function navigation(TemplateEvent $e):void
    {
        if ($this->config->shopEditionActive()) return;
        if(!$this->settings->ready())return;
        $e->setParameter('ps_public_staff',str_starts_with($e->getView(),'@admin/'));
        if($e->getView()==='Mypage/navi.twig'){
            $s=preg_replace('~(</ul>)~',"{% include '@PasskeySecurity/public_menu.twig' %}$1",$e->getSource(),1);
        }else $s=preg_replace('~({%\s*block\s+main\s*%})~',"$1{% include '@PasskeySecurity/public_link.twig' %}",$e->getSource(),1);
        if(is_string($s))$e->setSource($s);
    }
    public function passport(CheckPassportEvent $e):void
    {
        if ($this->config->shopEditionActive()) return;
        if(!$this->settings->ready())return;
        $u=$e->getPassport()->getUser();
        if($u instanceof Customer&&$this->store->resetRequired(Policy::subject($u)))
            throw new CustomUserMessageAuthenticationException('パスワードの再設定が必要です。');
    }
    public function login(LoginSuccessEvent $e):void
    {
        if ($this->config->shopEditionActive()) return;
        if(!$this->settings->ready())return;
        $u=$e->getUser();$s=$e->getRequest()->getSession();Policy::clear($s);
        $badge=\Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials::class;
        if($e->getPassport()->hasBadge($badge)&&$e->getPassport()->getBadge($badge)->isResolved()){
            if($u instanceof Member)$this->policy->prove($s,$u,'password',time());
            elseif($u instanceof Customer)$this->policy->prove($s,$u,'session',time());
        }
        if($u instanceof Member&&$this->publicPolicy->mustAuthenticate($u))
            $e->setResponse(new RedirectResponse($this->urls->generate('ps_member')));
    }
    public function guard(RequestEvent $e):void
    {
        if(!$e->isMainRequest())return;
        if ($this->config->shopEditionActive()) return;
        $r=$e->getRequest();$u=$this->tokens->getToken()?->getUser();
        if(!$this->settings->ready())return; // Fresh install leaves native store/login untouched.
        if(!($u instanceof Customer)&&!($u instanceof Member))return;
        $route=$r->attributes->get('_route');
        // The settings controller checks authorization and resumes its own MFA-protected operation.
        if ($route === 'passkey_security_admin_config' && $u instanceof Member) return;
        if(in_array($route,['ps_customer','ps_member','logout','admin_logout','admin_login'],true))return;
        if($u instanceof Customer){
            $reset=$this->store->resetRequired(Policy::subject($u));
            if(!$reset&&(!$this->settings->migrated()||($r->hasSession()&&$this->policy->complete($r->getSession(),$u,time()))))return;
            $this->tokens->setToken(null);if($r->hasSession())$r->getSession()->invalidate();$target=$reset?'forgot':'mypage_login';
        }else{
            try{
                if(!$this->publicPolicy->mustAuthenticate($u))return;
                if($r->hasSession()&&$this->policy->staffAccess($r->getSession(),$u,time()))return;
                // EC-CUBE checks native 2FA after this listener, including on ps_member.
                if(($route==='admin_two_factor_auth'||($route==='admin_two_factor_auth_set'&&!$u->getTwoFactorAuthKey()))
                    &&$u->isTwoFactorAuthEnabled()&&$this->twoFactorAuth->isEnabled()&&!$this->twoFactorAuth->isAuth($u))return;
            }catch(\UnexpectedValueException $error){
                if(!Policy::isClockFailure($error))throw $error;
                $response=new Response('認証処理を完了できませんでした。少し待ってから再度お試しください。',503,
                    ['Cache-Control'=>'no-store, private','Retry-After'=>'2']);
                $incident=$this->clockLog->rejected($error,'guard','member',$r->getMethod());
                if($incident!==null)$response->headers->set('X-PasskeySecurity-Incident',$incident);
                $e->setResponse($response);return;
            }catch(\Doctrine\DBAL\Exception\DriverException $error){
                if(!Store::isTransientDatabaseFailure($error))throw $error;
                $e->setResponse(new Response('認証処理が混み合っています。少し待ってから再度お試しください。',503,
                    ['Cache-Control'=>'no-store, private','Retry-After'=>'2']));return;
            }
            $target='ps_member';
        }
        $e->setResponse(in_array($r->getMethod(),['GET','HEAD'],true)?new RedirectResponse($this->urls->generate($target),303)
            :new Response('追加認証が必要です。画面を開き直してください。',403,['Cache-Control'=>'no-store']));
    }
    public function logout(LogoutEvent $e):void
    {
        if (!$this->config->shopEditionActive() && $e->getRequest()->hasSession()) {
            Policy::clear($e->getRequest()->getSession());
        }
    }
    public function reset(EventArgs $e):void
    {
        if ($this->config->shopEditionActive()) return;
        if($this->settings->ready()){$u=$e->getArgument('Customer');$this->store->passwordReset(Policy::subject($u),(string)$u->getPassword());}
    }
}
