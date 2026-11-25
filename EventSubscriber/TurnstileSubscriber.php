<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\EventSubscriber;
use Plugin\PasskeySecurity\Resource\Runtime\StorePresentation;
use Plugin\PasskeySecurity\Resource\Turnstile\{Configuration,Verifier,Routes,RegistrationFlow,VisitPage,SearchCrawler};
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\{RequestEvent,ResponseEvent};
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpFoundation\{Response,JsonResponse};
use Symfony\Component\Routing\{RouterInterface,Matcher\UrlMatcher};
final class TurnstileSubscriber implements EventSubscriberInterface
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private Configuration $config,private Verifier $verifier,private RouterInterface $router,private StorePresentation $presentation,private ?\Symfony\Component\Security\Csrf\CsrfTokenManagerInterface $csrf=null,private ?\Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface $tokens=null,private ?\Plugin\PasskeySecurity\Resource\Runtime\Policy $policy=null){}
    public static function getSubscribedEvents():array{return [KernelEvents::REQUEST=>[['guard',18],['guardStaff',6]],KernelEvents::RESPONSE=>['render',-900]];}
    private const STAFF_ROUTES=['ps_member','ps_staff_email_manage'];
    private function recentStaff(\Symfony\Component\HttpFoundation\Request $r,bool $requireFresh=true):bool
    {
        // Server-only clearance: active staff, completed MFA and a fresh proof; never a client flag.
        if(!$r->isSecure()||!$r->hasSession()||!$this->tokens||!$this->policy)return false;
        $until=$r->getSession()->get('ps_turnstile_visit_until',0);
        if(!is_int($until)||$until<time()||$until>time()+1800)return false;
        $u=$this->tokens->getToken()?->getUser();
        if(!$u instanceof \Eccube\Entity\Member||$u->getWork()?->getId()!==1)return false;
        if(!$requireFresh)return $this->policy->complete($r->getSession(),$u,time());
        try{$this->policy->staffProof($r->getSession(),$u,time());return true;}
        catch(\RuntimeException){return false;}
    }
    public function guard(RequestEvent $e):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        // Password login/anonymous forms stay before the firewall; staff clearance is evaluated after it.
        if(in_array($e->getRequest()->attributes->get('_route'),self::STAFF_ROUTES,true))return;
        $this->check($e);
    }
    public function guardStaff(RequestEvent $e):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        if(in_array($e->getRequest()->attributes->get('_route'),self::STAFF_ROUTES,true))$this->check($e);
    }
    private function check(RequestEvent $e):void
    {
        $r=$e->getRequest();
        // Activation is a state-changing GET in core. Complete the visit gate BEFORE it runs.
        if($e->isMainRequest() && in_array($r->getMethod(),['GET','HEAD'],true) && $r->attributes->get('_route')==='entry_activate'){
            try{
                $cfg=$this->config->data();
                if($cfg['enabled'] && (!$r->hasSession() || $r->getSession()->get('ps_turnstile_visit_until',0)<time())){
                    if(!$this->csrf || !$r->hasSession())throw new \RuntimeException('visit_session_required');
                    $response=new Response();VisitPage::apply($response,$cfg['site_key'],$this->router->generate('ps_turnstile_visit'),$this->csrf->getToken('ps_turnstile_visit')->getValue(),$this->presentation->appearance());
                    $e->setResponse($response);return;
                }
            }catch(\Throwable $error){$e->setResponse(new Response('安全確認を準備できませんでした。しばらくお待ちください。',503,['Cache-Control'=>'no-store, private']));return;}
        }
        $action=Routes::MAP[$r->attributes->get('_route')]??null;
        if(!$e->isMainRequest()||!$r->isMethod('POST')||$action===null)return;
        try{
            if(!$this->config->data()['enabled'])return;
            if(in_array($r->attributes->get('_route'),self::STAFF_ROUTES,true)&&$this->recentStaff($r,$r->attributes->get('_route')!=='ps_staff_email_manage'))return;
            $token=$r->request->get('cf-turnstile-response');
            if(str_contains($r->headers->get('Content-Type',''),'application/json')){
                if(strlen($r->getContent())>100000)throw new \RuntimeException('invalid_input');
                $d=json_decode($r->getContent(),true,16,JSON_THROW_ON_ERROR);$token=is_array($d)?($d['turnstile_token']??null):null;
                if (is_array($d) && in_array($r->attributes->get('_route'),['ps_customer','ps_member'],true) && in_array($d['action']??null,['register_verify','login_verify','verify_passkey'],true) && array_key_exists('turnstile_flow',$d)) {
                    if ($r->hasSession() && RegistrationFlow::consume($r->getSession(),$r->getPathInfo(),$d,time())) return;
                    throw new \RuntimeException('registration_flow_rejected');
                }
            }
            if($this->verifier->check($token,$action)){if($action==='visit')$r->attributes->set('_ps_visit_verified',true);elseif($r->hasSession())$r->getSession()->set('ps_turnstile_visit_until',time()+1800);$r->request->remove('cf-turnstile-response');return;}
        }catch(\Throwable $error){}
        $message='安全確認を完了できませんでした。入力画面に戻り、チェックを確認してからもう一度お試しください。';
        if (str_contains($r->headers->get('Content-Type', ''), 'application/json')) {
            $response = new JsonResponse(['ok' => false, 'error' => $message], 403);
        } else {
            $appearance = $this->presentation->appearance();
            $name = htmlspecialchars($appearance['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $favicon = $appearance['favicon'] === null ? '' : '<link rel="icon" href="'
                .htmlspecialchars($appearance['favicon'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8').'">';
            $response = new Response('<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                .'<title>安全確認 | '.$name.'</title>'.$favicon.'<main><h1>安全確認をお願いします</h1><p>'.$message
                .'</p><p>ブラウザの「戻る」で入力画面へ戻れます。時間をおいても解消しない場合は店舗へお問い合わせください。</p></main></html>', 403);
        }
        $response->headers->set('Cache-Control','no-store, private');$response->headers->set('Referrer-Policy','no-referrer');$e->setResponse($response);
    }
    public function render(ResponseEvent $e):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $response=$e->getResponse();$request=$e->getRequest();
        if(!$e->isMainRequest()||$response->getStatusCode()!==200||!str_contains($response->headers->get('Content-Type',''),'text/html'))return;
        try{$cfg=$this->config->data();}catch(\Throwable $error){$response->setStatusCode(503);$response->setContent('安全確認の設定を確認中です。しばらくお待ちください。');return;}
        if(!$cfg['enabled'])return;
        $html=(string)$response->getContent();if(str_contains($html,'id="ps-turnstile-script"'))return;
        $context=clone $this->router->getContext();$context->setMethod('POST');$matcher=new UrlMatcher($this->router->getRouteCollection(),$context);
        $site=htmlspecialchars($cfg['site_key'],ENT_QUOTES,'UTF-8');$found=false;$groups=[];
        $visited=$request->hasSession() && $request->getSession()->get('ps_turnstile_visit_until',0)>=time();
        $route=(string)$request->attributes->get('_route');
        $publicCrawler=SearchCrawler::allows($request);
        // Never cache an IP-specific exemption or issue a session clearance. Form guards still run.
        if($publicCrawler)$response->headers->set('Cache-Control','no-store, private');
        if(!$visited && !$publicCrawler && $request->isMethod('GET') && !$request->isXmlHttpRequest()
            && !str_contains($request->headers->get('Accept',''),'application/json')
            && (!str_starts_with($route,'admin_') || $route==='admin_login')){
            try{
                if(!$this->csrf || !$request->hasSession())throw new \RuntimeException('visit_session_required');
                VisitPage::apply($response,$cfg['site_key'],$this->router->generate('ps_turnstile_visit'),$this->csrf->getToken('ps_turnstile_visit')->getValue(),$this->presentation->appearance());
            }catch(\Throwable $error){
                $response->setStatusCode(503);$response->setContent('安全確認を準備できませんでした。しばらくお待ちください。');
                $response->headers->set('Cache-Control','no-store, private');
            }
            return;
        }
        $box=static function(string $action,string $appearance,bool $api=false)use($site):string{
            return '<div class="ps-turnstile" data-api="'.($api?'true':'false').'" data-sitekey="'.$site.'" data-action="'.$action.'" data-appearance="'.$appearance.'"><p class="ps-turnstile-status" role="status">安全確認を準備しています。</p><noscript>送信にはJavaScriptによる安全確認が必要です。</noscript></div>';
        };
        $recentStaff=$this->recentStaff($request);
        $html=preg_replace_callback('~<form\b[^>]*>.*?</form>~is',function(array $m)use($matcher,$request,$box,$visited,$recentStaff,&$found,&$groups){
            if(!preg_match('~^<form\b[^>]*\bmethod=["\']post["\']~i',$m[0]))return $m[0];
            preg_match('~^<form\b[^>]*\baction=["\']([^"\']*)["\']~i',$m[0],$a);
            $url=html_entity_decode($a[1]??$request->getPathInfo(),ENT_QUOTES);$parts=parse_url($url);
            if($parts===false||isset($parts['host'])&&$parts['host']!==$request->getHost())return $m[0];
            $path=$parts['path']??$request->getPathInfo();if(!str_starts_with($path,'/'))return $m[0];
            try{$match=$matcher->match($path);}catch(\Throwable $error){return $m[0];}
            $action=Routes::MAP[$match['_route']]??null;if($action===null)return $m[0];
            if($recentStaff&&in_array($match['_route'],self::STAFF_ROUTES,true))return $m[0];
            $found=true;$form=preg_replace('~^<form\b~','<form data-ps-turnstile-action="'.$action.'"',$m[0],1);
            if(isset($groups[$action]))return $form;$groups[$action]=true;
            $appearance='interaction-only';
            $safety=$box($action,$appearance);
            $pattern='~<(?:button\b(?![^>]*\btype=["\'](?:button|reset)["\'])|input\b(?=[^>]*\btype=["\']submit["\']))[^>]*>~i';
            $form=preg_replace($pattern,$safety.'$0',$form,1,$count);
            return $count?$form:substr($form,0,-7).$safety.'</form>';
        },$html);
        $route=$request->attributes->get('_route');
        if(in_array($route,['ps_customer','ps_member'],true)&&!$request->attributes->get('_ps_security_read_only',false)&&!($route==='ps_member'&&$recentStaff)){
            $found=true;$safety=$box(Routes::MAP[$route],'interaction-only',true);
            $primary=preg_quote((string)$request->attributes->get('_ps_security_primary','login-passkey'),'~');
            if(str_contains($html,'<div id="auth-safety-slot"></div>')){$html=str_replace('<div id="auth-safety-slot"></div>',$safety,$html);$count=1;}else $html=preg_replace('~<button\b(?=[^>]*\bid=["\']'.$primary.'["\'])[^>]*>~',$safety.'$0',$html,1,$count);
            if(!$count)$html=str_replace('</main>',$safety.'</main>',$html);
        }
        if(!$found)return;
        $nonce=base64_encode(random_bytes(24));$csp=$response->headers->get('Content-Security-Policy');
        if($csp){
            if(preg_match("~script-src[^;]*'nonce-([^']+)'~",$csp,$m))$nonce=$m[1];
            foreach(['script-src','frame-src','connect-src']as$directive){
                $addition='https://challenges.cloudflare.com';
                if(preg_match('~(?:^|;)\\s*'.$directive.'\\s+([^;]+)~',$csp,$m)){
                    $value=trim(str_replace("'none'",'', $m[1]));if(!str_contains($value,$addition))$value.=' '.$addition;
                    $csp=preg_replace('~((?:^|;)\\s*'.$directive.')\\s+[^;]+~','$1 '.$value,$csp,1);
                }else $csp.='; '.$directive.' '.$addition;
            }
            $response->headers->set('Content-Security-Policy',$csp);
        }
        $nonce=htmlspecialchars($nonce,ENT_QUOTES);$script=file_get_contents(__DIR__.'/../Resource/Turnstile/client.js');
        $ajaxPath=$this->router->getRouteCollection()->get('shopping_customer')?$this->router->generate('shopping_customer'):'';
        $addition='<style nonce="'.$nonce.'">.ps-turnstile{clear:both;max-width:100%;margin:14px 0}.password-help{color:#203044;background:#eef5f4;border-left:3px solid #175e68;padding:12px 16px;margin:12px 0;line-height:1.7}.password-help li,.password-help strong{color:inherit}.password-help code{color:inherit;white-space:normal;overflow-wrap:anywhere}.ps-turnstile-status{font-size:.9rem;line-height:1.6;margin:4px 0 8px}.ps-turnstile:has([hidden]){margin:0}.ps-turnstile[data-visit=true]{max-width:1080px;margin:18px auto;padding:12px 18px;border-radius:8px;background:#eef5f4;color:#203044}</style><script id="ps-turnstile-script" data-form-wait-seconds="'.$this->config->timeouts()['browser'].'" data-checkout-customer="'.htmlspecialchars($ajaxPath,ENT_QUOTES).'" nonce="'.$nonce.'">'.$script.'</script><script nonce="'.$nonce.'" src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=psTurnstileReady&amp;render=explicit" async defer></script>';
        $response->setContent(str_replace('</body>',$addition.'</body>',$html));$response->headers->set('Cache-Control','no-store, private');
    }
}
