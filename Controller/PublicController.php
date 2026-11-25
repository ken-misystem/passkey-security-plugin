<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Controller;

use Eccube\Controller\AbstractController;
use Eccube\Entity\{Customer,Member};
use Doctrine\ORM\EntityManagerInterface;
use Plugin\PasskeySecurity\Resource\Runtime\{Config,Store,Policy,Ceremony,PublicSettings,PublicPolicy,ClockEventLog};
use Symfony\Component\HttpFoundation\{Request,Response,JsonResponse};
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\UserAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;

/** Public edition: existing native login remains the entry point; no reopening or SMTP assumptions. */
final class PublicController extends AbstractController
{
    public function __construct(private Config $config,private Store $store,private Policy $policy,private PublicSettings $settings,
        private PublicPolicy $publicPolicy,private Ceremony $ceremony,private EntityManagerInterface $em,
        private UserPasswordHasherInterface $hasher,private UserAuthenticatorInterface $auth,
        private AuthenticatorInterface $customerAuthenticator,private AuthenticatorInterface $memberAuthenticator,
        private ClockEventLog $clockLog){}
    private function headers(Response $r,string $nonce=''):Response
    {
        foreach(['Cache-Control'=>'no-store, private','Referrer-Policy'=>'same-origin','X-Frame-Options'=>'DENY','X-Content-Type-Options'=>'nosniff']as$k=>$v)$r->headers->set($k,$v);
        if($nonce!=='')$r->headers->set('Content-Security-Policy',"default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        return $r;
    }
    private function transientDatabaseResponse(bool $json=false):Response
    {
        $message='認証処理が混み合っています。少し待ってから再度お試しください。';
        return $this->headers($json?new JsonResponse(['ok'=>false,'error'=>$message],503,['Retry-After'=>'2'])
            :new Response($message,503,['Retry-After'=>'2']));
    }
    private function transientClockResponse(\Throwable $error,Request $request,string $component,string $realm,bool $json=false):Response
    {
        $message='認証処理を完了できませんでした。少し待ってから再度お試しください。';
        $response=$this->headers($json?new JsonResponse(['ok'=>false,'error'=>$message],503,['Retry-After'=>'2'])
            :new Response($message,503,['Retry-After'=>'2']));
        $incident=$this->clockLog->rejected($error,$component,$realm,$request->getMethod());
        if($incident!==null)$response->headers->set('X-PasskeySecurity-Incident',$incident);
        if(!$json){
            $route=$component==='configure'?'passkey_security_admin_config':($realm==='customer'?'ps_customer':'ps_member');
            $url=htmlspecialchars($this->generateUrl($route),ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
            $response->setContent('<!doctype html><html lang="ja"><meta charset="utf-8"><title>認証処理の確認</title><p>'.$message.'</p><p>同じ操作を再送せず、2秒以上待って<a href="'.$url.'">画面を開き直し、状態を確認してください</a>。</p>'.($incident!==null?'<p>照会番号：'.$incident.'</p>':'').'</html>');
        }
        return $response;
    }
    private function account(string $kind):object
    {
        $u=$this->getUser();
        if(!($kind==='member'&&$u instanceof Member&&$u->getWork()?->getId()===1)
            &&!($kind==='customer'&&$u instanceof Customer&&$u->getStatus()?->getId()===2))throw new \RuntimeException('account_required');
        return $u;
    }
    /** @Route("/%eccube_admin_route%/plugin/passkey/config", name="passkey_security_admin_config", methods={"GET","POST"}) */
    public function configure(Request $r):Response
    {
        $u=$this->account('member');if($u->getAuthority()?->getId()!==0)throw $this->createAccessDeniedException();
        $message='';
        if($r->isMethod('POST')){
            try{
                if(!$r->isSecure()||$r->headers->get('Origin')!==$r->getSchemeAndHttpHost()
                    ||!$this->isCsrfTokenValid('ps_public_config',$r->request->get('_token')))throw new \RuntimeException('config_request');
                // Never reset the rate bucket or persist a request's Host on a public GET.
                if($this->store->active())$this->store->limit('public-config:'.Policy::subject($u),time(),5);
                if(!$this->hasher->isPasswordValid($u,(string)$r->request->get('password')))throw new \RuntimeException('config_password');
                if($this->settings->ready()&&$this->publicPolicy->enrolled($u))$this->policy->staffProof($r->getSession(),$u,time());
                $origin=(string)$r->request->get('origin');
                if($origin!==$r->getSchemeAndHttpHost())throw new \RuntimeException('config_origin');
                $required=$r->request->get('staff_required')==='1';
                if($required&&(!$this->publicPolicy->enrolled($u)||!$this->policy->complete($r->getSession(),$u,time())))throw new \RuntimeException('enroll_admin_first');
                $this->settings->save($origin,(string)$r->request->get('name'),$required,$this->store);$this->store->audit(Policy::subject($u),'public_policy_saved');
                $message='保存しました。既存のパスワードと認証器は変更していません。';
            }catch(\Throwable $error){
                if(Policy::isClockFailure($error))return $this->transientClockResponse($error,$r,'configure','member');
                if(Store::isTransientDatabaseFailure($error))return $this->transientDatabaseResponse();
                $message='保存できません。HTTPSのURL・現在のパスワードをご確認ください。必須化の前に、ご自身の追加認証を登録して本人確認を済ませてください。';
            }
        }
        $nonce=Ceremony::encode(random_bytes(24));
        return $this->headers($this->render('@PasskeySecurity/public_config.twig',['nonce'=>$nonce,'message'=>$message,
            'origin'=>$this->settings->get('origin')??($r->isSecure()?$r->getSchemeAndHttpHost():''),
            'name'=>$this->settings->get('name')??'アカウント','required'=>$this->settings->required(),'ready'=>$this->settings->ready()]),$nonce);
    }
    /**
     * @Route("/mypage/login/security", name="ps_customer", defaults={"kind"="customer"}, methods={"GET","POST"})
     * @Route("/%eccube_admin_route%/login/security", name="ps_member", defaults={"kind"="member"}, methods={"GET","POST"})
     */
    public function security(Request $r,string $kind):Response
    {
        try{
            if(!$this->settings->ready())return $this->headers(new Response('パスキーの準備は管理者のプラグイン設定画面から行ってください。従来のログインは引き続き利用できます。',409));
            if(!$r->isSecure()||$r->getSchemeAndHttpHost()!==$this->config->origin())throw new \RuntimeException('https_origin');
            if($r->isMethod('GET')){
                $u=$this->getUser();$same=$kind==='member'?$u instanceof Member:$u instanceof Customer;
                $subject=$same?Policy::subject($u):null;$nonce=Ceremony::encode(random_bytes(24));
                $f=$subject?$this->store->factor($subject):null;
                return $this->headers($this->render('@PasskeySecurity/public_security.twig',['kind'=>$kind,'signed_in'=>$same,
                    'nonce'=>$nonce,'csrf_id'=>'ps_public_'.$kind,'endpoint'=>$r->getPathInfo(),
                    'home'=>$this->generateUrl($kind==='member'?'admin_homepage':'mypage'),
                    'login'=>$this->generateUrl($kind==='member'?'admin_login':'mypage_login'),
                    'rows'=>$subject?$this->store->inventory($subject):[],'totp'=>(int)($f['confirmed']??0)===1,
                    'has_passkey'=>$subject&&count($this->store->credentials($subject))>0,
                    'name'=>$this->config->data()['rp_name']]),$nonce);
            }
            if($r->headers->get('Origin')!==$this->config->origin()||strlen($r->getContent())>100000)throw new \RuntimeException('request_origin');
            $i=json_decode($r->getContent(),true,16,JSON_THROW_ON_ERROR);
            if(!is_array($i)||!$this->isCsrfTokenValid('ps_public_'.$kind,$i['_token']??null))throw new \RuntimeException('csrf');
            $this->store->limit('public-ip:'.(string)$r->getClientIp(),time(),60);
            return $this->headers(new JsonResponse($this->action($r,$kind,$i)));
        }catch(\Throwable $error){
            if(Policy::isClockFailure($error))return $this->transientClockResponse($error,$r,'security',$kind,$r->isMethod('POST'));
            if(Store::isTransientDatabaseFailure($error))return $this->transientDatabaseResponse($r->isMethod('POST'));
            return $this->headers($r->isMethod('POST')?new JsonResponse(['ok'=>false,'error'=>'確認できませんでした。画面を開き直し、入力内容と登録手順をご確認ください。'],403):new Response('HTTPSの認証用URLからアクセスしてください。',403));
        }
    }
    private function action(Request $r,string $kind,array $i):array
    {
        $s=$r->getSession();$now=time();$a=$i['action']??'';
        if($a==='login_options')return ['ok'=>true,'options'=>$this->ceremony->options($s,$kind,'assert',null,$now)];
        if($a==='login_verify'){
            $v=$this->ceremony->assertion($s,$kind,null,$i,$now);$u=$this->em->find($kind==='member'?Member::class:Customer::class,(int)explode(':',$v['subject'])[1]);
            if(!$u||($u instanceof Member&&$u->getWork()?->getId()!==1)||($u instanceof Customer&&$u->getStatus()?->getId()!==2)
                ||$this->store->resetRequired($v['subject']))throw new \RuntimeException('account_unavailable');
            $this->auth->authenticateUser($u,$kind==='member'?$this->memberAuthenticator:$this->customerAuthenticator,$r);
            $this->policy->prove($s,$u,'passkey',$now,$v['generation']);if($u instanceof Customer)$this->policy->prove($s,$u,'session',$now,$v['generation']);
            return ['ok'=>true,'redirect'=>$this->generateUrl($kind==='member'?'admin_homepage':'mypage')];
        }
        $u=$this->account($kind);$subject=Policy::subject($u);$generation=$this->store->generation($subject);
        $this->store->limit('public-account:'.$subject.':'.($a==='verify_totp'?'totp':'changes'),$now,10);
        if(isset($i['password'])&&is_string($i['password'])&&$i['password']!==''){
            if(!$this->hasher->isPasswordValid($u,$i['password']))throw new \RuntimeException('password');
            $now=Policy::decisionTime($now,'password_check');
            $this->policy->prove($s,$u,$u instanceof Member?'password':'reauth',$now,$generation);
        }
        if($a==='claim_ticket'&&$u instanceof Member){
            $this->policy->proofGeneration($s,$u,'password',$now,300);
            $g=$this->store->claimTicket($subject,(string)($i['ticket']??''),$now);
            $this->policy->prove($s,$u,'enroll',$now,$g);
            return ['ok'=>true,'redirect'=>$r->getPathInfo()];
        }
        if($a==='change_password'&&$u instanceof Member){
            $g=$this->policy->proofGeneration($s,$u,'enroll',$now,600);$new=$i['new_password']??null;
            if(!$this->store->resetRequired($subject)||!is_string($new)||mb_strlen($new)<12||strlen($new)>72
                ||!$this->hasher->isPasswordValid($u,(string)($i['password']??''))||$this->hasher->isPasswordValid($u,$new))throw new \RuntimeException('new_password');
            $g=$this->em->wrapInTransaction(function()use($u,$new,$subject,$g,$now):int{
                $hash=$this->hasher->hashPassword($u,$new);Policy::decisionTime($now,'password_hash');
                $u->setPassword($hash);$u->setSalt(null);$this->em->flush();
                return $this->store->passwordReset($subject,$u->getPassword(),$g);
            });
            Policy::clear($s);$s->migrate(true);$this->policy->prove($s,$u,'enroll',$now,$g);$this->policy->prove($s,$u,'password',$now,$g);
            return ['ok'=>true,'redirect'=>$r->getPathInfo()];
        }
        if($a==='register_options'){
            $this->publicPolicy->enrollment($s,$u,$now);
            return ['ok'=>true,'options'=>$this->ceremony->options($s,$kind,'register',$subject,$now)];
        }
        if($a==='register_verify'){
            $this->publicPolicy->enrollment($s,$u,$now);$g=$this->ceremony->register($s,$kind,$subject,$i,$now);
            $this->policy->prove($s,$u,'passkey',$now,$g);if($u instanceof Member)$this->store->finishRecovery($subject,$g,$now);if($u instanceof Customer)$this->policy->prove($s,$u,'session',$now,$g);
            return ['ok'=>true,'redirect'=>$r->getPathInfo()];
        }
        if($a==='verify_options'&&$u instanceof Member)return ['ok'=>true,'options'=>$this->ceremony->options($s,$kind,'assert',$subject,$now)];
        if($a==='verify_passkey'&&$u instanceof Member){
            $v=$this->ceremony->assertion($s,$kind,$subject,$i,$now);$this->policy->prove($s,$u,'passkey',$now,$v['generation']);
            return ['ok'=>true,'redirect'=>$this->generateUrl('admin_homepage')];
        }
        if($a==='totp_setup'&&$u instanceof Member){
            $g=$this->publicPolicy->enrollment($s,$u,$now);Config::dependencies();$f=$this->store->factor($subject);
            if((int)$f['confirmed']===1)throw new \RuntimeException('already_enrolled');
            if($f['secret']===''){$otp=\OTPHP\TOTP::create();$this->store->setPendingTotp($subject,$otp->getSecret(),$g);}
            else $otp=\OTPHP\TOTP::createFromSecret($this->store->totpSecret($f));
            $otp->setLabel('staff-'.substr($this->config->digest($subject),0,12));$otp->setIssuer($this->config->data()['rp_name']);
            return ['ok'=>true,'secret'=>$otp->getSecret(),'provisioning_uri'=>$otp->getProvisioningUri()];
        }
        if($a==='verify_totp'&&$u instanceof Member){
            $g=$this->policy->proofGeneration($s,$u,'password',$now,300);
            $v=$this->store->consumeTotp($subject,(string)($i['code']??''),$now,$g);$this->policy->prove($s,$u,'totp',$now,$v);$this->store->finishRecovery($subject,$v,$now);$s->migrate(true);
            return ['ok'=>true,'redirect'=>$this->generateUrl('admin_homepage')];
        }
        if($a==='revoke'){
            $g=$this->publicPolicy->enrollment($s,$u,$now);$this->store->revokeOwn($subject,(string)($i['id']??''),$g,$now);
            Policy::clear($s);$s->migrate(true);return ['ok'=>true,'redirect'=>$r->getPathInfo()];
        }
        throw new \RuntimeException('action');
    }
}
