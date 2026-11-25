<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Controller;

use Eccube\Controller\AbstractController;
use Eccube\Entity\Member;
use Doctrine\ORM\EntityManagerInterface;
use Plugin\PasskeySecurity\Resource\Runtime\{Config,Store,Policy,Ceremony,InitialLink};
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\UserAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;

final class InitialLinkController extends AbstractController
{
    public function __construct(private Config $config,private Store $store,private Policy $policy,private InitialLink $links,
        private EntityManagerInterface $em,private UserAuthenticatorInterface $userAuthenticator,private AuthenticatorInterface $memberAuthenticator) {}

    /** @Route("/%eccube_admin_route%/login/initial-registration/start",name="ps_staff_initial_link",methods={"GET","POST"}) */
    public function index(Request $r): Response
    {
        if (!$this->config->shopEditionActive()) throw $this->createNotFoundException();
        $status=200;$message='メールのリンクから、パスキーまたは認証アプリの初回登録を始めます。';$reason='';
        try{
            if(!$r->isSecure()||$r->getSchemeAndHttpHost()!==$this->config->origin())throw new \RuntimeException('initial_link_invalid');
            if($r->isMethod('POST')){
                if($r->headers->get('Origin')!==$this->config->origin()||strlen((string)$r->getContent())>8192
                    ||!$this->isCsrfTokenValid('ps_staff_initial_link',$r->request->get('_token')))throw new \RuntimeException('initial_link_invalid');
                $now=time();$this->store->limit('initial-link-ip:'.$r->getClientIp(),$now,20);
                $current=$this->getUser();$expected=is_object($current)?Policy::subject($current):null;
                $p=$this->links->inspect((string)$r->request->get('token',''),$now,$expected);
                if(is_object($current)&&(!$current instanceof Member||Policy::subject($current)!==$p['subject']))throw new \RuntimeException('initial_link_other_account');
                $u=$this->em->find(Member::class,(int)substr($p['subject'],7));
                if(!$u||$u->getWork()?->getId()!==1)throw new \RuntimeException('initial_link_invalid');
                $this->store->limit('initial-link-subject:'.$p['subject'],$now,10);
                $generation=$this->em->getConnection()->transactional(function()use($r,$now,$expected):int{
                    $p=$this->links->inspect((string)$r->request->get('token',''),$now,$expected);
                    return $this->store->claimTicket($p['subject'],$p['ticket'],$now);
                });
                // Self-validating native authentication creates no password/MFA proof. The normal guard
                // still denies all admin content until registration + required password change complete.
                $this->userAuthenticator->authenticateUser($u,$this->memberAuthenticator,$r);
                $this->policy->prove($r->getSession(),$u,'enroll',$now,$generation);
                $this->store->audit($p['subject'],'initial_link_claimed');
                $response=$this->redirectToRoute('ps_member',['enrollment'=>'link'],303);
                foreach($this->headers()as$k=>$v)$response->headers->set($k,$v);
                return $response;
            }
        }catch(\Throwable $e){
            $status=403;$reason=$e->getMessage();
            $message=match($reason){
                'initial_link_expired'=>'この登録リンクの有効期限が切れました。発行から1時間以内に使用してください。新しいリンクを管理者へ依頼してください。',
                'initial_link_replaced'=>'この登録リンクは再発行により無効になりました。最新のメールを開いてください。見つからない場合は再依頼してください。',
                'initial_link_used','security_ticket_already_claimed'=>'この登録リンクは使用済みです。同じブラウザで登録を続けてください。登録済みならログインへ、再開できなければ管理者へ再開を依頼してください。',
                'initial_link_other_account'=>'別のスタッフでログイン中です。ログアウトするか、別のブラウザで本人宛てのリンクを開いてください。',
                'security_rate_limited'=>'確認回数が多いため一時的に制限しています。5分ほど待ってからお試しください。',
                default=>'この登録リンクは使えません。メールのリンク全体を開き直してください。登録先メールの変更・解除後は新しいリンクを管理者へ依頼してください。',
            };
        }
        $nonce=Ceremony::encode(random_bytes(24));
        $u=$this->getUser();$canResume=$u instanceof Member&&$u->getWork()?->getId()===1&&$this->policy->fresh($r->getSession(),$u,'enroll',time(),600);
        $registered=$u instanceof Member&&((int)($this->store->factor(Policy::subject($u))['confirmed']??0)===1||count($this->store->credentials(Policy::subject($u)))>0);
        $response=$this->render('@PasskeySecurity/initial_link.twig',['can_resume'=>$canResume,'registered'=>$registered,'nonce'=>$nonce,'message'=>$message,'failed'=>$status!==200,'reason'=>$reason]);
        $response->setStatusCode($status);
        foreach($this->headers()as$k=>$v)$response->headers->set($k,$v);
        $response->headers->set('Content-Security-Policy',"default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        return $response;
    }
    private function headers():array{return ['Cache-Control'=>'no-store, private','Pragma'=>'no-cache','Referrer-Policy'=>'same-origin','X-Content-Type-Options'=>'nosniff','X-Frame-Options'=>'DENY'];}
}
