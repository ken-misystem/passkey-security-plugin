<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Controller;
use Plugin\PasskeySecurity\Resource\Runtime\PasswordRules;

use Eccube\Controller\AbstractController;
use Eccube\Entity\Member;
use Eccube\Entity\Master\Work;
use Doctrine\ORM\EntityManagerInterface;
use Plugin\PasskeySecurity\Resource\Runtime\{Config,Store,Policy,Ceremony,StaffMailStore};
use Symfony\Component\HttpFoundation\{Request,Response,RedirectResponse};
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

final class StaffMailController extends AbstractController
{
    public function __construct(private Config $config,private Store $security,private StaffMailStore $mail,
        private Policy $policy,private EntityManagerInterface $em,private UserPasswordHasherInterface $hasher) {}
    /** @Route("/%eccube_admin_route%/login/initial-registration/email", name="ps_staff_initial_email", defaults={"mode"="initial_email"}, methods={"GET","POST"})
     * @Route("/%eccube_admin_route%/login/initial-code-request", name="ps_staff_initial_request", defaults={"mode"="initial_request"}, methods={"GET","POST"})
     * @Route("/%eccube_admin_route%/login/password-reset", name="ps_staff_password_reset", defaults={"mode"="request"}, methods={"GET","POST"})
     * @Route("/%eccube_admin_route%/login/password-reset/confirm", name="ps_staff_password_confirm", defaults={"mode"="reset"}, methods={"GET","POST"})
     * @Route("/%eccube_admin_route%/login/email-confirm", name="ps_staff_email_confirm", defaults={"mode"="verify"}, methods={"GET","POST"})
     * @Route("/%eccube_admin_route%/login/security/email", name="ps_staff_email_manage", defaults={"mode"="manage"}, methods={"GET","POST"}) */
    public function index(Request $r,string $mode): Response
    {
        if (!$this->config->shopEditionActive()) throw $this->createNotFoundException();
        $status=200;$message='';$address=null;$addresses=[];$success=false;$canView=false;$canEdit=false;$initialAddress=null;$initialRevision='';$loginHint='';$initialSigned=false;$resumeRequest=$r->query->get('resume')==='1'||$r->request->get('request_kind')==='resume';
        try {
            if (!$r->isSecure() || $r->getSchemeAndHttpHost()!==$this->config->origin()) throw new \RuntimeException('staff_mail_https_required');
            $actor=$this->getUser();
            $initialSigned=$actor instanceof Member&&$actor->getWork()?->getId()===Work::ACTIVE;
            if($mode==='initial_request'&&$initialSigned){
                $loginHint=(string)$actor->getLoginId();
                // A request is not an enrollment grant. Keep the email-unavailable path reachable.
            }
            if($mode==='initial_request'&&!$initialSigned){
                $hint=$r->getSession()->get('ps_staff_initial_hint');
                if(is_array($hint)&&is_string($hint['login']??null)&&($hint['at']??0)>=time()-1800&&($hint['at']??PHP_INT_MAX)<=time())$loginHint=$hint['login'];
            }
            if($mode==='initial_email'){
                if(!$initialSigned||!$this->security->initialEligible(Policy::subject($actor))
                    ||!$this->policy->initialPassword($r->getSession(),$actor,time()))throw new \RuntimeException('staff_initial_password_required');
                $subject=Policy::subject($actor);
                if($this->mail->initialEmailVerified($subject))return new RedirectResponse($this->generateUrl('ps_member'),303,['Cache-Control'=>'no-store, private']);
                $message='メールの確認はまだ完了していません。確認メールのリンクを開いて確認ボタンを押してから、この画面へ戻って次へ進んでください。';
                $initialAddress=$this->mail->initialEmailAddress($subject);$initialRevision=$this->mail->stateDigest($subject);
            }
            if ($mode==='manage') {
                $u=$this->getUser();
                if (!$u instanceof Member || $u->getWork()?->getId()!==Work::ACTIVE) throw new \RuntimeException('staff_mail_staff_required');
                if(!$this->policy->complete($r->getSession(),$u,time()))throw new \RuntimeException('staff_mail_staff_required');
                $canView=true;
                try{$this->policy->staffProof($r->getSession(),$u,time());$canEdit=true;}catch(\RuntimeException){}
                if(!$canEdit && in_array($r->getMethod(),['GET','HEAD'],true))
                    return new RedirectResponse($this->generateUrl('ps_member',['staff_mail_self'=>1]),303,['Cache-Control'=>'no-store, private','Referrer-Policy'=>'same-origin']);
                $address=$this->mail->displayAddress(Policy::subject($u));
                $addresses=$this->mail->addresses(Policy::subject($u));
            }
            if ($r->isMethod('POST')) {
                if ($r->headers->get('Origin')!==$this->config->origin() || strlen((string)$r->getContent())>8192
                    || !$this->isCsrfTokenValid('ps_staff_mail_'.$mode,$r->request->get('_token'))) throw new \RuntimeException('staff_mail_request_rejected');
                if($mode==='manage'&&!$canEdit)
                    return new RedirectResponse($this->generateUrl('ps_member',['staff_mail_self'=>1]),303,['Cache-Control'=>'no-store, private','Referrer-Policy'=>'same-origin']);
                $this->security->limit('staff-mail-ip:'.$r->getClientIp(),time(),20);
                if ($mode==='request') {
                    // Identical response and deferred lookup for known, unknown, inactive and unverified mailboxes.
                    try {
                        $target=StaffMailStore::address((string)$r->request->get('email',''));
                        $this->security->limit('staff-mail-address:'.$target,time(),3);
                        $this->job($r,$this->mail->queue('request',['address'=>$target],time()));
                    } catch (\RuntimeException $e) {}
                    $message='確認済みのメールアドレスが登録されている場合、再設定のご案内をお送りします。未登録・受信できない場合は管理担当者へご連絡ください。';$success=true;
                } elseif ($mode==='initial_email') {
                    $this->security->limit('staff-initial-email:'.$subject,time(),2);
                    $id=$this->mail->initialEmailVerification($subject,(string)$r->request->get('revision',''),time());
                    $this->job($r,$id);$initialRevision=$this->mail->stateDigest($subject);
                    $message='確認メールを予約しました。届いたメールのリンクで確認し、この画面に戻って「確認を済ませたので次へ」を押してください。';$success=true;
                } elseif ($mode==='initial_request') {
                    // Defer account lookup until after the response. Never disclose account/admin existence.
                    try{
                        $login=trim((string)$r->request->get('login_id',''));
                        if($login===''||mb_strlen($login)>50||strlen($login)>200||preg_match('/[\x00-\x20\x7f]/u',$login)!==0)throw new \RuntimeException('staff_request_input');
                        $loginHint=$login;
                        $r->getSession()->set('ps_staff_initial_hint',['login'=>$login,'at'=>time()]);
                        $this->security->limit('staff-initial-global',time(),30);
                        $this->security->limit('staff-initial-ip:'.$r->getClientIp(),time(),3);
                        $this->security->limit('staff-initial-login:'.$login,time(),1);
                        $this->job($r,$this->mail->queue('enrollrequest',['login_id'=>$login,'requested_at'=>time(),'request_kind'=>$resumeRequest?'resume':'initial'],time()));

                        if($initialSigned&&hash_equals((string)$actor->getLoginId(),$login))
                            $r->getSession()->set('ps_staff_initial_requested',['at'=>time(),'stamp'=>$this->policy->stamp($actor)]);

                    }catch(\RuntimeException){}
                    $message='依頼を受け付けました。登録状況を確認し、必要な場合にシステム管理者へ通知します。管理者による本人確認と登録リンク・コードの発行をお待ちください。';$success=true;
                } elseif ($mode==='manage') {
                    $this->policy->staffProof($r->getSession(),$u,time());
                    $this->security->limit('staff-mail-manage:'.Policy::subject($u),time(),3);
                    $slot=StaffMailStore::slot((string)$r->request->get('slot','primary'));
                    $action=(string)$r->request->get('action','verify');
                    if ($action==='revoke') {
                        foreach($this->mail->revoke(Policy::subject($u),$slot,time()) as $job) $this->job($r,$job);
                        $message='指定したメールアドレスの登録を解除しました。';
                    } elseif ($action==='verify') {
                        $this->job($r,$this->mail->verification(Policy::subject($u),(string)$r->request->get('email',''),time(),$slot));
                        $message='確認メールを予約しました。リンク先で確認が完了するまで再設定には利用できません。';
                    } else { throw new \RuntimeException('staff_mail_action_invalid'); }
                    $success=true;
                } elseif ($mode==='verify') {
                    foreach ($this->mail->confirm((string)$r->request->get('token',''),time()) as $id) $this->job($r,$id);
                    $message='メールアドレスを確認しました。初回登録やアカウント設定を続けてください。';$success=true;
                } else {
                    $password=(string)$r->request->get('password','');
                    if (!hash_equals($password,(string)$r->request->get('repeat',''))) throw new \RuntimeException('staff_mail_password_mismatch');
                    $member=function(string $subject):Member {
                        $u=$this->em->find(Member::class,(int)substr($subject,7));
                        if (!$u) throw new \RuntimeException('staff_mail_rejected'); return $u;
                    };
                    $notice=$this->mail->reset((string)$r->request->get('token',''),$password,time(),
                        fn($s,$p)=>$this->hasher->isPasswordValid($member($s),$p),fn($s,$p)=>$this->hasher->hashPassword($member($s),$p));
                    $this->job($r,$notice);
                    $this->em->clear();
                    $r->getSession()->invalidate(); // No auto-login. Password-bound proofs and native old sessions expire.
                    $message='パスワードを変更しました。ログイン画面から入り直してください。パスキー、または新しいパスワードと認証アプリの確認が必要です。';$success=true;
                }
            }
        } catch (\Throwable $e) {
            $status=403;$message=match($e->getMessage()){
                'staff_mail_password_invalid','staff_mail_password_unchanged'=>PasswordRules::MESSAGE,
                'staff_mail_password_mismatch'=>'確認欄にも同じパスワードを入力してください。',
                'staff_initial_password_required'=>'ID・パスワードによるログイン確認の期限が切れました。ログインし直すか、メールが使えない場合は管理者へコードを依頼してください。パスワード再発行は不要です。',
                default=>'手続きを完了できません。有効期限・入力内容・追加認証をご確認ください。解決しない場合は管理担当者へご連絡ください。'};
        }
        if($mode==='manage'&&$canView){try{$addresses=$this->mail->addresses(Policy::subject($u));$address=$this->mail->displayAddress(Policy::subject($u));}catch(\Throwable){$canView=false;$canEdit=false;$status=403;$message='登録内容を取得できません。未登録とは限りません。管理担当者へご連絡ください。';}}
        $nonce=Ceremony::encode(random_bytes(24));
        $response=$this->render('@PasskeySecurity/staff_mail.twig',['mode'=>$mode,'message'=>$message,'success'=>$success,'address'=>$address,'addresses'=>$addresses,'nonce'=>$nonce,'can_view'=>$canView,'can_edit'=>$canEdit,'initial_address'=>$initialAddress,'initial_revision'=>$initialRevision,'login_hint'=>$loginHint,'initial_signed'=>$initialSigned,'resume_request'=>$resumeRequest,'verification_initial'=>$r->query->get('registration')==='1'||$r->request->get('registration')==='1','verification_account'=>$initialSigned&&$this->policy->complete($r->getSession(),$actor,time())]);
        $response->setStatusCode($status);
        foreach (['Cache-Control'=>'no-store, private','Pragma'=>'no-cache','Referrer-Policy'=>'same-origin','X-Content-Type-Options'=>'nosniff','X-Frame-Options'=>'DENY',
            'Content-Security-Policy'=>"default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"] as $k=>$v) $response->headers->set($k,$v);
        return $response;
    }
    private function job(Request $r,string $id): void
    {
        $r->attributes->set('_ps_staff_mail_jobs',[...$r->attributes->get('_ps_staff_mail_jobs',[]),$id]);
    }
}
