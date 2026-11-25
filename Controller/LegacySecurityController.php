<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Controller;

use Eccube\Controller\AbstractController;
use Eccube\Entity\Customer;
use Eccube\Entity\Member;
use Eccube\Entity\Master\CustomerStatus;
use Eccube\Entity\Master\Work;
use Doctrine\ORM\EntityManagerInterface;
use Plugin\PasskeySecurity\Resource\Runtime\{Config, Store, Policy, SettingsContinuation, Ceremony, StaffMailStore, PasswordRules};
use Symfony\Component\HttpFoundation\{Request, Response, JsonResponse};
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Http\Authentication\UserAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;

final class LegacySecurityController extends AbstractController
{
    public function __construct(private Config $config, private Store $store, private Policy $policy,
        private Ceremony $ceremony, private EntityManagerInterface $em, private UserPasswordHasherInterface $hasher,
        private UserAuthenticatorInterface $userAuthenticator, private AuthenticatorInterface $customerAuthenticator,
        private AuthenticatorInterface $memberAuthenticator, private StaffMailStore $mail) {}

    public function index(Request $r, string $kind): Response
    {
        if (!$this->config->shopEditionActive()) throw $this->createNotFoundException();
        $headers = ['Cache-Control'=>'no-store, private', 'Pragma'=>'no-cache', 'Referrer-Policy'=>'no-referrer',
            'X-Content-Type-Options'=>'nosniff', 'X-Frame-Options'=>'DENY'];
        try {
            if (!$r->isSecure() || $r->getSchemeAndHttpHost() !== $this->config->origin()) throw new \RuntimeException('security_https_required');
            if ($r->isMethod('GET')) {
                $u = $this->getUser();
                $same = ($kind === 'member' && $u instanceof Member) || ($kind === 'customer' && $u instanceof Customer);
                if($kind==='member'&&$u instanceof Member&&$u->getWork()?->getId()===1&&$u->getAuthority()?->getId()===0){
                    $return=(string)$r->query->get('staff_mail_return','');
                    if(preg_match('/^[1-9][0-9]{0,8}$/D',$return))$r->getSession()->set('ps_staff_mail_return',
                        ['id'=>(int)$return,'subject'=>Policy::subject($u),'stamp'=>$this->policy->stamp($u),'at'=>time()]);
                }
                if($kind==='member'&&$u instanceof Member&&$u->getWork()?->getId()===1
                    &&$r->query->get('staff_mail_self')==='1')
                    $r->getSession()->set('ps_staff_mail_return',['id'=>0,'subject'=>Policy::subject($u),'stamp'=>$this->policy->stamp($u),'at'=>time()]);
                $nonce = Ceremony::encode(random_bytes(24));
                $subject=$same?Policy::subject($u):null;
                $inventory=$subject!==null?$this->store->inventory($subject):[];
                $active=$subject!==null?count($this->store->credentials($subject)):0;
                $canRevoke=false;
                if($same){
                    if($u instanceof Customer)$canRevoke=$this->policy->fresh($r->getSession(),$u,'reauth',time(),300);
                    else try{$this->policy->staffProof($r->getSession(),$u,time());$canRevoke=true;}catch(\RuntimeException $e){}
                }
                $hasTotp=$subject!==null && (int)($this->store->factor($subject)['confirmed']??0)===1;
                $complete=$same && $this->policy->complete($r->getSession(),$u,time());
                $enrollmentReady=$same&&$u instanceof Member&&$this->policy->fresh($r->getSession(),$u,'enroll',time(),600);
                $initial=$same&&$u instanceof Member&&!$complete&&$active===0&&!$hasTotp;
                $initialFactor=$initial?$this->store->factor($subject):null;
                $registrationInterrupted=$initial&&!$enrollmentReady&&$initialFactor&&$initialFactor['ticket']===''&&(int)$initialFactor['expires']>0;
                if($initial&&!$enrollmentReady&&!$registrationInterrupted&&$this->store->initialEligible($subject)){
                    if(!$this->policy->initialPassword($r->getSession(),$u,time())){
                        $response=new \Symfony\Component\HttpFoundation\RedirectResponse($this->generateUrl('admin_login'),303);
                        foreach($headers as$k=>$v)$response->headers->set($k,$v);return $response;
                    }
                    if(!$this->mail->initialEmailVerified($subject)&&!$this->store->manualInitialAllowed($subject)){
                        $response=new \Symfony\Component\HttpFoundation\RedirectResponse($this->generateUrl('ps_staff_initial_email'),303);
                        foreach($headers as$k=>$v)$response->headers->set($k,$v);return $response;
                    }
                    $requested=$r->getSession()->get('ps_staff_initial_requested');
                    $requested=is_array($requested)&&($requested['at']??0)>=time()-1800&&($requested['at']??PHP_INT_MAX)<=time()
                        &&hash_equals($this->policy->stamp($u),(string)($requested['stamp']??''));
                    $factor=$this->store->factor($subject);
                    $issued=$factor&&$factor['ticket']!=='';
                    if($r->query->get('setup')!=='code'&&!$requested&&!$issued){
                        $response=new \Symfony\Component\HttpFoundation\RedirectResponse($this->generateUrl('ps_staff_initial_request'),303);
                        foreach($headers as$k=>$v)$response->headers->set($k,$v);return $response;
                    }
                }
                $pendingSettings = $u instanceof Member ? SettingsContinuation::pending($r, $u, $this->policy) : null;
                $settingsReturn = $pendingSettings !== null;
                $passkeyRequired = $kind === 'member' && $this->config->staffPasskeyRequired();
                $settingsPasskey = $settingsReturn && ($passkeyRequired || ($pendingSettings['settings']['passkey_required'] ?? false));
                $staffReturn=($settingsReturn && (!$passkeyRequired || $active > 0 || !$complete))
                    ||($u instanceof Member&&$this->staffReturnId($r,$u)!==null);
                $r->attributes->set('_ps_security_login',!$same || (!$complete&&!$enrollmentReady));
                $primary=!$same?'login-passkey':($staffReturn?($active>0?'verify':'totp-verify'):
                    ($u instanceof Customer||$complete?'register':($active>0?'verify':($hasTotp?'totp-verify':
                    ($enrollmentReady?($this->store->resetRequired($subject)?'change-password':'register'):'claim')))));
                $r->attributes->set('_ps_security_primary',$primary);
                $r->attributes->set('_ps_security_read_only',$registrationInterrupted&&!$enrollmentReady&&$this->store->initialEligible($subject));
                $response = $this->render('@PasskeySecurity/security.twig', ['kind'=>$kind, 'signed_in'=>$same,
                    'staff_initial'=>$initial,'initial_retry_required'=>$registrationInterrupted&&$this->store->initialEligible($subject),'enrollment_expires'=>$enrollmentReady?(int)$r->getSession()->get('ps_enroll')['at']+600:0,'initial_resume_required'=>$initial&&!$enrollmentReady&&!$this->store->initialEligible($subject),'staff_password_recent'=>$same&&$u instanceof Member&&$this->policy->fresh($r->getSession(),$u,'password',time(),1800),'reset_required'=>$same && $u instanceof Member && $this->store->resetRequired($subject),
                    'nonce'=>$nonce, 'complete'=>$same && $this->policy->complete($r->getSession(), $u, time()),
                    'staff_return'=>$staffReturn, 'settings_return'=>$settingsReturn,
                    'staff_passkey_required'=>$passkeyRequired, 'settings_passkey'=>$settingsPasskey,
                    'totp_password_required'=>$same&&$u instanceof Member&&!$this->policy->fresh($r->getSession(),$u,'password',time(),$staffReturn?300:1800),
                    'enrollment_ready'=>$same&&$u instanceof Member&&$this->policy->fresh($r->getSession(),$u,'enroll',time(),600),
                    'endpoint'=>$r->getPathInfo(), 'login_url'=>$this->generateUrl($kind === 'member'?'admin_login':'mypage_login'),
                    'home_url'=>$this->generateUrl($kind === 'member'?'admin_homepage':'mypage'),
                    'initial_code_expired'=>$same&&$u instanceof Member&&($this->store->factor($subject)['ticket']??'')!==''&&(int)($this->store->factor($subject)['expires']??0)<time(),'initial_code_expires'=>$same&&$u instanceof Member?(int)($this->store->factor($subject)['expires']??0):0,
                    'csrf_id'=>'passkey_security_'.$kind,'credentials'=>$inventory,'active_count'=>$active,'can_revoke'=>$canRevoke,'has_totp'=>$hasTotp]);
                $response->headers->set('Content-Security-Policy', "default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
            } else {
                if ($r->headers->get('Origin') !== $this->config->origin() || strlen((string)$r->getContent()) > 100000) throw new \RuntimeException('security_request_rejected');
                $input = json_decode((string)$r->getContent(), true, 16, JSON_THROW_ON_ERROR);
                if (!is_array($input) || !$this->isCsrfTokenValid('passkey_security_'.$kind, $input['_token'] ?? null)) throw new \RuntimeException('security_csrf_rejected');
                $this->store->limit('ip:'.(string)$r->getClientIp(), time(), 60);
                $response = new JsonResponse($this->action($r, $kind, $input));
            }
        } catch (\Throwable $e) {
            // Never expose exception text, usernames, codes, credentials, provisioning URIs or passwords.
            $response = $r->isMethod('POST') ? new JsonResponse(['ok'=>false, 'error'=>match($e->getMessage()){'security_new_password_rejected'=>PasswordRules::MESSAGE,'security_initial_password_expired'=>'ログイン確認の有効期限（30分）が切れました。ID・パスワードでログインし直してから、有効期限内の同じコードを入力してください。パスワードの再発行は不要です。','security_initial_email_required'=>'先に登録メールアドレスの確認を完了してください。確認後、有効期限内のコードで登録を続けられます。','security_totp_registration_proof_expired'=>'登録操作の本人確認期限が切れました。画面を開き直し、表示される再開手順に従ってください。パスワードの再発行では再開できません。','security_ticket_expired'=>'このコードの有効期限が切れました（発行から1時間）。新しい登録リンク・コードを管理者へ依頼してください。パスワードの再発行は不要です。','security_ticket_rejected','security_ticket_already_claimed'=>'コードを確認できません。最新のコードを使ってください。期限切れ・使用済みの場合は、コードの依頼・登録再開のリンクから管理者へご相談ください。','security_totp_rejected','security_totp_replay'=>'6桁のコードを確認できません。アプリの数字が新しく切り替わってから入力してください。スマートフォンの日時を自動設定にしてください。','security_totp_missing'=>'先に「登録用QRコードを表示」を押し、認証アプリでQRコードを読み取ってください。','security_reauth_rejected'=>'現在のパスワードを確認してください。パスワードの再発行は、この操作では行いません。','security_rate_limited'=>'確認回数が多いため、一時的に制限しています。5分ほど待ってからお試しください。','security_recent_proof_required','security_staff_authentication_required','security_initial_enrollment_required'=>(($input['action']??'')==='verify_totp'?'本人確認の期限が切れました。画面を再読み込みし、現在のパスワードとアプリの新しい6桁コードを入力してください。パスワードの再発行は不要です。':'登録の確認期限が切れた可能性があります。画面を再読み込みし、表示される再開手順に従ってください。パスワードの再発行は不要です。'),default=>'認証を完了できません。入力内容をご確認いただくか、管理担当者へご連絡ください。'}, ...($kind==='member'&&in_array($e->getMessage(),['security_initial_password_expired','security_initial_email_required','security_ticket_expired','security_ticket_rejected','security_ticket_already_claimed','security_totp_registration_proof_expired'],true)?['continue_url'=>$this->generateUrl(match($e->getMessage()){'security_initial_password_expired'=>'admin_login','security_initial_email_required'=>'ps_staff_initial_email',default=>$this->registrationHelp()['route']},in_array($e->getMessage(),['security_initial_password_expired','security_initial_email_required'],true)?[]:$this->registrationHelp()['parameters']),'continue_label'=>match($e->getMessage()){'security_initial_password_expired'=>'ID・パスワードでログインし直す','security_initial_email_required'=>'登録メールアドレスを確認する',default=>$this->registrationHelp()['label']}]:[])], 403)
                : new Response('HTTPSの認証用URLからアクセスしてください。', 403);
        }
        foreach ($headers as $k=>$v) $response->headers->set($k, $v);
        return $response;
    }
    private function registrationHelp():array
    {
        try{
            $u=$this->getUser();
            if($u instanceof Member){
                $s=Policy::subject($u);$f=$this->store->factor($s);
                if((int)($f['confirmed']??0)===1||count($this->store->credentials($s))>0)return ['route'=>'ps_member','parameters'=>[],'label'=>'認証設定へ戻って本人確認する'];
                if(!$this->store->initialEligible($s))return ['route'=>'ps_staff_initial_request','parameters'=>['resume'=>'1'],'label'=>'管理者へ登録の再開を依頼する'];
            }
        }catch(\Throwable){}
        return ['route'=>'ps_staff_initial_request','parameters'=>[],'label'=>'新しい登録リンク・コードを依頼する'];
    }
    private function user(string $kind): object
    {
        $u = $this->getUser();
        if (!(($kind === 'member' && $u instanceof Member) || ($kind === 'customer' && $u instanceof Customer))) throw new \RuntimeException('security_login_required');
        if ($u instanceof Customer && $this->store->resetRequired(Policy::subject($u))) throw new \RuntimeException('security_reset_required');
        return $u;
    }
    private function allowedEnrollment(Request $r, object $u): int
    {
        $s = $r->getSession(); $now = time();
        if ($u instanceof Member) {
            if(!$this->policy->fresh($s,$u,'enroll',$now,600)&&$this->store->initialEligible(Policy::subject($u))&&!$this->mail->initialEmailVerified(Policy::subject($u)))throw new \RuntimeException('security_initial_email_required');
            if ($this->store->resetRequired(Policy::subject($u))) throw new \RuntimeException('security_staff_password_change_first');
            if (!$this->policy->fresh($s,$u,'enroll',$now,600)) $this->policy->staffProof($s,$u,$now);
        } elseif (!$this->policy->fresh($s, $u, 'reauth', $now, 300)) throw new \RuntimeException('security_recent_password_required');
        $name=$u instanceof Member?($this->policy->fresh($s,$u,'enroll',$now,600)?'enroll':$this->policy->staffProof($s,$u,$now)):'reauth';
        return $this->policy->proofGeneration($s,$u,$name,$now,$name==='enroll'?600:300);
    }
    private function action(Request $r, string $kind, array $i): array
    {
        $s = $r->getSession(); $now = time(); $a = $i['action'] ?? '';
        if ($a === 'login_options') {
            $options=$this->ceremony->options($s,$kind,'assert',null,$now);
            $flow=\Plugin\PasskeySecurity\Resource\Turnstile\RegistrationFlow::issue($s,$r->getPathInfo(),(string)$i['_token'],$now,'login_verify');
            return ['ok'=>true,'options'=>$options,'turnstile_flow'=>$flow];
        }
        if ($a === 'login_verify') {
            $verified = $this->ceremony->assertion($s, $kind, null, $i, $now);$subject=$verified['subject'];
            $u = $this->em->find($kind === 'member'?Member::class:Customer::class, (int)explode(':', $subject)[1]);
            if (!$u || ($u instanceof Member && $u->getWork()->getId() !== Work::ACTIVE)
                || ($u instanceof Customer && ($u->getStatus()->getId() !== CustomerStatus::REGULAR || $this->store->resetRequired($subject)))) {
                throw new \RuntimeException('security_account_unavailable');
            }
            $this->userAuthenticator->authenticateUser($u, $kind === 'member'?$this->memberAuthenticator:$this->customerAuthenticator, $r);
            $this->policy->prove($s, $u, 'passkey', $now,$verified['generation']);
            if ($u instanceof Customer) $this->policy->prove($s,$u,'session',$now,$verified['generation']);
            if($u instanceof Member)$this->completeStaff($r,$u,$now,$verified['generation']);
            return ['ok'=>true, 'redirect'=>$u instanceof Member?$this->staffDestination($r,$u):$this->generateUrl('mypage')];
        }
        $u = $this->user($kind); $subject = Policy::subject($u);
        $group=match($a){'reauth','change_password'=>'password','verify_totp'=>'totp','claim_ticket'=>'ticket',default=>'credential'};
        $this->store->limit('account:'.$subject.':'.$this->store->generation($subject).':'.$group, $now);
        if ($a === 'reauth') {
            $generation=$this->store->generation($subject);
            if (!$this->hasher->isPasswordValid($u, (string)($i['password'] ?? ''))) throw new \RuntimeException('security_reauth_rejected');
            if($u instanceof Member){$this->policy->prove($s,$u,'password',$now,$generation);$this->policy->proveInitialPassword($s,$u,$now);}
            else{
                $this->policy->prove($s, $u, 'reauth', $now,$generation);
                $this->policy->prove($s,$u,'session',$now,$generation);
            }
            return ['ok'=>true,'redirect'=>$r->getPathInfo()];
        }
        if ($a === 'claim_ticket' && $u instanceof Member) {
            $f=$this->store->factor($subject);
            if($f&&$f['ticket']!==''&&(int)$f['expires']<$now&&hash_equals($f['ticket'],$this->config->digest(trim((string)($i['ticket']??'')))))throw new \RuntimeException('security_ticket_expired');
            $initialPassword=$this->policy->initialPassword($s,$u,$now);
            if($this->store->initialEligible($subject)){
                if(!$this->policy->initialPassword($s,$u,$now))throw new \RuntimeException('security_initial_password_expired');
                if(!$this->mail->initialEmailVerified($subject)&&!$this->store->manualInitialAllowed($subject))throw new \RuntimeException('security_initial_email_required');
            }
            $generation=$this->store->claimTicket($subject, (string)($i['ticket'] ?? ''), $now);
            $this->policy->prove($s, $u, 'enroll', $now,$generation);
            if($initialPassword)$this->policy->prove($s,$u,'password',$now,$generation);
            return ['ok'=>true,'redirect'=>$r->getPathInfo().'?enrollment='.bin2hex(random_bytes(4)).'#'.($this->store->resetRequired($subject)?'initial-password':'passkey-section')];
        }
        if ($a === 'change_password' && $u instanceof Member) {
            if (!$this->store->resetRequired($subject) || !$this->policy->fresh($s, $u, 'enroll', $now, 600)) {
                throw new \RuntimeException('security_initial_enrollment_required');
            }
            $new = $i['new_password'] ?? null;
            $expectedGeneration=$this->policy->proofGeneration($s,$u,'enroll',$now,600);
            if (!is_string($new) || !$this->mail->passwordAllowed($subject,$new)
                || !$this->hasher->isPasswordValid($u, (string)($i['password'] ?? '')) || $this->hasher->isPasswordValid($u, $new)) {
                throw new \RuntimeException('security_new_password_rejected');
            }
            $generation=$this->em->wrapInTransaction(function () use ($u, $new, $subject,$expectedGeneration): int {
                $u->setPassword($this->hasher->hashPassword($u, $new)); $u->setSalt(null); $this->em->flush();
                return $this->store->passwordReset($subject, $u->getPassword(),$expectedGeneration);
            });
            Policy::clear($s); $s->migrate(true); $this->policy->prove($s, $u, 'enroll', $now,$generation);
            $this->policy->prove($s,$u,'password',$now,$generation);
            return ['ok'=>true,'redirect'=>$r->getPathInfo().'?enrollment='.bin2hex(random_bytes(4)).'#passkey-section'];
        }
        if ($a === 'register_options') {
            if ($u instanceof Customer && array_key_exists('password', $i)) {
                $this->store->limit('account:'.$subject.':'.$this->store->generation($subject).':password', $now);
                if (!is_string($i['password']) || !$this->hasher->isPasswordValid($u, $i['password'])) throw new \RuntimeException('security_reauth_rejected');
                $generation=$this->store->generation($subject);
                $this->policy->prove($s,$u,'reauth',$now,$generation);
                $this->policy->prove($s,$u,'session',$now,$generation);
            }
            $this->allowedEnrollment($r, $u);
            $options=$this->ceremony->options($s, $kind, 'register', $subject, $now);
            $flow=\Plugin\PasskeySecurity\Resource\Turnstile\RegistrationFlow::issue($s,$r->getPathInfo(),(string)$i['_token'],$now);
            return ['ok'=>true, 'options'=>$options, 'turnstile_flow'=>$flow];
        }
        if ($a === 'register_verify') {
            $this->allowedEnrollment($r, $u); $generation=$this->ceremony->register($s, $kind, $subject, $i, $now);
            $this->policy->prove($s, $u, 'passkey', $now,$generation);
            if($u instanceof Member){
                $this->completeStaff($r,$u,$now,$generation);
                if (SettingsContinuation::pending($r, $u, $this->policy) !== null) {
                    return ['ok'=>true, 'redirect'=>$this->staffDestination($r,$u)];
                }
            }
            return ['ok'=>true,'redirect'=>$r->getPathInfo()];
        }
        if ($a === 'verify_options' && $u instanceof Member) {
            $options=$this->ceremony->options($s,$kind,'assert',$subject,$now);
            $flow=\Plugin\PasskeySecurity\Resource\Turnstile\RegistrationFlow::issue($s,$r->getPathInfo(),(string)$i['_token'],$now,'verify_passkey');
            return ['ok'=>true,'options'=>$options,'turnstile_flow'=>$flow];
        }
        if ($a === 'verify_passkey' && $u instanceof Member) {
            $verified=$this->ceremony->assertion($s, $kind, $subject, $i, $now);
            $this->policy->prove($s, $u, 'passkey', $now,$verified['generation']);
            $this->completeStaff($r,$u,$now,$verified['generation']);
            return ['ok'=>true,'redirect'=>$this->staffDestination($r,$u)];
        }
        if ($a === 'totp_setup' && $u instanceof Member) {
            $grant=$this->allowedEnrollment($r, $u); Config::dependencies();
            $f = $this->store->factor($subject);
            if (!$f || (int)$f['generation']!==$grant || (int)$f['confirmed'] === 1) throw new \RuntimeException('security_totp_already_enrolled');
            if ($f['secret'] === '') { $otp = \OTPHP\TOTP::create(); $this->store->setPendingTotp($subject, $otp->getSecret(),(int)$f['generation']); }
            else $otp = \OTPHP\TOTP::createFromSecret($this->store->totpSecret($f));
            $otp->setLabel('staff-'.substr($this->config->digest($subject),0,12)); $otp->setIssuer($this->config->data()['rp_name']);
            $uri = $otp->getProvisioningUri();
            return ['ok'=>true, 'provisioning_uri'=>$uri, 'secret'=>$otp->getSecret(), 'qr_data_uri'=>\Plugin\PasskeySecurity\Resource\Runtime\TotpQr::dataUri($uri)];
        }
        if ($a === 'verify_totp' && $u instanceof Member) {
            // Pending enrollment must retain its registration proof through final confirmation.
            $pending=$this->store->factor($subject);
            if($pending&&(int)$pending['confirmed']!==1){
                try{$this->allowedEnrollment($r,$u);}catch(\RuntimeException $e){throw new \RuntimeException('security_totp_registration_proof_expired');}
            }
            // TOTP is an alternative second factor after a verified password, never a stand-alone login.
            if($this->store->resetRequired($subject))throw new \RuntimeException('security_password_change_required');
            if(isset($i['password'])&&is_string($i['password'])&&$i['password']!==''){
                if(!$this->hasher->isPasswordValid($u,$i['password']))throw new \RuntimeException('security_reauth_rejected');
                $this->policy->prove($s,$u,'password',$now,$this->store->generation($subject));
            }
            $generation=$this->policy->proofGeneration($s,$u,'password',$now,($this->staffReturnId($r,$u)!==null||SettingsContinuation::pending($r,$u,$this->policy)!==null)?300:1800);
            $verified=$this->store->consumeTotp($subject, (string)($i['code'] ?? ''), $now,$generation);
            $this->policy->prove($s, $u, 'totp', $now,$verified);
            $this->completeStaff($r,$u,$now,$verified);$s->migrate(true);
            return ['ok'=>true, 'redirect'=>$this->staffDestination($r,$u)];
        }
        if ($a === 'revoke') {
            $name=$u instanceof Member?$this->policy->staffProof($s,$u,$now):'reauth';
            $generation=$this->policy->proofGeneration($s,$u,$name,$now);
            $this->store->revokeOwn($subject,(string)($i['credential_id']??''),$generation,$now);
            Policy::clear($s);$s->migrate(true);
            return ['ok'=>true,'redirect'=>$this->generateUrl($u instanceof Member?'ps_member':'mypage_login')];
        }
        throw new \RuntimeException('security_action_rejected');
    }
    private function completeStaff(Request $r, object $u, int $now, int $generation): void
    {
        if(!$this->policy->complete($r->getSession(),$u,$now))throw new \RuntimeException('security_staff_authentication_required');
        $this->store->finishRecovery(Policy::subject($u),$generation,$now);
        if($this->policy->fresh($r->getSession(),$u,'enroll',$now,600))$this->store->audit(Policy::subject($u),'staff_enrollment_completed');
        $r->getSession()->remove('ps_enroll');
    }
    private function staffReturnId(Request $r,Member $u): ?int
    {
        $p=$r->getSession()->get('ps_staff_mail_return');$now=time();
        if(!is_array($p)||$u->getWork()?->getId()!==1||(($p['id']??null)!==0&&$u->getAuthority()?->getId()!==0)
            ||($p['subject']??null)!==Policy::subject($u)||!is_int($p['id']??null)||$p['id']<0
            ||($p['at']??0)<$now-600||($p['at']??PHP_INT_MAX)>$now
            ||!hash_equals($this->policy->stamp($u),(string)($p['stamp']??'')))return null;
        return $p['id'];
    }
    private function staffDestination(Request $r,Member $u): string
    {
        $pending = SettingsContinuation::pending($r, $u, $this->policy);
        $passkeyRequired = $this->config->staffPasskeyRequired();
        if (($passkeyRequired && !$this->policy->staffAccess($r->getSession(), $u, time()))
            || ($pending !== null && ($passkeyRequired || ($pending['settings']['passkey_required'] ?? false))
                && !$this->policy->fresh($r->getSession(), $u, 'passkey', time(), 300))) {
            return $this->generateUrl('ps_member');
        }
        if ($pending !== null) {
            return $this->generateUrl(SettingsContinuation::ROUTE, ['resume' => '1']);
        }
        $id=$this->staffReturnId($r,$u);$r->getSession()->remove('ps_staff_mail_return');
        return $id===null?$this->generateUrl('admin_homepage'):($id===0?$this->generateUrl('ps_staff_email_manage'):$this->generateUrl('admin_ps_staff_mail',['id'=>$id]));
    }
}
