<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Controller;
use Eccube\Controller\AbstractController;
use Eccube\Entity\Member;
use Eccube\Entity\Master\Work;
use Doctrine\ORM\EntityManagerInterface;
use Plugin\PasskeySecurity\Resource\Runtime\{Config,Store,Policy,Ceremony,StaffMailStore,StaffMailAdminAccess};
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\Routing\Annotation\Route;
final class StaffMailAdminController extends AbstractController
{
    public function __construct(private Config $config,private Store $security,private StaffMailStore $mail,
        private StaffMailAdminAccess $access,private EntityManagerInterface $em){}
    /** @Route("/%eccube_admin_route%/setting/system/member/{id}/mail", name="admin_ps_staff_mail", requirements={"id"="[1-9][0-9]*"}, methods={"GET","POST"}) */
    public function index(Request $r,int $id):Response
    {
        if (!$this->config->shopEditionActive()) throw $this->createNotFoundException();
        $actor=$this->getUser();
        if(!$r->isSecure()||$r->getSchemeAndHttpHost()!==$this->config->origin()||!$this->access->view($actor,$r))throw $this->createAccessDeniedException();
        $member=$this->em->find(Member::class,$id);if(!$member)throw $this->createNotFoundException();
        // Reauthenticate automatically before opening editable staff settings. Never replay a POST.
        if(in_array($r->getMethod(),['GET','HEAD'],true) && $member->getWork()?->getId()===Work::ACTIVE
            && !$this->access->edit($actor,$r)) {
            $response=$this->redirectToRoute('ps_member',['staff_mail_return'=>$id],303);
            $response->headers->set('Cache-Control','no-store, private');
            $response->headers->set('Referrer-Policy','same-origin');
            return $response;
        }
        $subject=Policy::subject($member);$status=200;$message='';$ticket=null;
        if($r->isMethod('POST')){
            try{
                if($member->getWork()?->getId()!==Work::ACTIVE
                    ||$r->headers->get('Origin')!==$this->config->origin()||strlen((string)$r->getContent())>8192
                    ||!$this->isCsrfTokenValid('ps_staff_mail_admin_'.$id,$r->request->get('_token'))
                    ||!hash_equals($this->mail->stateDigest($subject),(string)$r->request->get('revision','')))throw new \RuntimeException('staff_mail_admin_rejected');
                if(!$this->access->edit($actor,$r)){
                    $response=$this->redirectToRoute('ps_member',['staff_mail_return'=>$id]);
                    $response->headers->set('Cache-Control','no-store, private');
                    $response->headers->set('Referrer-Policy','same-origin');
                    return $response;
                }
                $this->security->limit('staff-mail-admin:'.Policy::subject($actor),time(),20);
                $action=(string)$r->request->get('action','');
                $this->mail->withState($subject,(string)$r->request->get('revision',''),function()use($r,$subject,$action,$actor,&$ticket,&$message):void{
                if($action==='initial'){
                    if(!hash_equals($this->initialRevision($subject),(string)$r->request->get('initial_revision','')))throw new \RuntimeException('staff_mail_initial_state_changed');
                    if($r->request->get('identity_checked')!=='1'||!$this->security->initialEligible($subject))throw new \RuntimeException('staff_mail_initial_rejected');
                    $delivery=(string)$r->request->get('initial_delivery','');
                    if(!in_array($delivery,['email','display'],true))throw new \RuntimeException('staff_mail_initial_delivery_required');
                    $addresses=$this->mail->addresses($subject);
                    if($delivery==='email'&&!$addresses['primary']['verified']&&!$addresses['backup']['verified'])throw new \RuntimeException('staff_mail_verified_address_required');
                    $this->security->limit('initial-issue:'.$subject,time(),3);
                    $ticket=$this->security->issueInitialTicket($subject,time());
                    if($delivery==='display')$this->security->allowManualInitial($subject,$ticket);
                    if($delivery==='email'){
                        $job=$this->mail->initialDelivery($subject,$ticket,time());
                        if($job===null)throw new \RuntimeException('staff_mail_verified_address_required');
                        $this->job($r,$job);$ticket=null;
                        $message='確認済みの本人メールアドレス宛てに初回登録リンクを予約しました。メールの「登録を始める」から進めます。最新のメールだけを使用してください。有効期限は発行から1時間です。';
                    }else $message='初回登録コードを画面に表示しました。メールは送っていません。本人確認した別の方法で渡してください。表示は今回のみ、有効期限は1時間です。';
                    $this->security->audit($subject,($delivery==='email'?'staff_mail_initial_link_by:':'staff_mail_initial_display_by:').$actor->getId());
                }else{
                    $slot=StaffMailStore::slot((string)$r->request->get('slot',''));
                    if($action==='stage'){$this->mail->stageEnrollment($subject,(string)$r->request->get('email',''),time(),$slot);$message='確認待ちアドレスを保存しました。メールは送信していません。';}
                    elseif($action==='verify'){$this->job($r,$this->mail->verification($subject,(string)$r->request->get('email',''),time(),$slot));$message='本人宛の確認メールを予約しました。本人がリンク先で確認するまで、変更前の確認済みアドレスを維持します。';}
                    elseif($action==='revoke'){foreach($this->mail->revoke($subject,$slot,time())as$job)$this->job($r,$job);$message='指定したアドレスを解除しました。解除したアドレスへ通知を予約します。';}
                    else throw new \RuntimeException('staff_mail_action_invalid');
                }
                $this->security->audit($subject,'staff_mail_admin_'.$action.'_by:'.$actor->getId());
                });
            }catch(\Throwable){$status=403;$message='変更できません。入力・重複登録・追加認証の有効期限をご確認ください。別の管理者が更新した場合は、画面を開き直してください。';}
        }
        // POST/Redirect/GET: refreshing the result page must never issue another code.
        $resultKey='ps_staff_initial_result_'.$id;
        if($r->isMethod('POST')&&$status===200&&$r->request->get('action')==='initial'){
            $factor=$this->security->factor($subject);
            $r->getSession()->set($resultKey,['actor'=>$actor->getId(),'at'=>time(),
                'stamp'=>$this->config->digest($actor->getPassword()),'generation'=>(int)($factor['generation']??0),
                'ticket'=>$ticket,'message'=>$message]);
            $response=$this->redirectToRoute('admin_ps_staff_mail',['id'=>$id],303);
            foreach(['Cache-Control'=>'no-store, private','Pragma'=>'no-cache','Referrer-Policy'=>'same-origin','X-Content-Type-Options'=>'nosniff','X-Frame-Options'=>'DENY']as$k=>$v)$response->headers->set($k,$v);
            return $response;
        }
        if($r->isMethod('GET')){
            $once=$r->getSession()->remove($resultKey);
            if(is_array($once)&&($once['actor']??null)===$actor->getId()
                &&($once['at']??0)>=time()-120&&($once['at']??PHP_INT_MAX)<=time()
                &&hash_equals($this->config->digest($actor->getPassword()),(string)($once['stamp']??''))){
                $factor=$this->security->factor($subject);
                if($this->access->edit($actor,$r)&&(int)($factor['generation']??0)===($once['generation']??-1)){
                    $message=(string)($once['message']??'');$candidate=$once['ticket']??null;
                    if(is_string($candidate)&&($factor['ticket']??'')!==''&&(int)$factor['expires']>=time()
                        &&hash_equals($factor['ticket'],$this->config->digest($candidate)))$ticket=$candidate;
                }
            }
        }
        $nonce=Ceremony::encode(random_bytes(24));$response=$this->render('@PasskeySecurity/staff_mail_admin.twig',[
            'member'=>$member,'addresses'=>$this->mail->addresses($subject),'revision'=>$this->mail->stateDigest($subject),
            'can_edit'=>$this->access->edit($actor,$r)&&$member->getWork()?->getId()===Work::ACTIVE,
            'initial_revision'=>$this->initialRevision($subject),
            'initial_overview'=>(new \Plugin\PasskeySecurity\Resource\Runtime\EnrollmentOverview($this->em->getConnection(),$this->security))->forStaff($subject,time()),
            'can_initial'=>$this->security->initialEligible($subject),'message'=>$message,'ticket'=>$ticket,'nonce'=>$nonce]);
        $response->setStatusCode($status);
        foreach(['Cache-Control'=>'no-store, private','Pragma'=>'no-cache','Referrer-Policy'=>'same-origin','X-Content-Type-Options'=>'nosniff','X-Frame-Options'=>'DENY',
            'Content-Security-Policy'=>"default-src 'none'; style-src 'nonce-$nonce'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"]as$k=>$v)$response->headers->set($k,$v);
        return $response;
    }
    private function initialRevision(string $subject):string
    {
        $factor=$this->security->factor($subject);
        return $this->config->digest('initial-issue:'.$subject.':'.(int)($factor['generation']??0));
    }
    private function pristine(string $subject):bool
    {
        $db=$this->em->getConnection();
        if((int)$db->fetchOne('SELECT COUNT(*) FROM plg_ps_credential WHERE subject=?',[$subject])!==0)return false;
        if((int)$db->fetchOne('SELECT COUNT(*) FROM plg_ps_recovery WHERE subject=?',[$subject])!==0)return false;
        $f=$this->security->factor($subject);
        return !$f||($f['ticket']===''&&$f['secret']===''&&(int)$f['confirmed']===0&&(int)$f['expires']===0&&(int)$f['generation']===1&&(int)$f['last_step']===-1);
    }
    private function job(Request $r,string $id):void{$r->attributes->set('_ps_staff_mail_jobs',[...$r->attributes->get('_ps_staff_mail_jobs',[]),$id]);}
}
