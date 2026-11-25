<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Controller;
use Eccube\Controller\AbstractController;
use Eccube\Entity\Master\CustomerStatus;
use Eccube\Repository\CustomerRepository;
use Eccube\Service\MailService;
use Plugin\PasskeySecurity\Resource\Runtime\{Config,Store,Ceremony};
use Symfony\Component\HttpFoundation\{Request,Response};
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

/** Explicit, password-confirmed resend; never activates an account or resets a password. */
final class CustomerRegistrationController extends AbstractController
{
    public function __construct(private Config $config,private Store $store,private CustomerRepository $customers,
        private UserPasswordHasherInterface $hasher,private MailService $mail) {}
    /** @Route("/entry/resend", name="ps_customer_registration_resend", methods={"GET","POST"}) */
    public function index(Request $r):Response
    {
        if (!$this->config->shopEditionActive()) throw $this->createNotFoundException();
        $success=false;$status=200;$message='';
        try{
            if(!$r->isSecure()||$r->getSchemeAndHttpHost()!==$this->config->origin())throw new \RuntimeException('origin');
            if($r->isMethod('POST')){
                if($r->headers->get('Origin')!==$this->config->origin()||strlen($r->getContent())>4096
                    ||!$this->isCsrfTokenValid('ps_customer_registration_resend',$r->request->get('_token')))throw new \RuntimeException('request');
                $email=trim((string)$r->request->get('email',''));$password=(string)$r->request->get('password','');
                if(strlen($email)>254||!filter_var($email,FILTER_VALIDATE_EMAIL)||strlen($password)<1||strlen($password)>200)throw new \RuntimeException('input');
                // Known, unknown, completed, bad-password and rate-limited accounts have the same response.
                try{
                    $this->store->limit('customer-confirm-ip:'.$r->getClientIp(),time(),10);
                    $this->store->limit('customer-confirm-credential:'.mb_strtolower($email),time(),3);
                    $customer=$this->customers->findOneBy(['email'=>$email,'Status'=>CustomerStatus::PROVISIONAL]);
                    $probe=$customer??$this->customers->newCustomer();
                    if(!$customer){$probe->setSalt(null);$probe->setPassword('$2y$13$XFtKb9HttRIf6I/JAxDvJuhgc0X8ssCWRjiWUp5QyxVtgEAumjUQ2');}
                    $valid=$this->hasher->isPasswordValid($probe,$password);
                    if($customer&&$valid){
                        $this->store->limit('customer-confirm-delivery:'.mb_strtolower($email),time(),1);
                        $url=$this->generateUrl('entry_activate',['secret_key'=>$customer->getSecretKey()]);$parts=parse_url($url);$path=$parts['path']??null;
                        if(!is_string($path)||!str_starts_with($path,'/')||str_starts_with($path,'//')||isset($parts['query'])||isset($parts['fragment']))throw new \RuntimeException('route');
                        $this->mail->sendCustomerConfirmMail($customer,$this->config->origin().$path);
                    }
                }catch(\Throwable $ignored){}
                $success=true;$message='入力内容が一致し、メール確認がまだ完了していない場合に、確認メールを予約しました。迷惑メールフォルダもご確認ください。続けての再送は5分ほどお待ちください。';
            }
        }catch(\Throwable $error){$status=403;$message='送信できませんでした。この画面を開き直し、メールアドレスと登録時のパスワード、安全確認をお確かめください。';}
        $nonce=Ceremony::encode(random_bytes(24));$response=$this->render('@PasskeySecurity/customer_registration.twig',['mode'=>'resend','success'=>$success,'message'=>$message,'nonce'=>$nonce]);$response->setStatusCode($status);
        foreach(['Cache-Control'=>'no-store, private','Referrer-Policy'=>'same-origin','X-Content-Type-Options'=>'nosniff','X-Frame-Options'=>'DENY','Content-Security-Policy'=>"default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"]as$k=>$v)$response->headers->set($k,$v);return $response;
    }
}
