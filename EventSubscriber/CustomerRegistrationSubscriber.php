<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\EventSubscriber;
use Eccube\Entity\Master\CustomerStatus;
use Eccube\Repository\CustomerRepository;
use Plugin\PasskeySecurity\Resource\Runtime\Ceremony;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;

/** Keep used/bad activation links useful without granting a login or revealing personal data. */
final class CustomerRegistrationSubscriber implements EventSubscriberInterface
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private CustomerRepository $customers,private Environment $twig){}
    public static function getSubscribedEvents():array{return [KernelEvents::REQUEST=>['activationProblem',6]];}
    public function activationProblem(RequestEvent $event):void
    {
        if (!$this->compatibility->shopEditionActive()) return;
        $r=$event->getRequest();
        if(!$event->isMainRequest()||!in_array($r->getMethod(),['GET','HEAD'],true)||$r->attributes->get('_route')!=='entry_activate')return;
        // Core's qtyInCart completion branch does not activate or send mail. Preserve it.
        if($r->attributes->get('qtyInCart')!==null)return;
        $secret=(string)$r->attributes->get('secret_key','');$confirmed=false;
        if(preg_match('/^[a-zA-Z0-9]{16,128}$/D',$secret)){
            $customer=$this->customers->findOneBy(['secret_key'=>$secret]);
            if($customer?->getStatus()?->getId()===CustomerStatus::PROVISIONAL)return; // Original core activation remains unchanged.
            $confirmed=$customer?->getStatus()?->getId()===CustomerStatus::REGULAR;
        }
        $nonce=Ceremony::encode(random_bytes(24));$html=$this->twig->render('@PasskeySecurity/customer_registration.twig',['mode'=>$confirmed?'already':'invalid','success'=>false,'message'=>'','nonce'=>$nonce]);
        $response=new Response($html,$confirmed?200:404,['Cache-Control'=>'no-store, private','Referrer-Policy'=>'no-referrer','X-Content-Type-Options'=>'nosniff','X-Frame-Options'=>'DENY','Content-Security-Policy'=>"default-src 'none'; style-src 'nonce-$nonce'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"]);
        $event->setResponse($response);
    }
}
