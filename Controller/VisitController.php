<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Controller;

use Eccube\Controller\AbstractController;
use Plugin\PasskeySecurity\Resource\Runtime\Config;
use Symfony\Component\HttpFoundation\{Request,JsonResponse};
use Symfony\Component\Routing\Annotation\Route;

final class VisitController extends AbstractController
{
    public function __construct(private Config $config) {}
    /** @Route("/security/visit-check", name="ps_turnstile_visit", methods={"POST"}) */
    public function index(Request $r): JsonResponse
    {
        if (!$this->config->shopEditionActive()) throw $this->createNotFoundException();
        $ok=false;
        try {
            $d=json_decode($r->getContent(),true,8,JSON_THROW_ON_ERROR);
            $ok=$r->attributes->get('_ps_visit_verified')===true && $r->hasSession() && $r->isSecure() && $r->getSchemeAndHttpHost()===$this->config->origin()
                && $r->headers->get('Origin')===$this->config->origin()
                && is_array($d) && $this->isCsrfTokenValid('ps_turnstile_visit',$d['_token']??null);
        } catch (\Throwable $e) {}
        if($ok)$r->getSession()->set('ps_turnstile_visit_until',time()+1800);
        return new JsonResponse(['ok'=>$ok],$ok?200:403,['Cache-Control'=>'no-store, private']);
    }
}
