<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Controller;

use Eccube\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

final class EmailHelpController extends AbstractController
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility) {}

    /** @Route("/mypage/login/email-help", name="ps_email_help", methods={"GET"}) */
    public function index(): Response
    {
        if (!$this->compatibility->shopEditionActive()) throw $this->createNotFoundException();
        $response = $this->render('@PasskeySecurity/email_help.twig');
        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        return $response;
    }
}
