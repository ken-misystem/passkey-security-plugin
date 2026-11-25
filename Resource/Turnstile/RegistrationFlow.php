<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Turnstile;

use Symfony\Component\HttpFoundation\Session\SessionInterface;

/** One continuation of an already checked WebAuthn ceremony, never a general CAPTCHA bypass. */
final class RegistrationFlow
{
    private const KEY = 'ps_turnstile_registration';

    public static function issue(SessionInterface $session, string $path, string $csrf, int $now, string $verifyAction = 'register_verify'): string
    {
        $ceremony = $session->get('ps_ceremony');
        if (!is_array($ceremony) || ($ceremony['purpose'] ?? null) !== (['register_verify'=>'register','login_verify'=>'assert','verify_passkey'=>'assert'][$verifyAction] ?? 'invalid')) {
            throw new \RuntimeException('registration_ceremony_required');
        }
        $token = bin2hex(random_bytes(32));
        $session->set(self::KEY, ['digest'=>hash('sha256', $token), 'path'=>$path,
            'csrf'=>hash('sha256', $csrf), 'expires'=>$now+120, 'action'=>$verifyAction,
            'ceremony'=>hash('sha256', serialize($ceremony))]);
        return $token;
    }

    public static function consume(SessionInterface $session, string $path, array $input, int $now): bool
    {
        // Consume before validation, including failed attempts and wrong CSRF/path.
        $grant = $session->remove(self::KEY);
        $token = $input['turnstile_flow'] ?? null;
        $csrf = $input['_token'] ?? null;
        $ceremony = $session->get('ps_ceremony');
        return is_array($grant) && is_string($token) && strlen($token) === 64
            && is_string($csrf) && ($input['action'] ?? null) === ($grant['action'] ?? null)
            && in_array($grant['action'] ?? null, ['register_verify','login_verify','verify_passkey'], true)
            && $grant['path'] === $path && $grant['expires'] >= $now
            && is_array($ceremony) && ($ceremony['purpose'] ?? null) === (['register_verify'=>'register','login_verify'=>'assert','verify_passkey'=>'assert'][$grant['action']] ?? 'invalid')
            && hash_equals($grant['digest'], hash('sha256', $token))
            && hash_equals($grant['csrf'], hash('sha256', $csrf))
            && hash_equals($grant['ceremony'], hash('sha256', serialize($ceremony)));
    }
}
