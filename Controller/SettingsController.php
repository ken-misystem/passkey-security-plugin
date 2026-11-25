<?php
declare(strict_types=1);

namespace Plugin\PasskeySecurity\Controller;

use Eccube\Controller\AbstractController;
use Eccube\Entity\Member;
use Plugin\PasskeySecurity\Resource\Runtime\{Ceremony, ClockEventLog, Policy, PublicPolicy, PublicSettings, SettingsContinuation, Store};
use Plugin\PasskeySecurity\Resource\Turnstile\{Configuration as TurnstileConfiguration, Verifier};
use Symfony\Component\HttpFoundation\{Request, Response};
use Symfony\Component\Routing\Annotation\Route;

final class SettingsController extends AbstractController
{
    private const TURNSTILE_KEY_CHECK = 'settings_key_check';

    public function __construct(
        private PublicSettings $settings,
        private Store $store,
        private Policy $policy,
        private PublicPolicy $publicPolicy,
        private ClockEventLog $clockLog,
        private TurnstileConfiguration $turnstile,
        private Verifier $turnstileVerifier,
    ) {}

    /** @Route("/%eccube_admin_route%/plugin/passkey/config", name="passkey_security_admin_config", methods={"GET","POST"}) */
    public function configure(Request $request): Response
    {
        $user = $this->getUser();
        if (!$user instanceof Member || !SettingsContinuation::admin($user)) {
            throw $this->createAccessDeniedException();
        }
        $ready = $this->settings->ready();
        $shop = $this->settings->migrated();
        $passkeyRequired = $this->settings->staffPasskeyRequired();
        $message = '';
        $resume = null;
        $keyCheckSite = null;
        $settingsRoute = SettingsContinuation::ROUTE;
        try {
            $needsProof = $ready && ($shop || $this->publicPolicy->mustAuthenticate($user));
            $pending = $ready ? SettingsContinuation::pending($request, $user, $this->policy) : null;
            if (!$request->isMethod('POST')) {
                if ($needsProof && !$this->policy->staffAccess($request->getSession(), $user, time())) {
                    if ($pending === null) {
                        SettingsContinuation::start($request, $user, $this->policy, null);
                    }
                    return $this->secureResponse($this->redirectToRoute('ps_member', [], 303));
                }
                if ($request->query->get('resume') === '1' && $pending !== null && $pending['settings'] !== null) {
                    $resume = $pending['token'];
                    if ($pending['settings']['turnstile_keys'] !== null) {
                        $keyCheckSite = $this->turnstile->openKeys($pending['settings']['turnstile_keys'])['site_key'];
                    }
                } elseif ($request->query->get('resume') === '1' && $pending !== null) {
                    SettingsContinuation::clear($request);
                }
            } else {
                if (!$request->isSecure() || $request->headers->get('Origin') !== $request->getSchemeAndHttpHost()
                    || !$this->isCsrfTokenValid('ps_public_config', $request->request->get('_token'))) {
                    throw new \RuntimeException('config_request');
                }
                $token = $request->request->get('resume_token');
                if ($token !== null) {
                    if ($pending === null || $pending['settings'] === null || !hash_equals($pending['token'], $token)) {
                        throw new \RuntimeException('config_continuation');
                    }
                    $values = $pending['settings'];
                } else {
                    $values = $this->submittedSettings($request, $shop);
                }
                if ($values['origin'] !== $request->getSchemeAndHttpHost()) {
                    throw new \RuntimeException('config_origin');
                }
                $required = $shop || $values['required'];
                $requirePasskey = $passkeyRequired || $values['passkey_required'] === true;
                if ($values['passkey_required'] === true && !$passkeyRequired && $this->settings->staffWithoutPasskey() > 0) {
                    throw new \RuntimeException('public_staff_passkey_enrollment_required');
                }
                if ($needsProof || ($ready && ($required || $requirePasskey))) {
                    try {
                        $proof = $this->policy->staffProof($request->getSession(), $user, time());
                        if ($requirePasskey && $proof !== 'passkey') {
                            throw new \RuntimeException('security_recent_proof_required');
                        }
                    } catch (\RuntimeException $error) {
                        if (!in_array($error->getMessage(), ['security_recent_proof_required', 'security_staff_authentication_required'], true)) {
                            throw $error;
                        }
                        if ($token === null) {
                            SettingsContinuation::start($request, $user, $this->policy, $values);
                        }
                        return $this->secureResponse($this->redirectToRoute('ps_member', [], 303));
                    }
                }
                if ($this->store->active()) {
                    $this->store->limit('public-config:'.Policy::subject($user), time(), 5);
                }
                $enrolled = $this->publicPolicy->enrolled($user);
                if ($required && (!$enrolled || !$this->policy->complete($request->getSession(), $user, time()))) {
                    throw new \RuntimeException('enroll_admin_first');
                }
                if ($values['turnstile_keys'] !== null) {
                    if ($token === null) {
                        SettingsContinuation::start($request, $user, $this->policy, $values);
                        return $this->secureResponse($this->redirectToRoute($settingsRoute, ['resume' => '1'], 303));
                    }
                    $keys = $this->turnstile->openKeys($values['turnstile_keys']);
                    if (!$this->turnstileVerifier->verifyKeys($keys, $request->request->get('turnstile_check_token'), self::TURNSTILE_KEY_CHECK)) {
                        $request->getSession()->getFlashBag()->add('passkey_settings_notice',
                            '新しいTurnstileキーを確認できませんでした。現在のキーでの運用を継続しています。');
                        return $this->secureResponse($this->redirectToRoute($settingsRoute, ['resume' => '1'], 303));
                    }
                }
                SettingsContinuation::clear($request);
                $this->settings->save($values['origin'], $values['name'], $required, $this->store, $values['hours'],
                    $values['turnstile_timeouts'], $values['turnstile_keys'], $values['passkey_required']);
                $this->store->audit(Policy::subject($user), 'public_policy_saved');
                $request->getSession()->getFlashBag()->add('passkey_settings_notice', '設定を保存しました。');
                return $this->secureResponse($this->redirectToRoute($settingsRoute, [], 303));
            }
        } catch (\Throwable $error) {
            if (Policy::isClockFailure($error)) {
                $incident = $this->clockLog->rejected($error, 'configure', 'member', $request->getMethod());
                $url = htmlspecialchars($this->generateUrl('passkey_security_admin_config'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                $response = new Response('<!doctype html><html lang="ja"><meta charset="utf-8"><title>認証処理の確認</title>'
                    .'<p>認証処理を完了できませんでした。</p><p>同じ操作を再送せず、2秒以上待って<a href="'.$url
                    .'">画面を開き直し、状態を確認してください</a>。</p>'
                    .($incident === null ? '' : '<p>照会番号：'.$incident.'</p>'), 503, ['Retry-After' => '2']);
                if ($incident !== null) {
                    $response->headers->set('X-PasskeySecurity-Incident', $incident);
                }
                return $this->secureResponse($response);
            }
            if (Store::isTransientDatabaseFailure($error)) {
                return $this->secureResponse(new Response('認証処理が混み合っています。少し待ってから再度お試しください。',
                    503, ['Retry-After' => '2']));
            }
            $reason = $error->getMessage();
            $message = match ($reason) {
                'config_request' => '画面を開き直してから、もう一度保存してください。',
                'config_origin', 'public_https_origin_required', 'public_origin_immutable' =>
                    'この店舗のHTTPS URLから設定画面を開いてください。',
                'public_name_invalid' => '認証時に表示する店舗名を確認してください。',
                'public_staff_session_hours_invalid' => '保持時間は1〜6時間から選択してください。',
                'public_staff_passkey_enrollment_required' => 'パスキーを必須にする前に、稼働中の全スタッフがパスキーを登録してください。',
                'public_turnstile_timeout_invalid' => 'Turnstileの待ち時間を指定範囲内で入力してください。',
                'turnstile_config', 'turnstile_test_key_prohibited' => 'この店舗用のTurnstileのサイトキーとシークレットキーを入力してください。',
                'enroll_admin_first' => 'スタッフの追加認証を必須にする前に、ご自身の追加認証を登録し、本人確認を完了してください。',
                'config_continuation' => '保存の続きが期限切れです。値を確認してから保存してください。',
                'security_rate_limited' => '保存の試行回数が上限に達しました。時間をおいてからお試しください。',
                default => '設定を保存できませんでした。',
            };
        }

        if ($message === '' && $request->hasSession()) {
            $message = $request->getSession()->getFlashBag()->get('passkey_settings_notice')[0] ?? '';
        }
        $nonce = Ceremony::encode(random_bytes(24));
        return $this->secureResponse($this->render('@PasskeySecurity/public_config.twig', [
            'nonce' => $nonce,
            'message' => $message,
            'resume_token' => $resume,
            'turnstile_check_site' => $keyCheckSite,
            'turnstile_check_action' => self::TURNSTILE_KEY_CHECK,
            'origin' => $this->settings->get('origin') ?? ($request->isSecure() ? $request->getSchemeAndHttpHost() : ''),
            'name' => $this->settings->get('name') ?? 'アカウント',
            'required' => $this->settings->required(),
            'shop' => $shop,
            'staff_passkey_required' => $passkeyRequired,
            'staff_without_passkey' => $ready ? $this->settings->staffWithoutPasskey() : null,
            'ready' => $this->settings->ready(),
            'staff_session_hours' => $this->settings->staffSessionHours(),
            'staff_session_options' => PublicSettings::STAFF_SESSION_HOURS,
            'turnstile_timeouts' => $shop ? $this->settings->turnstileTimeouts() : null,
        ]), $nonce, $keyCheckSite !== null);
    }

    private function submittedSettings(Request $request, bool $shop): array
    {
        $origin = (string) $request->request->get('origin');
        $name = (string) $request->request->get('name');
        $hours = $request->request->get('staff_session_hours');
        PublicSettings::validateOrigin($origin);
        if ($name === '' || strlen($name) > 80 || preg_match('/[\x00-\x1f\x7f]/u', $name) !== 0) {
            throw new \RuntimeException('public_name_invalid');
        }
        if ($hours !== null && !in_array($hours, array_map('strval', PublicSettings::STAFF_SESSION_HOURS), true)) {
            throw new \RuntimeException('public_staff_session_hours_invalid');
        }
        $browser = $request->request->get('turnstile_browser_seconds');
        $gateway = $request->request->get('turnstile_gateway_seconds');
        $timeouts = $shop && ($browser !== null || $gateway !== null) ? [
            'browser' => PublicSettings::timeout($browser, PublicSettings::TURNSTILE_BROWSER_SECONDS),
            'gateway' => PublicSettings::timeout($gateway, PublicSettings::TURNSTILE_GATEWAY_SECONDS),
        ] : null;
        $site = (string) $request->request->get('turnstile_site_key', '');
        $secret = (string) $request->request->get('turnstile_secret_key', '');
        $keys = $shop && ($site !== '' || $secret !== '') ? $this->turnstile->stageKeys($site, $secret, $origin) : null;
        $passkey = $request->request->get('staff_passkey_required');
        if ($passkey !== null && !in_array($passkey, ['0', '1'], true)) {
            throw new \RuntimeException('public_policy_invalid');
        }
        if ($passkey === '1' && !$this->settings->ready()) {
            throw new \RuntimeException('public_staff_passkey_enrollment_required');
        }
        return ['origin' => $origin, 'name' => $name, 'hours' => $hours, 'turnstile_timeouts' => $timeouts, 'turnstile_keys' => $keys,
            'passkey_required' => $passkey === null ? null : $passkey === '1',
            'required' => $shop || $request->request->get('staff_required') === '1'];
    }

    private function secureResponse(Response $response, string $nonce = '', bool $keyCheck = false): Response
    {
        $response->headers->add([
            'Cache-Control' => 'no-store, private',
            'Referrer-Policy' => 'same-origin',
            'X-Frame-Options' => 'DENY',
            'X-Content-Type-Options' => 'nosniff',
        ]);
        if ($nonce !== '') {
            $cloudflare = $keyCheck ? ' https://challenges.cloudflare.com' : '';
            $frame = $keyCheck ? "; frame-src$cloudflare; connect-src$cloudflare" : '';
            $response->headers->set('Content-Security-Policy',
                "default-src 'none'; script-src 'nonce-$nonce'$cloudflare; style-src 'nonce-$nonce'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'$frame");
        }
        return $response;
    }
}
