<?php
declare(strict_types=1);

namespace Plugin\PasskeySecurity\Resource\Runtime;

use Eccube\Entity\Member;
use Symfony\Component\HttpFoundation\Request;

final class SettingsContinuation
{
    public const ROUTE = 'passkey_security_admin_config';
    private const KEY = 'ps_config_continuation';

    public static function admin(Member $user): bool
    {
        return $user->getWork()?->getId() === 1 && $user->getAuthority()?->getId() === 0;
    }

    public static function start(Request $request, Member $user, Policy $policy, ?array $settings): void
    {
        $request->getSession()->set(self::KEY, [
            'token' => bin2hex(random_bytes(24)),
            'subject' => Policy::subject($user),
            'stamp' => $policy->stamp($user),
            'issued' => time(),
            'settings' => $settings,
        ]);
    }

    public static function pending(Request $request, Member $user, Policy $policy): ?array
    {
        if (!self::admin($user) || !$request->hasSession()) {
            return null;
        }
        $pending = $request->getSession()->get(self::KEY);
        if (!is_array($pending) || $pending['subject'] !== Policy::subject($user)
            || $pending['issued'] > time() || $pending['issued'] <= time() - 600 || !hash_equals($pending['stamp'], $policy->stamp($user))) {
            return null;
        }
        return $pending;
    }

    public static function clear(Request $request): void
    {
        $request->getSession()->remove(self::KEY);
    }
}
