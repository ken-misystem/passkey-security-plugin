<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Eccube\Validator\EmailValidator\NoRFCEmailValidator;
use Symfony\Component\Mime\Address;

/** Same syntax boundary as the actual mailer. No DNS lookup or address rewriting. */
final class Mailbox
{
    public static function accepts(string $email): bool
    {
        try { new Address($email); return true; }
        catch (\InvalidArgumentException $e) { return false; }
    }

    public static function needsHelp(string $email): bool
    {
        return strlen($email) <= 254 && (new NoRFCEmailValidator())->isValid($email) && !self::accepts($email);
    }
}
