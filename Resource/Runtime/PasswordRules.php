<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

/** Common rules for newly assigned passwords. Never gate existing login passwords. */
final class PasswordRules
{
    public const MIN_LENGTH=12;
    public const MAX_LENGTH=200;
    public const PATTERN='/\A(?=.*[A-Za-z])(?=.*[0-9])[!-~]{12,200}\z/D';
    public const HTML_PATTERN='(?=.*[A-Za-z])(?=.*[0-9])[!-~]{12,200}';
    public const MESSAGE='半角12～200文字で、英字と数字をそれぞれ1文字以上含めてください。空白・全角文字は使えません。以前のパスワードやメールアドレスとは異なるものにしてください。';
    public static function valid(mixed $password,array $emails=[]):bool
    {
        if(!is_string($password)||strlen($password)<self::MIN_LENGTH||strlen($password)>self::MAX_LENGTH
            ||preg_match(self::PATTERN,$password)!==1)return false;
        foreach($emails as$email)if(is_string($email)&&$email!==''&&hash_equals($email,$password))return false;
        return true;
    }
}
