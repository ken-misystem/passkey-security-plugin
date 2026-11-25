<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Plugin\PasskeySecurity\Controller\LegacySecurityController;
use Symfony\Component\HttpFoundation\RequestStack;

/** Domain-separated key uses the existing application secret plus a per-install random salt. */
final class Config
{
    public function __construct(private PublicSettings $settings,private string $applicationSecret,
        private ?RequestStack $requests = null) {}
    public function data():array
    {
        if ($this->settings->get('shop_edition') !== null && !$this->shopEditionActive()) {
            throw new \RuntimeException('legacy_shop_package_required');
        }
        $origin=$this->settings->get('origin')??'';
        $host=PublicSettings::validateOrigin($origin);
        $salt=$this->settings->get('salt');
        if(strlen($this->applicationSecret)<32||$this->applicationSecret==='<change.me>'
            ||!is_string($salt)||!preg_match('/^[a-f0-9]{64}$/D',$salt))throw new \RuntimeException('public_application_secret_required');
        return ['origin'=>$origin,'rp_id'=>$host,'rp_name'=>$this->settings->get('name')??'アカウント',
            'key'=>hash_hkdf('sha256',$this->applicationSecret,32,'eccube/PasskeySecurity/public/v1',hex2bin($salt))];
    }
    public function ready():bool{return $this->settings->ready();}
    public function key():string{return $this->data()['key'];}
    public function origin():string{return $this->data()['origin'];}
    public function staffSessionTtl(): int { return $this->settings->staffSessionHours() * 3600; }
    public function staffPasskeyRequired(): bool { return $this->settings->staffPasskeyRequired(); }
    public function usesLegacyIdentity(): bool { return $this->settings->migrated(); }
    public static function supportsShopEdition(string $edition): bool
    {
        return $edition === 'shop-068-v1'
            && (class_exists(ShopEdition::class) || class_exists(LegacySecurityController::class));
    }

    public function shopEditionActive(): bool
    {
        $request = $this->requests?->getMainRequest();
        $attribute = '_passkey_security_legacy_profile';
        if ($request?->attributes->has($attribute)) {
            return $request->attributes->getBoolean($attribute);
        }
        $edition = $this->settings->get('shop_edition');
        $active = $edition !== null && self::supportsShopEdition($edition);
        $request?->attributes->set($attribute, $active);
        return $active;
    }
    public function shopEncryptionKey(): string
    {
        $wrapped = $this->settings->get('legacy_identity');
        if (!$this->shopEditionActive() || $wrapped === null) {
            throw new \RuntimeException('legacy_shop_package_required');
        }
        return $this->unwrapLegacyIdentity($wrapped);
    }
    public function digest(string $value, bool $binary = false): string
    {
        $wrapped = $this->settings->get('legacy_identity');
        $key = $wrapped === null ? $this->key() : $this->unwrapLegacyIdentity($wrapped);
        return hash_hmac('sha256', $value, $key, $binary);
    }
    public function sealLegacyIdentity(string $key): string
    {
        if (strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new \RuntimeException('legacy_identity_invalid');
        }
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return base64_encode($nonce.sodium_crypto_secretbox($key, $nonce, $this->identityWrappingKey()));
    }
    private function unwrapLegacyIdentity(string $wrapped): string
    {
        $bytes = base64_decode($wrapped, true);
        if ($bytes === false || strlen($bytes) !== 72) {
            throw new \RuntimeException('legacy_identity_invalid');
        }
        $key = sodium_crypto_secretbox_open(substr($bytes, 24), substr($bytes, 0, 24), $this->identityWrappingKey());
        if ($key === false) {
            throw new \RuntimeException('legacy_identity_invalid');
        }
        return $key;
    }
    private function identityWrappingKey(): string
    {
        return hash_hkdf('sha256', $this->key(), 32, 'eccube/PasskeySecurity/legacy-identity/v1');
    }
    public function __debugInfo():array{return ['secrets'=>'[redacted]'];}
    public static function dependencies():void{require_once dirname(__DIR__).'/dependencies/vendor/autoload.php';}
}
