<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Doctrine\DBAL\{ArrayParameterType, Connection};

/** Public profile metadata only. No host-derived first-visit initialization. */
final class PublicSettings
{
    public const STAFF_SESSION_HOURS = [1, 2, 3, 4, 5, 6];
    public const TURNSTILE_BROWSER_SECONDS = [5, 60, 20];
    public const TURNSTILE_GATEWAY_SECONDS = [2, 10, 10];
    private const TURNSTILE_KEY_PARTS = [
        'turnstile_keys_0', 'turnstile_keys_1', 'turnstile_keys_2', 'turnstile_keys_3',
        'turnstile_keys_4', 'turnstile_keys_5', 'turnstile_keys_6', 'turnstile_keys_7',
    ];

    public function __construct(private Connection $db) {}
    public function get(string $name): ?string
    {
        $v=$this->db->fetchOne('SELECT value FROM plg_ps_meta WHERE name=?',['public_'.$name]);
        return is_string($v)?$v:null;
    }
    public function put(string $name,string $value):void
    {
        if(strlen($value)>128)throw new \RuntimeException('public_setting_length');
        if($this->get($name)===null)$this->db->insert('plg_ps_meta',['name'=>'public_'.$name,'value'=>$value]);
        else $this->db->update('plg_ps_meta',['value'=>$value],['name'=>'public_'.$name]);
    }
    public function ready():bool
    {
        $this->assertShopEdition();
        $profile=$this->get('profile');
        if($profile!==null&&$profile!=='1')throw new \RuntimeException('public_profile_invalid');
        if($profile===null&&$this->db->fetchOne("SELECT value FROM plg_ps_meta WHERE name='epoch'")!==false)
            throw new \RuntimeException('public_migration_requires_review');
        return $this->get('origin')!==null;
    }
    public function required():bool
    {
        $v=$this->get('staff_required');
        if(!in_array($v,['0','1'],true)||($v==='0'&&$this->migrated()))throw new \RuntimeException('public_policy_invalid');
        return $v==='1';
    }
    public function staffPasskeyRequired(): bool
    {
        $required = $this->get('staff_passkey_required');
        if (!in_array($required, [null, '0', '1'], true)) {
            throw new \RuntimeException('public_policy_invalid');
        }
        return $required === '1';
    }

    public function staffWithoutPasskey(): int
    {
        $activeStaff = $this->db->fetchFirstColumn('SELECT id FROM dtb_member WHERE work_id=1');
        $registered = $this->db->fetchFirstColumn("SELECT DISTINCT subject FROM plg_ps_credential WHERE revoked=0 AND subject LIKE 'member:%'");
        return count(array_diff(array_map(static fn($id): string => 'member:'.$id, $activeStaff), $registered));
    }

    public function migrated(): bool { return $this->get('legacy_identity') !== null; }

    public function staffSessionHours(): int
    {
        $hours = $this->get('staff_session_hours');
        return $hours !== null && self::validStaffSessionHours($hours) ? (int) $hours : 1;
    }

    private static function validStaffSessionHours(string $hours): bool
    {
        return (string) (int) $hours === $hours && in_array((int) $hours, self::STAFF_SESSION_HOURS, true);
    }

    public function turnstileTimeouts(): array
    {
        return [
            'browser' => self::timeout($this->get('turnstile_browser_seconds'), self::TURNSTILE_BROWSER_SECONDS),
            'gateway' => self::timeout($this->get('turnstile_gateway_seconds'), self::TURNSTILE_GATEWAY_SECONDS),
        ];
    }

    public static function timeout(?string $value, array $range): int
    {
        if ($value === null) {
            return $range[2];
        }
        $seconds = (int) $value;
        if ((string) $seconds !== $value || $seconds < $range[0] || $seconds > $range[1]) {
            throw new \DomainException('public_turnstile_timeout_invalid');
        }
        return $seconds;
    }

    public function turnstileKeys(): ?string
    {
        $names = array_map(static fn(string $name): string => 'public_'.$name, self::TURNSTILE_KEY_PARTS);
        $parts = $this->db->fetchFirstColumn('SELECT value FROM plg_ps_meta WHERE name IN (?) ORDER BY name',
            [$names], [ArrayParameterType::STRING]);
        if ($parts === []) {
            return null;
        }
        if (count($parts) !== count($names)) {
            throw new \RuntimeException('turnstile_managed_keys_invalid');
        }
        return implode('', $parts);
    }

    public function assertInstallable(): bool
    {
        // EC-CUBE can exclude plugin-owned tables from the ORM's schema inventory.
        if ($this->db->createSchemaManager()->listTableColumns('plg_ps_meta') === []) {
            if (class_exists(ShopEdition::class)) {
                throw new \RuntimeException('legacy_shop_migration_required');
            }
            return false;
        }
        $this->assertShopEdition();
        if (class_exists(ShopEdition::class) && $this->get('shop_edition') !== ShopEdition::ID) {
            throw new \RuntimeException('public_migration_requires_review');
        }
        if ($this->get('profile') !== '1'
            && $this->db->fetchOne("SELECT value FROM plg_ps_meta WHERE name='epoch'") !== false) {
            throw new \RuntimeException('public_migration_requires_review');
        }
        return true;
    }

    private function assertShopEdition(): void
    {
        $edition = $this->get('shop_edition');
        if ($edition !== null && !Config::supportsShopEdition($edition)) {
            throw new \RuntimeException('legacy_shop_package_required');
        }
    }
    public function install():void
    {
        $this->db->transactional(function():void{
            $epoch=$this->db->fetchOne("SELECT value FROM plg_ps_meta WHERE name='epoch'");
            // The shop-specific edition is never silently converted by a public update.
            if($epoch!==false&&$this->get('profile')!=='1')throw new \RuntimeException('public_migration_requires_review');
            if($this->get('profile')===null){
                $this->put('profile','1');$this->put('staff_required','0');
                $this->put('salt',bin2hex(random_bytes(32)));
            }
        });
    }
    public static function validateOrigin(string $origin):string
    {
        $u=parse_url($origin);
        if(strlen($origin)>128||!is_array($u)||($u['scheme']??'')!=='https'
            ||isset($u['path'])||isset($u['user'])||isset($u['pass'])||isset($u['query'])||isset($u['fragment'])
            ||!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/D',$u['host']??'')
            ||isset($u['port'])&&($u['port']<1||$u['port']>65535))throw new \RuntimeException('public_https_origin_required');
        return $u['host'];
    }
    /** Called only by authenticated, CSRF-protected admin setup, never a storefront request. */
    public function configure(string $origin,string $name,Store $store):void
    {
        self::validateOrigin($origin);
        if($name===''||strlen($name)>80||preg_match('/[\x00-\x1f\x7f]/u',$name)!==0)throw new \RuntimeException('public_name_invalid');
        $this->db->transactional(function()use($origin,$name,$store):void{
            $old=$this->get('origin');
            if($old!==null&&!hash_equals($old,$origin))throw new \RuntimeException('public_origin_immutable');
            $this->put('origin',$origin);$this->put('name',$name);
            // Empty arrays are deliberate: installing never resets any existing password.
            if(!$store->active())$store->activate([],[]);
        });
    }
    public function save(string $origin,string $name,bool $required,Store $store,?string $staffSessionHours=null, ?array $turnstileTimeouts = null,
        ?string $turnstileKeys = null, ?bool $staffPasskeyRequired = null):void
    {
        if ($staffSessionHours !== null && !self::validStaffSessionHours($staffSessionHours)) {
            throw new \DomainException('public_staff_session_hours_invalid');
        }
        $this->db->transactional(function()use($origin,$name,$required,$store,$staffSessionHours,$turnstileTimeouts,$turnstileKeys,$staffPasskeyRequired):void{
            $this->configure($origin,$name,$store);$this->requireStaff($required);
            if ($staffSessionHours !== null) {
                $this->put('staff_session_hours', $staffSessionHours);
            }
            if ($staffPasskeyRequired !== null) {
                if ($staffPasskeyRequired && !$this->staffPasskeyRequired() && $this->staffWithoutPasskey() > 0) {
                    throw new \RuntimeException('public_staff_passkey_enrollment_required');
                }
                $this->put('staff_passkey_required', $staffPasskeyRequired ? '1' : '0');
            }
            if ($turnstileKeys !== null) {
                $parts = str_split($turnstileKeys, 128);
                if (count($parts) > count(self::TURNSTILE_KEY_PARTS)) {
                    throw new \RuntimeException('turnstile_managed_keys_invalid');
                }
                foreach (self::TURNSTILE_KEY_PARTS as $i => $name) {
                    $this->put($name, $parts[$i] ?? '');
                }
            }
            if ($turnstileTimeouts !== null) {
                $this->put('turnstile_browser_seconds', (string) self::timeout((string) $turnstileTimeouts['browser'], self::TURNSTILE_BROWSER_SECONDS));
                $this->put('turnstile_gateway_seconds', (string) self::timeout((string) $turnstileTimeouts['gateway'], self::TURNSTILE_GATEWAY_SECONDS));
            }
        });
    }
    public function requireStaff(bool $required):void
    {
        if (!$required && $this->migrated()) {
            throw new \RuntimeException('legacy_staff_factor_required');
        }
        $this->put('staff_required',$required?'1':'0');
    }
}
