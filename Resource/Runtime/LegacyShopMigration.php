<?php
declare(strict_types=1);

namespace Plugin\PasskeySecurity\Resource\Runtime;

use Doctrine\DBAL\Connection;

/** One-time migration of the reviewed shop build. Run with the storefront and workers stopped. */
final class LegacyShopMigration
{
    private const SOURCE = [
        'composer.json' => '71e03512148f125481a0e2f7faac9f441bd86aa0c6536527cb67b6214303dc3a',
        'Resource/Runtime/Config.php' => '0d5bf3238ebc4a278eca7bf3a6fb5e424147046b67c21b97602180272797cb75',
        'Resource/Runtime/Ceremony.php' => '6b5fa7959c44ed36f9354af9df3da771717d56ede97fb469398b1b60ffd13750',
        'Resource/Runtime/Store.php' => '479ffcb91944c83f049fee0351ffe8b8c5381c4099b13535241d1d7b253f5c09',
        'Resource/Runtime/Policy.php' => '6d01b98631cdaa2e7401a4ae54fcf55fdd976528b6c7b4be099e41d65965d8b1',
        'Resource/Runtime/StaffMailStore.php' => '0caecaaca246b11db1ebb9415d364bf9fa5bbc98937ac4468921b90116eb4196',
        'Resource/Runtime/InitialLink.php' => 'e140264a2bb756da618065eca88dc93dfa841da4335eb339b98f1162e4372c5d',
        'EventSubscriber/SecuritySubscriber.php' => 'f7c01836f03750385bd92a59653489dc9a1ae7cdd11485fd5ed61a7bbfdfc6a3',
        'Controller/SecurityController.php' => '2f7a0defc5088ca67ab412622c4dfc909b17a67b0bf99a227b5734d35357ae93',
    ];

    private const TABLES = [
        'plg_ps_meta' => 'name',
        'plg_ps_factor' => 'subject',
        'plg_ps_credential' => 'id',
        'plg_ps_reset' => 'subject',
        'plg_ps_recovery' => 'id',
        'plg_ps_limit' => 'bucket',
        'plg_ps_audit' => 'id',
        'plg_ps_staff_mailbox' => 'subject,slot',
        'plg_ps_staff_mail_enrollment' => 'subject,slot',
        'plg_ps_staff_mail_token' => 'id',
        'plg_ps_staff_mail_job' => 'id',
    ];

    public function __construct(
        private Connection $db,
        private PublicSettings $settings,
        private Config $config,
        private string $projectDir,
    ) {}

    public function run(string $source, string $configuration, ?string $expected = null): array
    {
        $this->verifySource($source);
        $shopEdition = class_exists(ShopEdition::class);
        if ($shopEdition) {
            ShopEdition::verify();
        }
        $legacy = $this->legacyConfiguration($configuration);
        if (!str_contains((string)$this->db->fetchOne('SELECT VERSION()'), 'MariaDB')
            || $this->db->isTransactionActive()) {
            throw new \DomainException('legacy_mariadb_connection_required');
        }

        $lock = 'ps068:' . substr(hash('sha256', (string)$this->db->getDatabase()), 0, 48);
        if ($expected !== null && (int)$this->db->fetchOne('SELECT GET_LOCK(?, 0)', [$lock]) !== 1) {
            throw new \DomainException('legacy_migration_busy');
        }
        try {
            return $this->db->transactional(function () use ($legacy, $expected, $shopEdition): array {
                return $this->inspect($legacy, $expected, $shopEdition);
            });
        } finally {
            if ($expected !== null) {
                $this->db->fetchOne('SELECT RELEASE_LOCK(?)', [$lock]);
            }
        }
    }

    private function inspect(array $legacy, ?string $expected, bool $shopEdition): array
    {
        $lock = $expected === null ? '' : ' FOR UPDATE';
        $this->verifyTables();
        $rows = [];
        $counts = [];
        $digest = hash_init('sha256', HASH_HMAC, $legacy['key']);
        hash_update($digest, json_encode([$legacy['origin'], $legacy['name']], JSON_THROW_ON_ERROR));
        if ($shopEdition) {
            hash_update($digest, ShopEdition::MANIFEST_SHA256);
        }
        foreach (self::TABLES as $table => $order) {
            $counts[$table] = 0;
            hash_update($digest, $table."\n");
            foreach ($this->db->iterateAssociative("SELECT * FROM $table ORDER BY $order".$lock) as $row) {
                hash_update($digest, json_encode($row, JSON_THROW_ON_ERROR)."\n");
                ++$counts[$table];
                if (in_array($table, ['plg_ps_meta', 'plg_ps_factor', 'plg_ps_reset', 'plg_ps_recovery', 'plg_ps_credential'], true)) {
                    $rows[$table][] = $row;
                }
            }
        }
        $meta = array_column($rows['plg_ps_meta'] ?? [], 'value', 'name');
        if (!preg_match('/^[a-f0-9]{32}$/D', $meta['epoch'] ?? '') || preg_grep('/^public_/', array_keys($meta))) {
            throw new \DomainException('legacy_profile_not_pristine');
        }
        if ($this->db->fetchOne("SELECT version FROM dtb_plugin WHERE code='PasskeySecurity'".$lock) !== '0.6.8') {
            throw new \DomainException('legacy_plugin_version_mismatch');
        }
        $keyVerified = false;
        foreach ($rows['plg_ps_reset'] ?? [] as $reset) {
            $password = $this->passwordHash($reset['subject'], $lock);
            hash_update($digest, json_encode([$reset['subject'], $password], JSON_THROW_ON_ERROR)."\n");
            if (is_string($password)
                && hash_equals($reset['baseline'], hash_hmac('sha256', $password, $legacy['key']))) {
                $keyVerified = true;
            }
        }
        $issued = [];
        $blockers = [];
        foreach ($rows['plg_ps_recovery'] ?? [] as $recovery) {
            if ($recovery['status'] === 'issued') {
                $issued[$recovery['subject'].':'.$recovery['generation']] = true;
            }
            if ($recovery['status'] === 'claimed') {
                $blockers['legacy_recovery_in_progress'] = true;
            }
        }
        $totp = 0;
        foreach ($rows['plg_ps_factor'] ?? [] as $factor) {
            if ($factor['secret'] !== '') {
                $secret = $this->decryptTotp($factor['secret'], $legacy['key']);
                sodium_memzero($secret);
                $keyVerified = true;
                ++$totp;
            }
            if (!$shopEdition && $factor['ticket'] !== '' && (int)$factor['expires'] >= time()
                && !isset($issued[$factor['subject'].':'.$factor['generation']])) {
                $blockers['legacy_initial_link_in_progress'] = true;
            }
        }
        foreach ($rows['plg_ps_credential'] ?? [] as $credential) {
            $raw = Ceremony::decode($credential['credential']);
            if (!hash_equals($credential['id'], hash('sha256', $raw))
                || !preg_match('/^(customer|member):[1-9][0-9]*$/D', $credential['subject'])
                || !in_array((int)$credential['backup_eligible'], [0, 1], true)) {
                throw new \DomainException('legacy_credential_invalid');
            }
        }
        if (!$keyVerified) {
            $blockers['legacy_key_not_verified'] = true;
        }
        if (!$shopEdition && ($counts['plg_ps_staff_mailbox'] || $counts['plg_ps_staff_mail_enrollment']
            || $this->db->fetchOne("SELECT id FROM plg_ps_staff_mail_token WHERE consumed=0 AND expires>=? LIMIT 1".$lock, [time()]) !== false
            || $this->db->fetchOne("SELECT id FROM plg_ps_staff_mail_job WHERE status IN ('pending','queued','sending','processing') LIMIT 1".$lock) !== false)) {
            $blockers['legacy_staff_mail_adapter_required'] = true;
        }
        $gateRequired = $_SERVER['TURNSTILE_REQUIRED'] ?? $_ENV['TURNSTILE_REQUIRED'] ?? getenv('TURNSTILE_REQUIRED');
        $gatePath = $_SERVER['TURNSTILE_CONFIG'] ?? $_ENV['TURNSTILE_CONFIG'] ?? getenv('TURNSTILE_CONFIG');
        $gateConfigured = is_string($gatePath) && $gatePath !== '';
        $gatePath = $gateConfigured ? $gatePath : '/run/eccube-private/passkey/turnstile.json';
        if ($gateRequired === '1' || $gateConfigured || is_file($gatePath)) {
            if (!$shopEdition) {
                $blockers['legacy_turnstile_adapter_required'] = true;
            } else {
                try {
                    $gate = (new \Plugin\PasskeySecurity\Resource\Turnstile\Configuration($gatePath))->data();
                    if (($gateConfigured && !is_file($gatePath)) || ($gateRequired === '1' && !$gate['enabled'])
                        || ($gate['enabled'] && $gate['hostname'] !== parse_url($legacy['origin'], PHP_URL_HOST))) {
                        throw new \RuntimeException('gate_configuration_mismatch');
                    }
                    hash_update($digest, json_encode($gate, JSON_THROW_ON_ERROR));
                } catch (\Throwable) {
                    $blockers['legacy_turnstile_configuration_invalid'] = true;
                }
            }
        }
        $fingerprint = hash_final($digest);
        $result = ['status'=>'checked', 'fingerprint'=>$fingerprint, 'totp'=>$totp,
            'credentials'=>$counts['plg_ps_credential'], 'mandatory_resets'=>count(array_filter(
                $rows['plg_ps_reset'] ?? [], static fn(array $row): bool => (int)$row['required'] === 1
            )), 'blockers'=>array_keys($blockers)];
        if ($expected === null) {
            return $result;
        }
        if (!hash_equals($fingerprint, $expected)) {
            throw new \DomainException('legacy_source_changed');
        }
        if ($blockers) {
            return ['status'=>'blocked'] + $result;
        }

        $this->settings->put('origin', $legacy['origin']);
        $this->settings->put('name', $legacy['name']);
        $this->settings->put('salt', bin2hex(random_bytes(32)));
        $this->settings->put('staff_required', '1');
        if ($shopEdition) {
            $this->settings->put('shop_edition', ShopEdition::ID);
        }
        $this->settings->put('legacy_identity', $this->config->sealLegacyIdentity($legacy['key']));
        $key = $this->config->key();
        foreach ($rows['plg_ps_factor'] ?? [] as $factor) {
            if ($factor['secret'] === '') {
                continue;
            }
            $secret = $this->decryptTotp($factor['secret'], $legacy['key']);
            try {
                $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
                $ciphertext = base64_encode($nonce.sodium_crypto_secretbox($secret, $nonce, $key));
                $affected = $this->db->update('plg_ps_factor', ['secret'=>$ciphertext], ['subject'=>$factor['subject']]);
                if ($affected !== 1) {
                    throw new \DomainException('legacy_totp_update_failed');
                }
            } finally {
                sodium_memzero($secret);
            }
        }
        $this->settings->put('profile', '1');
        return ['status'=>'applied'] + $result;
    }

    private function verifyTables(): void
    {
        $schema = $this->db->createSchemaManager();
        $names = array_keys(self::TABLES);
        foreach ([...$names, 'dtb_plugin', 'dtb_member', 'dtb_customer'] as $table) {
            $engine = $this->db->fetchOne(
                'SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?',
                [$table]
            );
            if ($engine !== 'InnoDB') {
                throw new \DomainException('legacy_innodb_tables_required');
            }
        }
        $columns = $schema->listTableColumns('plg_ps_credential');
        foreach (['label', 'created', 'revoked_at', 'revoked_reason'] as $name) {
            if (!isset($columns[$name])) {
                throw new \DomainException('legacy_schema_mismatch');
            }
        }
    }

    private function passwordHash(string $subject, string $lock): string|false
    {
        if (!preg_match('/^(member|customer):([1-9][0-9]*)$/D', $subject, $match)) {
            return false;
        }
        $table = $match[1] === 'member' ? 'dtb_member' : 'dtb_customer';
        return $this->db->fetchOne("SELECT password FROM $table WHERE id=?".$lock, [$match[2]]);
    }

    private function decryptTotp(string $encoded, string $key): string
    {
        $bytes = base64_decode($encoded, true);
        if ($bytes === false || strlen($bytes) < 41) {
            throw new \DomainException('legacy_totp_invalid');
        }
        $secret = sodium_crypto_secretbox_open(substr($bytes, 24), substr($bytes, 0, 24), $key);
        if ($secret === false) {
            throw new \DomainException('legacy_totp_key_mismatch');
        }
        return $secret;
    }

    private function verifySource(string $source): void
    {
        $root = realpath($source);
        if ($root === false || $source !== $root || !is_dir($root)) {
            throw new \DomainException('legacy_source_required');
        }
        foreach (self::SOURCE as $file => $digest) {
            $path = $root.'/'.$file;
            if (realpath($path) !== $path || !is_file($path) || !hash_equals($digest, hash_file('sha256', $path))) {
                throw new \DomainException('legacy_build_mismatch');
            }
        }
    }

    private function legacyConfiguration(string $configuration): array
    {
        $data = json_decode($this->privateFile($configuration), true, 8, JSON_THROW_ON_ERROR);
        if (!is_array($data) || array_keys($data) !== ['rp_id','origin','rp_name','key_file']
            || !is_string($data['origin']) || !is_string($data['rp_name']) || !is_string($data['key_file'])
            || PublicSettings::validateOrigin($data['origin']) !== $data['rp_id']
            || $data['rp_name'] === '' || strlen($data['rp_name']) > 80
            || preg_match('/[\x00-\x1f\x7f]/u', $data['rp_name']) !== 0) {
            throw new \DomainException('legacy_configuration_invalid');
        }
        $key = trim($this->privateFile($data['key_file']));
        if (!preg_match('/^[a-f0-9]{64}$/D', $key)) {
            throw new \DomainException('legacy_key_invalid');
        }
        return ['origin'=>$data['origin'], 'name'=>$data['rp_name'], 'key'=>hex2bin($key)];
    }

    private function privateFile(string $path): string
    {
        if (realpath($path) !== $path || !is_file($path)
            || str_starts_with($path, realpath($this->projectDir).'/')
            || (fileperms($path) & 0077) !== 0 || filesize($path) > 8192) {
            throw new \DomainException('legacy_private_file_required');
        }
        $bytes = file_get_contents($path);
        if ($bytes === false) {
            throw new \DomainException('legacy_private_file_required');
        }
        return $bytes;
    }
}
