<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Symfony\Component\HttpFoundation\Session\SessionInterface;

final class Ceremony
{
    public function __construct(private Config $config, private Store $store) {}
    public static function encode(string $raw): string { return rtrim(strtr(base64_encode($raw), '+/', '-_'), '='); }
    public static function decode(string $encoded): string
    {
        if (strlen($encoded) > 65536 || !preg_match('/^[a-zA-Z0-9_-]+$/D', $encoded)) throw new \RuntimeException('security_binary_invalid');
        $raw = base64_decode(strtr($encoded, '-_', '+/'), true);
        if ($raw === false || self::encode($raw) !== $encoded) throw new \RuntimeException('security_binary_invalid');
        return $raw;
    }
    public function handle(string $subject): string { return hash_hmac('sha256', 'handle:'.$subject, $this->config->key(), true); }
    private function server(): \lbuchs\WebAuthn\WebAuthn
    {
        Config::dependencies(); $d = $this->config->data();
        return new \lbuchs\WebAuthn\WebAuthn($d['rp_name'], $d['rp_id'], ['none'], true);
    }
    public function options(SessionInterface $session, string $kind, string $purpose, ?string $subject, int $now): object
    {
        $server = $this->server();
        $rows = $subject ? $this->store->credentials($subject) : [];
        $ids = array_map(fn($c)=>self::decode($c['credential']), $rows);
        $args = $purpose === 'register'
            ? $server->getCreateArgs($this->handle((string)$subject), 'account-'.substr($this->config->digest((string)$subject), 0, 16), '店舗アカウント', 60, true, true, null, $ids)
            : $server->getGetArgs($ids, 60, true, true, true, true, true, true);
        $session->set('ps_ceremony', ['kind'=>$kind, 'purpose'=>$purpose, 'subject'=>$subject, 'ids'=>$ids,
            'challenge'=>self::encode($server->getChallenge()->getBinaryString()), 'expires'=>$now+300,
            'epoch'=>$this->store->epoch(),'generation'=>$subject!==null?$this->store->generation($subject):null]);
        return $args;
    }
    private function take(SessionInterface $session, string $kind, string $purpose, ?string $subject, int $now): array
    {
        $c = $session->remove('ps_ceremony'); // Consume BEFORE validation, including every failed response.
        if (!is_array($c) || $c['kind'] !== $kind || $c['purpose'] !== $purpose || $c['subject'] !== $subject
            || $c['expires'] < $now || $c['epoch'] !== $this->store->epoch()
            || ($subject!==null && ($c['generation']??-1)!==$this->store->generation($subject))) throw new \RuntimeException('security_challenge_rejected');
        return $c;
    }
    private function client(array $input): string
    {
        $raw = self::decode((string)($input['clientDataJSON'] ?? ''));
        $d = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        // Library accepts RP subdomains. This application requires an EXACT configured HTTPS origin.
        if (!is_array($d) || ($d['origin'] ?? '') !== $this->config->origin()
            || ($d['crossOrigin'] ?? false) !== false || isset($d['topOrigin'])) throw new \RuntimeException('security_origin_rejected');
        return $raw;
    }
    public function register(SessionInterface $s, string $kind, string $subject, array $input, int $now): int
    {
        $c = $this->take($s, $kind, 'register', $subject, $now);
        $d = $this->server()->processCreate($this->client($input), self::decode((string)($input['attestationObject'] ?? '')),
            self::decode($c['challenge']), true, true);
        if (!hash_equals($d->credentialId, self::decode((string)($input['id'] ?? '')))) throw new \RuntimeException('security_credential_id_mismatch');
        if ($d->isBackedUp && !$d->isBackupEligible) throw new \RuntimeException('security_backup_flags');
        return $this->store->register($subject, $d,$c['generation'],(string)($input['label']??''));
    }
    public function assertion(SessionInterface $s, string $kind, ?string $subject, array $input, int $now): array
    {
        $c = $this->take($s, $kind, 'assert', $subject, $now);
        $id = self::decode((string)($input['id'] ?? ''));
        $row = $this->store->credential($id);
        $generation=$this->store->generation($row['subject']);
        if (!str_starts_with($row['subject'], $kind.':') || ($subject !== null && $row['subject'] !== $subject)
            || ($subject !== null && !in_array($id, $c['ids'], true))) throw new \RuntimeException('security_credential_owner');
        $handle = $input['userHandle'] ?? null;
        if (($subject === null && !is_string($handle)) || ($handle !== null && !hash_equals($this->handle($row['subject']), self::decode($handle)))) {
            throw new \RuntimeException('security_user_handle_rejected');
        }
        $auth = self::decode((string)($input['authenticatorData'] ?? ''));
        if (strlen($auth) < 37 || ((ord($auth[32]) & 0x10) && !(ord($auth[32]) & 0x08))
            || (bool)(ord($auth[32]) & 0x08) !== (bool)$row['backup_eligible']) throw new \RuntimeException('security_backup_flags');
        $server = $this->server();
        $server->processGet($this->client($input), $auth, self::decode((string)($input['signature'] ?? '')),
            $row['public_key'], self::decode($c['challenge']), (int)$row['counter'], true, true);
        $this->store->counter($row, (int)$server->getSignatureCounter(),$generation);
        $this->store->audit($row['subject'], 'passkey_verified');
        return ['subject'=>$row['subject'],'generation'=>$generation];
    }
}
