<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity;

use Eccube\Plugin\AbstractPluginManager;
use Psr\Container\ContainerInterface;
use Plugin\PasskeySecurity\Resource\Runtime\{Config,Store,PublicSettings};

final class PluginManager extends AbstractPluginManager
{
    public function install(array $meta,ContainerInterface $container)
    {
        $db=$container->get('doctrine')->getConnection();
        $settings=new PublicSettings($db);
        $hasMetadata = $settings->assertInstallable();
        $config=new Config($settings,(string)$container->get(\Eccube\Common\EccubeConfig::class)->get('kernel.secret'));
        if ($hasMetadata && $config->shopEditionActive()) {
            if (!$settings->ready() || !$settings->required()
                || $db->fetchOne("SELECT value FROM plg_ps_meta WHERE name='epoch'") === false) {
                throw new \RuntimeException('legacy_profile_not_ready');
            }
            $key = $config->shopEncryptionKey();
            sodium_memzero($key);
            $schema = $db->createSchemaManager();
            foreach (['plg_ps_staff_mailbox', 'plg_ps_staff_mail_enrollment', 'plg_ps_staff_mail_token', 'plg_ps_staff_mail_job'] as $table) {
                if ($schema->listTableColumns($table) === []) {
                    throw new \RuntimeException('legacy_staff_mail_schema_missing');
                }
            }
            $path = $_SERVER['TURNSTILE_CONFIG'] ?? $_ENV['TURNSTILE_CONFIG'] ?? getenv('TURNSTILE_CONFIG');
            $path = is_string($path) && $path !== '' ? $path : '/run/eccube-private/passkey/turnstile.json';
            $gate = (new \Plugin\PasskeySecurity\Resource\Turnstile\Configuration($path, $settings, $config))->data();
            if ($gate['enabled'] && $gate['hostname'] !== parse_url($config->origin(), PHP_URL_HOST)) {
                throw new \RuntimeException('legacy_turnstile_configuration_invalid');
            }
        }
        (new Store($db,$config))->install();$settings->install();
    }
    public function enable(array $meta,ContainerInterface $container)
    {
        // The EC-CUBE plugin service locator does not expose the request or token.
        // An authenticated administrator configures the origin explicitly.
    }
    public function update(array $meta,ContainerInterface $container){$this->install($meta,$container);}
    // No account/credential deletion, SMTP switching, forced password reset or worker startup.
}
