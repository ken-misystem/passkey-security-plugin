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
        $config=new Config($settings,(string)$container->get(\Eccube\Common\EccubeConfig::class)->get('kernel.secret'));
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
