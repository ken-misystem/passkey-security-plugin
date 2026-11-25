<?php
declare(strict_types=1);

namespace Plugin\PasskeySecurity\Resource\Runtime;

use Eccube\Repository\BaseInfoRepository;
use Symfony\Component\Asset\Packages;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/** Resolve storefront artwork from the installed EC-CUBE site. */
final class StorePresentation extends AbstractExtension
{
    public function __construct(
        private BaseInfoRepository $baseInfo,
        private Packages $assets,
        private string $publicDir,
    ) {}

    public function getFunctions(): array
    {
        return [new TwigFunction('passkey_store_appearance', $this->appearance(...))];
    }

    public function appearance(): array
    {
        try {
            $name = $this->baseInfo->get()?->getShopName();
        } catch (\Doctrine\DBAL\Exception) {
            $name = null;
        }
        return [
            'name' => is_string($name) && trim($name) !== '' ? $name : 'PasskeySecurity',
            'logo' => $this->existingAsset('user_data', 'img/logo.png'),
            'favicon' => $this->existingAsset('user_data', 'assets/img/common/favicon.ico'),
            'app_store' => $this->existingAsset('plugin', 'PasskeySecurity/assets/app-store.svg'),
            'google_play' => $this->existingAsset('plugin', 'PasskeySecurity/assets/google-play.svg'),
        ];
    }

    private function existingAsset(string $package, string $path): ?string
    {
        $local = rtrim($this->publicDir, '/').'/'.$package.'/'.$path;
        return is_file($local) && is_readable($local) ? $this->assets->getUrl($path, $package) : null;
    }
}
