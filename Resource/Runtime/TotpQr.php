<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

/** Encode only in memory, using EC-CUBE's installed TCPDF QR encoder. */
final class TotpQr
{
    public static function dataUri(string $uri): string
    {
        if (!str_starts_with($uri, 'otpauth://totp/') || strlen($uri) > 2048) {
            throw new \InvalidArgumentException('invalid_totp_provisioning_uri');
        }
        $matrix = (new \TCPDF2DBarcode($uri, 'QRCODE,M'))->getBarcodeArray();
        if (!$matrix || $matrix['num_rows'] !== $matrix['num_cols']) {
            throw new \RuntimeException('totp_qr_generation_failed');
        }
        // Four white modules on every side are required for reliable scanning.
        $size = (int) $matrix['num_rows'] + 8;
        $path = '';
        foreach ($matrix['bcode'] as $y => $row) {
            foreach ($row as $x => $dark) {
                if ($dark) $path .= 'M'.($x + 4).' '.($y + 4).'h1v1h-1z';
            }
        }
        // No URI/secret in descriptions, metadata, URLs, files or external services.
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '.$size.' '.$size.'" width="280" height="280" shape-rendering="crispEdges">'
            .'<path fill="#fff" d="M0 0h'.$size.'v'.$size.'H0z"/><path fill="#000" d="'.$path.'"/></svg>';
        return 'data:image/svg+xml;base64,'.base64_encode($svg);
    }
}
