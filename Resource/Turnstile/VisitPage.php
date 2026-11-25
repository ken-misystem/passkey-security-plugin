<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Turnstile;

use Symfony\Component\HttpFoundation\Response;

/** A same-URL entry screen, not Cloudflare WAF clearance or an authentication grant. */
final class VisitPage
{
    public static function apply(Response $response, string $site, string $url, string $csrf, array $appearance): void
    {
        $nonce=base64_encode(random_bytes(24));
        $escape=static fn(string $s):string=>htmlspecialchars($s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
        $style=file_get_contents(__DIR__.'/visit.css');
        $script=file_get_contents(__DIR__.'/visit.js');
        $n=$escape($nonce);
        $name=$escape($appearance['name']);
        $favicon=$appearance['favicon']===null?'':'<link rel="icon" href="'.$escape($appearance['favicon']).'">';
        $logo=$appearance['logo']===null?$name:
            '<img class="store-logo" src="'.$escape($appearance['logo']).'" width="383" height="92" alt="'.$name.'">';
        $html='<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            .'<title>安全性を確認しています | '.$name.'</title>'.$favicon

            .'<style nonce="'.$n.'">'.$style.'</style></head><body><main id="ps-visit-screen"'
            .' data-visit="true" data-sitekey="'.$escape($site).'" data-visit-url="'.$escape($url).'" data-visit-csrf="'.$escape($csrf).'">'
            .'<header>'.$logo.'</header>'
            .'<section class="verification"><div class="spinner" aria-hidden="true"></div><p class="eyebrow">安心してお買い物いただくために</p>'
            .'<h1>安全性を確認しています</h1><p class="intro">接続を確認しています。確認が終わると、<br class="wide-only">ご覧になりたいページへ自動で進みます。</p>'
            .'<div id="visit-widget"></div><p id="visit-status" role="status" aria-live="polite">しばらくお待ちください。</p>'
            .'<button id="visit-retry" type="button" hidden>もう一度確認する</button>'
            .'<noscript><p class="noscript">この確認にはJavaScriptが必要です。ブラウザの設定で有効にし、このページを再読み込みしてください。</p></noscript>'
            .'<details><summary>確認が進まない場合</summary><ul><li>チェック欄が表示された場合は、画面の案内に従ってください。</li>'
            .'<li>通信環境や、ブラウザのJavaScript・Cookie設定をご確認ください。</li><li>解消しない場合は、時間をおいてお試しください。</li></ul></details>'
            .'</section><footer>'.$name.' <span>安全な接続の確認</span></footer></main>'
            .'<script id="ps-visit-script" nonce="'.$n.'">'.$script.'</script>'
            .'<script nonce="'.$n.'" src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=psVisitReady&amp;render=explicit" async defer></script></body></html>';
        // Do not advertise a temporary check screen as the indexed store page.
        $response->setStatusCode(503);
        $response->headers->set('Retry-After','60');
        $response->setContent($html);
        $response->headers->remove('Content-Length');
        $response->headers->remove('ETag');
        $response->headers->remove('Last-Modified');
        $response->headers->set('Cache-Control','no-store, private');
        $response->headers->set('Referrer-Policy','no-referrer');
        $response->headers->set('Content-Security-Policy',"default-src 'none'; script-src 'nonce-".$nonce."' https://challenges.cloudflare.com; style-src 'nonce-".$nonce."'; img-src 'self'; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    }
}
