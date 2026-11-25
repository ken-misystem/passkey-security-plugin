<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Turnstile;

use Symfony\Component\HttpFoundation\{IpUtils,Request};

/** Public, read-only catalogue access; never an authentication/Turnstile grant. */
final class SearchCrawler
{
    private const SOURCES = [
        'google'=>'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
        'bing'=>'https://www.bing.com/toolbox/bingbot.json',
    ];
    private const PATHS = [
        'homepage'=>'/', 'product_list'=>'/products/list',
        'help_guide'=>'/guide', 'help_about'=>'/help/about', 'help_privacy'=>'/help/privacy',
        'help_tradelaw'=>'/help/tradelaw', 'help_agreement'=>'/help/agreement',
    ];

    public static function allows(Request $request): bool
    {
        $path=getenv('PASSKEY_SEARCH_CRAWLER_POLICY');
        return self::matches($request, is_string($path)&&$path!==''?$path:__DIR__.'/search-crawlers.json', time());
    }

    /** Explicit file/clock inputs allow offline boundary tests; no request-controlled configuration. */
    public static function matches(Request $request, string $file, int $now): bool
    {
        try {
            if (!in_array($request->getMethod(), ['GET','HEAD'], true) || $request->isXmlHttpRequest()) return false;
            $route=(string)$request->attributes->get('_route');
            if ($route==='product_detail') {
                if (!preg_match('~^/products/detail/[1-9][0-9]*$~D',$request->getPathInfo())) return false;
            } elseif (!isset(self::PATHS[$route]) || self::PATHS[$route]!==$request->getPathInfo()) return false;
            // EC-CUBE mutates its query bag while preparing product-list defaults.
            // Inspect the original URL parameters, never those controller-added fields.
            $rawQuery=$request->server->get('QUERY_STRING','');
            if(!is_string($rawQuery)||strlen($rawQuery)>2048)return false;
            parse_str($rawQuery,$query);
            foreach ($query as $key=>$value) {
                if ($route!=='product_list' || !in_array($key,['category_id','orderby','pageno','disp_number'],true)
                    || !is_string($value) || !preg_match('/^[0-9]{1,5}$/D',$value)) return false;
            }
            $ua=$request->headers->get('User-Agent','');
            if (strlen($ua)>1024) return false;
            $google=preg_match('~(?:^|[ (;/])Googlebot(?:-Image)?/[0-9.]+(?:$|[ ;)])~D',$ua)===1;
            $bing=preg_match('~(?:^|[ (;/])bingbot/[0-9.]+(?:$|[ ;)])~D',$ua)===1;
            if ($google===$bing) return false;
            $provider=$google?'google':'bing';
            // Symfony accepts forwarded IPs only from the deployment's explicit trusted proxies.
            $ips=$request->getClientIps();
            if(count($ips)!==1 || !filter_var($ips[0],FILTER_VALIDATE_IP,FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE)) return false;
            if(!is_file($file)||is_link($file)||!is_readable($file)||filesize($file)>1048576) return false;
            $policy=json_decode(file_get_contents($file),true,32,JSON_THROW_ON_ERROR);
            if(($policy['format']??null)!==1 || !is_int($policy['fetched_at']??null) || !is_int($policy['expires_at']??null)
                || $policy['fetched_at']>$now || $policy['expires_at']<=$now
                || $policy['expires_at']<=$policy['fetched_at'] || $policy['expires_at']-$policy['fetched_at']>172800) return false;
            $data=$policy['providers'][$provider]??null;
            if(!is_array($data)||($data['source']??null)!==self::SOURCES[$provider]
                || !is_string($data['source_sha256']??null)||!preg_match('/^[a-f0-9]{64}$/D',$data['source_sha256'])
                || !is_array($data['cidrs']??null)||count($data['cidrs'])===0||count($data['cidrs'])>4096) return false;
            foreach($data['cidrs']as$cidr){
                if(!is_string($cidr)||!preg_match('~^([^/]+)/([0-9]{1,3})$~D',$cidr,$m))return false;
                if(!filter_var($m[1],FILTER_VALIDATE_IP,FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE))return false;
                $v6=str_contains($m[1],':');$mask=(int)$m[2];
                if($mask<($v6?32:16)||$mask>($v6?128:32))return false;
            }
            return IpUtils::checkIp($ips[0],$data['cidrs']);
        } catch (\Throwable $error) { return false; }
    }
}
