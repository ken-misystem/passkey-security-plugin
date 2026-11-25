<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Turnstile;
class Gateway
{
    public function __construct(private ?Configuration $configuration = null) {}

    public function verify(string $secret,string $token):array
    {
        // Only this local socket is reachable from the isolated Web container.
        $s=@stream_socket_client('unix:///run/eccube-turnstile/verify.sock',$errno,$error,2);
        if(!$s)throw new \RuntimeException('turnstile_unavailable');
        try{
            stream_set_timeout($s, $this->configuration?->timeouts()['gateway'] ?? 10);
            $wire=json_encode(['secret'=>$secret,'response'=>$token],JSON_THROW_ON_ERROR)."\n";
            while($wire!==''){$n=fwrite($s,$wire);if(!$n)throw new \RuntimeException('turnstile_unavailable');$wire=substr($wire,$n);}
            $raw=fgets($s,8193);if(!is_string($raw)||!str_ends_with($raw,"\n")||strlen($raw)>8192)throw new \RuntimeException('turnstile_unavailable');
            $d=json_decode($raw,true,8,JSON_THROW_ON_ERROR);if(!is_array($d))throw new \RuntimeException('turnstile_unavailable');return $d;
        }finally{fclose($s);}
    }
}
