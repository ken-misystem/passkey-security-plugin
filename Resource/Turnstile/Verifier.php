<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Turnstile;
final class Verifier
{
    public function __construct(private Configuration $config,private Gateway $gateway){}
    public function check(mixed $token,string $action):bool
    {
        $c=$this->config->data();if(!$c['enabled'])return true;
        return $this->verifyKeys($c, $token, $action);
    }

    public function verifyKeys(array $c, mixed $token, string $action): bool
    {
        if(!is_string($token)||$token===''||strlen($token)>2048||preg_match('/[\x00-\x20\x7f]/',$token))return false;
        try{
            $d=$this->gateway->verify($c['secret_key'],$token);
            $at=is_string($d['challenge_ts']??null)?strtotime($d['challenge_ts']):false;
            return ($d['success']??false)===true&&($d['hostname']??null)===$c['hostname']&&($d['action']??null)===$action&&$at!==false&&$at<=time()+30&&$at>=time()-300;
        }catch(\Throwable $e){return false;}
    }
}
