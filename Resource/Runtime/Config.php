<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

/** Domain-separated key uses the existing application secret plus a per-install random salt. */
final class Config
{
    public function __construct(private PublicSettings $settings,private string $applicationSecret) {}
    public function data():array
    {
        $origin=$this->settings->get('origin')??'';
        $host=PublicSettings::validateOrigin($origin);
        $salt=$this->settings->get('salt');
        if(strlen($this->applicationSecret)<32||$this->applicationSecret==='<change.me>'
            ||!is_string($salt)||!preg_match('/^[a-f0-9]{64}$/D',$salt))throw new \RuntimeException('public_application_secret_required');
        return ['origin'=>$origin,'rp_id'=>$host,'rp_name'=>$this->settings->get('name')??'アカウント',
            'key'=>hash_hkdf('sha256',$this->applicationSecret,32,'eccube/PasskeySecurity/public/v1',hex2bin($salt))];
    }
    public function ready():bool{return $this->settings->ready();}
    public function key():string{return $this->data()['key'];}
    public function origin():string{return $this->data()['origin'];}
    public function digest(string $value):string{return hash_hmac('sha256',$value,$this->key());}
    public function __debugInfo():array{return ['secrets'=>'[redacted]'];}
    public static function dependencies():void{require_once dirname(__DIR__).'/dependencies/vendor/autoload.php';}
}
