<?php
namespace Plugin\PasskeySecurity;
final class Nav implements \Eccube\Common\EccubeNav
{
    public static function getNav():array
    {
        return ['passkey_security'=>['name'=>'パスキー・認証設定','icon'=>'fa-key','children'=>[
            'self'=>['name'=>'自分のログイン方法','url'=>'ps_member'],
            'config'=>['name'=>'導入・必須化設定','url'=>'passkey_security_admin_config']]]];
    }
}
