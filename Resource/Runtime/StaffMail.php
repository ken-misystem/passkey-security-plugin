<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Eccube\Repository\BaseInfoRepository;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

final class StaffMail
{
    public function __construct(private StaffMailStore $store, private Config $config, private MailerInterface $mailer,
        private UrlGeneratorInterface $urls, private BaseInfoRepository $baseInfo) {}
    private function initialUrl(?int $memberId=null): string
    {
        $parts=parse_url($this->urls->generate($memberId===null?'ps_member':'admin_ps_staff_mail',$memberId===null?[]:['id'=>$memberId],UrlGeneratorInterface::ABSOLUTE_URL));
        $path=is_array($parts)?($parts['path']??null):null;
        if(!is_string($path)||!str_starts_with($path,'/')||str_starts_with($path,'//')
            ||preg_match('/[\\\\\x00-\x20\x7f]/',$path)||isset($parts['query'])||isset($parts['fragment']))throw new \RuntimeException('staff_mail_route_invalid');
        return $this->config->origin().$path;
    }
    /** CLI routers may return an absolute URL when enforcing HTTPS, even for ABSOLUTE_PATH. */
    private function confirmationUrl(bool $verify,string $token,bool $initial=false): string
    {
        $generated=$this->urls->generate($verify?'ps_staff_email_confirm':'ps_staff_password_confirm',[],UrlGeneratorInterface::ABSOLUTE_URL);
        $parts=parse_url($generated);
        $path=is_array($parts)?($parts['path']??null):null;
        if (!is_string($path) || !str_starts_with($path,'/') || str_starts_with($path,'//')
            || preg_match('/[\\\\\x00-\x20\x7f]/',$path) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new \RuntimeException('staff_mail_route_invalid');
        }
        // Discard router authority. Only the private, validated origin determines the destination.
        return $this->config->origin().$path.($verify&&$initial?'?registration=1':'').'#token='.rawurlencode($token);
    }
    /** Queue admission occurs after the HTTP response; no request can start a worker. */
    public function process(string $id,int $now): string
    {
        $store=$this->store->deliveryStore();
        try {
            $job=$store->claim($id,$now); if (!$job) return 'skipped';
            $p=$job['payload'];
            if($job['kind']==='enrollrequest'){
                $children=$store->initialRequestNotifications($p['login_id'],$id,(int)$p['requested_at'],$now,(string)($p['request_kind']??'initial'));
                $store->finish($id,$children?'sent':'ignored',$now);
                foreach($children as$child)$this->process($child,$now);
                return $children?'sent':'ignored'; // Notification jobs created; never automatic code issuance.
            }
            if ($job['kind']==='request') {
                $p=$store->resetMessage($p['address'],$now);
                if (!$p) { $store->finish($id,'ignored',$now); return 'ignored'; }
            }
            if($job['kind']==='enrollnotice'){
                $p=$store->initialRequestNotice($p,$now);
                if(!$p){$store->finish($id,'ignored',$now);return 'ignored';}
                $at=(new \DateTimeImmutable('@'.$p['requested_at']))->setTimezone(new \DateTimeZone('Asia/Tokyo'))->format('Y-m-d H:i:s T');
                $resume=($p['request_kind']??'initial')==='resume';
                $subject=$resume?'スタッフ登録の再開・復旧コード発行依頼':'スタッフの初回登録リンク・コード発行依頼';
                $text=$subject."を受け付けました。\n\n依頼日時：".$at."\nスタッフ：".$p['member_name'].
                    "\nログインID：".$p['member_login']."\n受付番号：".$p['request_id']."\n\n".
                    ($resume?"登録途中の中断・期限切れ、または認証器の復旧依頼です。初回コードを発行できない状態の場合は、管理担当者の復旧手順で対応してください。\n":"")."この通知は本人確認済みを意味しません。登録情報と別の連絡手段で本人確認し、".($resume?"管理担当者の復旧手順でコードを用意してください。対象スタッフの確認用画面：":"管理画面から登録リンクまたはコードを発行してください。")."\n".
                    $this->initialUrl($p['member_id'])."\n\n登録リンク・コードは自動発行していません。登録済みの認証器を紛失した場合は、初回発行で解除せず所定の復旧手順を使ってください。";
            } elseif ($job['kind']==='initial') {
                $p=$store->initialMessage($p,$now);
                if(!$p){$store->finish($id,'ignored',$now);return 'ignored';}
                if(($p['link_version']??null)===1){
                    $token=$store->initialLinkToken($p,$now);
                    $generated=$this->urls->generate('ps_staff_initial_link',[],UrlGeneratorInterface::ABSOLUTE_URL);
                    $parts=parse_url($generated);$path=is_array($parts)?($parts['path']??null):null;
                    if(!is_string($path)||!str_starts_with($path,'/')||str_starts_with($path,'//')||preg_match('/[\\\\\x00-\x20\x7f]/',$path)||isset($parts['query'])||isset($parts['fragment']))throw new \RuntimeException('staff_mail_route_invalid');
                    $url=$this->config->origin().$path.'#token='.rawurlencode($token);
                    $f=['expires'=>$p['expires']];
                    $expiry=(new \DateTimeImmutable('@'.$f['expires']))->setTimezone(new \DateTimeZone('Asia/Tokyo'))->format('Y/m/d H:i T');
                    $subject='スタッフの初回登録リンク';
                    $text="管理者が本人確認のうえ、初回登録リンクを発行しました。\nパスキーまたは認証アプリを登録してください。\n\n".$url.
                        "\n\n有効期限：".$expiry."（発行から1時間・1回限り）\nリンクを開き「登録を始める」を押してください。コードの転記やID・パスワードのログイン画面に戻る必要はありません。\n".
                        "登録操作の有効期限は画面に表示します。仮パスワードの変更や、認証アプリ登録時の現在のパスワード確認が必要な場合も、同じ画面で案内します。\n".
                        "期限切れの場合はリンク先の「新しい登録リンク・コードを依頼する」を選んでください。再発行後は最新のメールだけを使用してください。\n".
                        "メールが使えない場合は管理者にコードを別の方法で渡してもらってください。心当たりがなければ使用せず管理担当者へ連絡してください。";
                }else{
                $url=$this->initialUrl();
                $subject='スタッフの初回登録コード';
                $text="管理者がスタッフ用の初回登録コードを発行しました。\n\n".$p['ticket']."\n\n発行から1時間・1回限り有効です。\n".
                    $url."\nパスワードでログインし、このコードを確認してから、10分以内にパスキーまたは認証アプリを登録してください。\n".
                    "認証アプリの6桁コードとは別のコードです。再発行された場合は最新のメールだけを使用してください。\n心当たりがなければ使用せず管理担当者に連絡してください。";
                }
            } elseif ($job['kind']==='notice') {
                $subject='スタッフ認証情報の変更通知'; $text=$p['text'];
            } else {
                $verify=$job['kind']==='verify';
                // Fragment never reaches access logs or the Referer header. No Host-header URL generation.
                $url=$this->confirmationUrl($verify,$p['token'],(bool)($p['initial_registration']??false));
                $subject=$verify?'スタッフ用メールアドレスの確認':'スタッフのパスワード再設定';
                $text=($verify?'メールアドレスの確認':'パスワードの再設定')."を受け付けました。30分以内に以下のURLから手続きしてください。\n".$url.
                    "\n心当たりがなければ手続きせず管理担当者に連絡してください。パスキー・認証アプリは解除されません。";
            }
            $from=$this->baseInfo->get()->getEmail01();
            $this->mailer->send((new Email())->from($from)->to($p['address'])->subject($subject)->text($text));
            $store->finish($id,'sent',$now); return 'sent'; // Means queue admission, never SMTP delivery.
        } catch (\Throwable $e) {
            // Keep evidence and never retry a possibly accepted queue admission automatically.
            $store->finish($id,'uncertain',$now); return 'uncertain';
        } finally { $store->close(); }
    }
}
