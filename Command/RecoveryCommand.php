<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Command;

use Doctrine\DBAL\Connection;
use Plugin\PasskeySecurity\Resource\Runtime\Store;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\{InputArgument,InputInterface};
use Symfony\Component\Console\Output\OutputInterface;

/** No HTTP equivalent. A local operator must attest the out-of-band identity check. */
final class RecoveryCommand extends Command
{
    protected static $defaultName='passkey-security:recover-staff';
    public function __construct(private Store $store,private Connection $db,private string $projectDir){parent::__construct();}
    protected function configure():void
    {
        $this->addArgument('staff_id',InputArgument::REQUIRED)->addArgument('identity_check_file',InputArgument::REQUIRED)
            ->addArgument('private_ticket_output',InputArgument::REQUIRED);
    }
    private function privatePath(string $path,bool $existing):void
    {
        $parent=realpath(dirname($path));
        if (!$parent || $path!==$parent.'/'.basename($path) || is_link($path)
            || str_starts_with($path,realpath($this->projectDir).'/') || (fileperms($parent)&0077)!==0
            || ($existing?(!is_file($path)||realpath($path)!==$path||(fileperms($path)&0077)!==0||filesize($path)>4096):file_exists($path))) {
            throw new \RuntimeException('private_file_required');
        }
    }
    protected function execute(InputInterface $input,OutputInterface $out):int
    {
        $f=null;
        try{
            $id=(string)$input->getArgument('staff_id');$in=(string)$input->getArgument('identity_check_file');$path=(string)$input->getArgument('private_ticket_output');
            if (!preg_match('/^[1-9][0-9]*$/D',$id)) throw new \RuntimeException('invalid_staff');
            $hash=$this->db->fetchOne('SELECT password FROM dtb_member WHERE id=? AND work_id=1',[$id]);
            if (!is_string($hash)) throw new \RuntimeException('active_staff_required');
            $this->privatePath($in,true);$this->privatePath($path,false);
            $evidence=json_decode((string)file_get_contents($in),true,8,JSON_THROW_ON_ERROR);
            if (!is_array($evidence)) throw new \RuntimeException('invalid_evidence');
            $f=fopen($path,'x');if (!$f || !chmod($path,0600)) throw new \RuntimeException('private_output_failed');
            $this->db->transactional(function()use($id,$hash,$evidence,$f):void{
                $ticket=$this->store->recoverStaff('member:'.$id,$hash,$evidence,time());
                $body=json_encode($ticket,JSON_THROW_ON_ERROR)."\n";
                if(fwrite($f,$body)!==strlen($body)||!fflush($f))throw new \RuntimeException('private_output_failed');
                if(function_exists('fsync')&&!fsync($f))throw new \RuntimeException('private_output_failed');
            });
            $out->writeln('{"ok":true,"ticket_saved_privately":true,"all_old_factors_revoked":true,"password_change_required":true}');return 0;
        }catch(\Throwable $e){$out->writeln('{"ok":false,"reason":"staff_recovery_refused"}');return 1;}
        finally{if(is_resource($f))fclose($f);}
    }
}
