<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Command;

use Plugin\PasskeySecurity\Resource\Runtime\{StaffMail,StaffMailStore};
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\{InputArgument,InputInterface};
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name:'passkey-security:staff-mail',description:'Admit pending encrypted staff mail jobs, or request an identity-checked initial mailbox verification.')]
final class StaffMailCommand extends Command
{
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private StaffMailStore $store,private StaffMail $mail,private string $projectDir) { parent::__construct(); }
    protected function configure(): void
    {
        $this->addArgument('action',InputArgument::REQUIRED,'drain or bootstrap');
        $this->addArgument('private_identity_file',InputArgument::OPTIONAL,'Private evidence file, bootstrap only');
    }
    protected function execute(InputInterface $input,OutputInterface $output): int
    {
        try {
            if (!$this->compatibility->shopEditionActive()) throw new \RuntimeException('legacy_profile_required');
            if ($input->getArgument('action')==='drain') {
                $counts=['sent'=>0,'ignored'=>0,'uncertain'=>0,'skipped'=>0];
                foreach ($this->store->pending() as $id) ++$counts[$this->mail->process($id,time())];
                $output->writeln(json_encode(['ok'=>$counts['uncertain']===0,'queue_admission_only'=>true,'counts'=>$counts]));
                return $counts['uncertain']===0?0:1;
            }
            if ($input->getArgument('action')!=='bootstrap') throw new \RuntimeException('staff_mail_action_rejected');
            $path=(string)$input->getArgument('private_identity_file');$dir=dirname($path);
            if (realpath($path)!==$path || is_link($path) || !is_file($path) || (fileperms($path)&0777)!==0600
                || (fileperms($dir)&0077)!==0 || filesize($path)>4096 || str_starts_with($path,realpath($this->projectDir).'/')) throw new \RuntimeException('staff_mail_private_input_required');
            $e=json_decode(file_get_contents($path),true,8,JSON_THROW_ON_ERROR);
            if (array_keys($e)!==['subject','address','case_id','operator','method','verified_at']
                || !preg_match('/^member:[1-9][0-9]*$/D',$e['subject'])
                || !preg_match('/^[A-Za-z0-9_-]{8,80}$/D',$e['case_id']) || !preg_match('/^[A-Za-z0-9_-]{3,80}$/D',$e['operator'])
                || !in_array($e['method'],['known_channel_callback','in_person'],true) || !is_int($e['verified_at']) || $e['verified_at']>time() || $e['verified_at']<time()-900
                || $this->store->mailbox($e['subject'])) throw new \RuntimeException('staff_mail_identity_check_rejected');
            // Initial missing mailbox only. Does not change a verified mailbox, password, MFA or any account status.
            $this->store->verification($e['subject'],$e['address'],time());
            $output->writeln('{"ok":true,"mailbox_not_yet_verified":true,"queued_verification_only":true}');return 0;
        } catch (\Throwable $e) { $output->writeln('{"ok":false,"error":"staff_mail_operation_refused"}');return 1; }
    }
}
