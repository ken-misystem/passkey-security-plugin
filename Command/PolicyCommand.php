<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Command;

use Doctrine\DBAL\Connection;
use Plugin\PasskeySecurity\Resource\Runtime\Store;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\{InputArgument, InputInterface};
use Symfony\Component\Console\Output\OutputInterface;

final class PolicyCommand extends Command
{
    protected static $defaultName = 'passkey-security:policy';
    public function __construct(private \Plugin\PasskeySecurity\Resource\Runtime\Config $compatibility, private Store $store, private Connection $db, private string $projectDir) { parent::__construct(); }
    protected function configure(): void
    {
        $this->addArgument('action', InputArgument::REQUIRED, 'staff-ticket')
            ->addArgument('staff_id', InputArgument::OPTIONAL)->addArgument('private_output', InputArgument::OPTIONAL);
    }
    protected function execute(InputInterface $input, OutputInterface $out): int
    {
        try {
            if (!$this->compatibility->shopEditionActive()) throw new \RuntimeException('legacy_profile_required');
            if ($input->getArgument('action') !== 'staff-ticket') throw new \RuntimeException('invalid_action');
            $id = (string)$input->getArgument('staff_id'); $path = (string)$input->getArgument('private_output');
            if (!preg_match('/^[1-9][0-9]*$/D', $id) || !$this->db->fetchOne('SELECT id FROM dtb_member WHERE id=? AND work_id=1', [$id])) throw new \RuntimeException('active_staff_required');
            $parent = realpath(dirname($path));
            if (!$parent || $path !== $parent.'/'.basename($path) || file_exists($path) || is_link($path)
                || str_starts_with($path, realpath($this->projectDir).'/') || (fileperms($parent)&0077) !== 0) throw new \RuntimeException('private_output_required');
            $f = fopen($path, 'x'); if (!$f) throw new \RuntimeException('private_output_failed');
            chmod($path, 0600);
            try { $ticket = $this->store->issueTicket('member:'.$id, time()); fwrite($f, $ticket."\n"); fflush($f); }
            finally { fclose($f); }
            $out->writeln('{"ticket_saved_privately":true,"expires_in_seconds":3600}'); return 0;
        } catch (\Throwable $e) { $out->writeln('{"ok":false,"reason":"policy_operation_refused"}'); return 1; }
    }
}
