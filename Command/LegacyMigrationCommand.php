<?php
declare(strict_types=1);

namespace Plugin\PasskeySecurity\Command;

use Plugin\PasskeySecurity\Resource\Runtime\LegacyShopMigration;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\{InputArgument, InputInterface, InputOption};
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'passkey-security:migrate-shop-068', description: 'Check or migrate the reviewed shop authentication data')]
final class LegacyMigrationCommand extends Command
{
    public function __construct(private LegacyShopMigration $migration)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('legacy-source', InputArgument::REQUIRED, 'Absolute path to the retained 0.6.8 source')
            ->addArgument('legacy-config', InputArgument::REQUIRED, 'Absolute path to the private legacy configuration')
            ->addOption('apply', null, InputOption::VALUE_REQUIRED, 'Fingerprint from the check, after stopping application traffic and workers');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $expected = $input->getOption('apply');
        if ($expected !== null && !preg_match('/^[a-f0-9]{64}$/D', $expected)) {
            $output->writeln('{"status":"refused","reason":"legacy_fingerprint_required"}');
            return self::INVALID;
        }
        try {
            $result = $this->migration->run($input->getArgument('legacy-source'), $input->getArgument('legacy-config'), $expected);
            $output->writeln(json_encode($result, JSON_THROW_ON_ERROR));
            return $result['blockers'] ? self::FAILURE : self::SUCCESS;
        } catch (\DomainException $error) {
            $output->writeln(json_encode(['status'=>'refused', 'reason'=>$error->getMessage()], JSON_THROW_ON_ERROR));
        } catch (\Throwable) {
            $output->writeln('{"status":"refused","reason":"legacy_migration_failed"}');
        }
        return self::FAILURE;
    }
}
