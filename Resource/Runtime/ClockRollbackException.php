<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

/** Carries clock samples only; never attach the request, user, session or credentials. */
final class ClockRollbackException extends \UnexpectedValueException
{
    public readonly string $point;
    public function __construct(public readonly int $previous,public readonly int $current,string $point)
    {
        $this->point=in_array($point,['proof_check','password_check','password_hash'],true)?$point:'proof_check';
        parent::__construct('security_clock_rollback');
    }
}
