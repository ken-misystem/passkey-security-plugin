<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Runtime;

use Psr\Log\LoggerInterface;

/** Operational metadata only. Logging failure never changes an authentication decision. */
final class ClockEventLog
{
    public function __construct(private LoggerInterface $logger){}

    public function rejected(\Throwable $error,string $component,string $realm,string $method):?string
    {
        if(!Policy::isClockFailure($error))return null;
        $incident=null;
        try{
            $incident=bin2hex(random_bytes(16));
            $sample=$error instanceof ClockRollbackException?$error:null;
            $this->logger->warning('passkey_security.clock_rollback',[
                'schema'=>1,'incident'=>$incident,'event'=>'clock_rollback','http_status'=>503,
                'component'=>in_array($component,['security','configure','guard'],true)?$component:'unknown',
                'realm'=>in_array($realm,['member','customer'],true)?$realm:'unknown',
                'method'=>in_array($method,['GET','HEAD','POST'],true)?$method:'OTHER',
                'point'=>$sample?->point??'unspecified','previous'=>$sample?->previous,'current'=>$sample?->current,
                'delta_seconds'=>$sample?$sample->current-$sample->previous:null,
                'observed_unix'=>\time(),'monotonic_ns'=>\hrtime(true),'pid'=>getmypid(),
                'result'=>'clock_check_rejected','state_verification'=>'required','automatic_retry'=>false,
            ]);
        }catch(\Throwable){
            // No exception object, SQL, input, URL or session in either output path.
            try{@error_log('PasskeySecurity clock_event_log_failed incident='.($incident??'unavailable'));}catch(\Throwable){}
        }
        return $incident;
    }
}
