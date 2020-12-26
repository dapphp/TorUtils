<?php

namespace Dapphp\TorUtils\Event;

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

class StreamStatus extends AsyncEvent
{
    const STATUS_NEW         = 'NEW';
    const STATUS_NEWRESOLVE  = 'NEWRESOLVE';
    const STATUS_REMAP       = 'REMAP';
    const STATUS_SENTCONNECT = 'SENTCONNECT';
    const STATUS_SENTRESOLVE = 'SENTRESOLVE';
    const STATUS_SUCCEEDED   = 'SUCCEEDED';
    const STATUS_FAILED      = 'FAILED';
    const STATUS_CLOSED      = 'CLOSED';
    const STATUS_DETACHED    = 'DETACHED';

    public $streamId;

    public $streamStatus;

    public $circuitId;

    public $target;

    public $reason;

    public $remoteReason;

    public $source;

    public $sourceAddr;

    public $purpose;

    public $socksUsername;

    public $socksPassword;

    public $clientProtocol;

    public $nymEpoch;

    public $sessionGroup;

    public $isoFields;

    protected $asyncEventName = 'STREAM';

    public function parse(ProtocolReply $eventReply, Parser $parser)
    {
        if (strpos($eventReply[0], $this->asyncEventName) !== 0) {
            $what = substr($eventReply[0], 0, 6);
            throw new \InvalidArgumentException("Argument passed to StreamStatus::parse must begin with {$this->name}, got '$what'");
        }

        $parts = explode(' ', $eventReply[0], 6);

        list( , $id, $status, $circuitID, $target) = $parts;
        $extra = '';

        if (isset($parts[5])) {
            $extra = trim($parts[5]);
        }

        $this->streamId     = $id;
        $this->streamStatus = $status;
        $this->circuitId    = $circuitID;
        $this->target       = $target;

        if (!empty($extra)) {
            $fields = $parser->parseKeywordArguments($extra);

            foreach ($fields as $key => $value) {
                $key = $this->eventNameToProperty($key);
                $this->{$key} = $value;
            }
        }

        return $this;
    }

    public function __toString()
    {
        return sprintf(
            "STREAM (%d) / %s Circuit ID: %d   Target: %s\n",
            $this->streamId, $this->streamStatus, ($this->circuitId ?: 'N/A'), $this->target
        );
    }

}
