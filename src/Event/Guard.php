<?php

namespace Dapphp\TorUtils\Event;

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

class Guard extends AsyncEvent
{
    const STATUS_NEW     = 'NEW';
    const STATUS_UP      = 'UP';
    const STATUS_DOWN    = 'DOWN';
    const STATUS_BAD     = 'BAD';
    const STATUS_GOOD    = 'GOOD';
    const STATUS_DROPPED = 'DROPPED';

    public $type;

    public $name;

    public $status;

    protected $asyncEventName = 'GUARD';

    public function parse(ProtocolReply $eventReply, Parser $parser)
    {
        $parts = explode(' ', $eventReply[0], 5);

        if (sizeof($parts) < 4) {
            throw new \Exception("GUARD reply incomplete; expect at least 4 parts");
        }

        $this->type = $parts[1];
        $this->name = $parts[2];
        $this->status = $parts[3];

        return $this;
    }

    public function __toString()
    {
        return sprintf(
            "%s guard status changed for %s to %s\n",
            ucfirst(strtolower($this->type)),
            $this->name,
            $this->status
        );
    }
}
