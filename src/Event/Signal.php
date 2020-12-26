<?php

namespace Dapphp\TorUtils\Event;

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

class Signal extends AsyncEvent
{
    public $signal;

    protected $asyncEventName = 'SIGNAL';

    public function parse(ProtocolReply $eventReply, Parser $parser)
    {
        $parts = explode(' ', $eventReply[0], 2);

        list(, $this->signal) = $parts;

        return $this;
    }

    public function __toString()
    {
        return sprintf("%s signal received\n", $this->signal);
    }
}
