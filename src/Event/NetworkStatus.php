<?php

namespace Dapphp\TorUtils\Event;

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

class NetworkStatus extends AsyncEvent
{
    /* @var \Dapphp\TorUtils\RouterDescriptor $descriptor */
    public $descriptor;

    protected $asyncEventName = 'NS';

    public function parse(ProtocolReply $eventReply, Parser $parser)
    {
        $descriptors = $parser->parseRouterStatus($eventReply);
        $this->descriptor = array_shift($descriptors);

        return $this;
    }

    public function __toString()
    {
        return sprintf(
            "Status changed for %s; flags=%s; weight=%s\n",
            $this->descriptor->nickname,
            join(', ', $this->descriptor->flags),
            $this->descriptor->bandwidth
        );
    }
}
