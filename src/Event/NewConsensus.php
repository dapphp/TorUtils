<?php

namespace Dapphp\TorUtils\Event;

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

class NewConsensus extends AsyncEvent
{
    /* @var \Dapphp\TorUtils\RouterDescriptor[] $descriptors */
    public $descriptors;

    protected $asyncEventName = 'NEWCONSENSUS';

    public function parse(ProtocolReply $eventReply, Parser $parser)
    {
        $this->descriptors = $parser->parseRouterStatus($eventReply);

        return $this;
    }

    public function __toString()
    {
        return sprintf(
            "New consensus network status arrived. There are %d usable relays.\n",
            count($this->descriptors)
        );
    }
}
