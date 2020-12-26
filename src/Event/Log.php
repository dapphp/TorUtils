<?php

namespace Dapphp\TorUtils\Event;

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

abstract class Log extends AsyncEvent
{
    public $severity;
    public $data;

    public function parse(ProtocolReply $eventReply, Parser $parser)
    {
        $name = $this->getEventName();

        if (!preg_match('/^' . preg_quote($name) . ' /', $eventReply[0])) {
            throw new \Exception("Invalid log event for $name {$eventReply[0]}");
        }

        list($this->severity, $this->data) = explode(' ', $eventReply[0], 2);

        return $this;
    }

    public function __toString()
    {
        return sprintf("%s %s\n", $this->severity, $this->data);
    }
}
