<?php

namespace Dapphp\TorUtils\Event;

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

abstract class AsyncEvent
{
    public function __construct()
    {

    }

    abstract public function parse(ProtocolReply $eventReply, Parser $parser);

    public function getEventName()
    {
        return $this->asyncEventName;
    }

    public function eventNameToProperty($key)
    {
        return preg_replace_callback(
            '/_(.)/',
            function($m) {
                return strtoupper($m[1]);
            },
            strtolower($key)
        );
    }
}
