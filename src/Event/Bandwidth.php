<?php

namespace Dapphp\TorUtils\Event;

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

class Bandwidth extends AsyncEvent
{
    public $bytesRead;
    public $bytesWritten;
    public $type;
    public $num;

    protected $asyncEventName = 'BW';

    public function parse(ProtocolReply $eventReply, Parser $parser)
    {
        $name = $this->getEventName();

        if (strpos($eventReply[0], $name) !== 0) {
            $what = substr($eventReply[0], 0, 6);
            throw new \InvalidArgumentException("Argument passed to StreamStatus::parse must begin with $name, got '$what'");
        }

        $parts = explode(' ', $eventReply[0], 4);

        list( , $bytesRead, $bytesWritten) = $parts;

        $this->bytesRead    = $bytesRead;
        $this->bytesWritten = $bytesWritten;

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
            "BW (%d) in / (%s) out\n",
            $this->bytesRead, $this->bytesWritten
        );
    }
}
