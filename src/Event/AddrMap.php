<?php

namespace Dapphp\TorUtils\Event;

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

class AddrMap extends AsyncEvent
{
    public $address;

    public $newAddress;

    public $expiry;

    public $error;

    public $expires;

    public $cached;

    protected $asyncEventName = 'ADDRMAP';

    public function parse(ProtocolReply $eventReply, Parser $parser)
    {
        $data = $parser->parseAddrMap($eventReply[0]);

        $this->address    = $data['ADDRESS'];
        $this->newAddress = $data['NEWADDRESS'];
        $this->expiry     = $data['EXPIRY'];
        $this->error      = ($data['error']) ?? null;
        $this->expires    = ($data['EXPIRES']) ?? null;
        $this->cached     = ($data['CACHED']) ?? null;

        return $this;
    }

    public function __toString()
    {
        return sprintf(
            "Mapped address: %s to %s (expires=%s)\n",
            $this->address,
            $this->newAddress,
            ($this->expires ? $this->expires : $this->expiry)
        );
    }
}
