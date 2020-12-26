<?php

namespace Dapphp\TorUtils\Event\Log;

use Dapphp\TorUtils\Event\Log;

class Debug extends Log
{
    public $severity;
    public $data;

    protected $asyncEventName = 'DEBUG';
}
