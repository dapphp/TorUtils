<?php

namespace Dapphp\TorUtils\Event\Log;

use Dapphp\TorUtils\Event\Log;

class Err extends Log
{
    public $severity;
    public $data;

    protected $asyncEventName = 'ERR';
}
