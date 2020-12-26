<?php

namespace Dapphp\TorUtils\Event\Log;

use Dapphp\TorUtils\Event\Log;

class Warn extends Log
{
    public $severity;
    public $data;

    protected $asyncEventName = 'WARN';
}
