<?php

namespace Dapphp\TorUtils\Event\Log;

use Dapphp\TorUtils\Event\Log;

class Notice extends Log
{
    public $severity;
    public $data;

    protected $asyncEventName = 'NOTICE';
}
