<?php

namespace Dapphp\TorUtils\Event\Log;

use Dapphp\TorUtils\Event\Log;

class Info extends Log
{
    public $severity;
    public $data;

    protected $asyncEventName = 'INFO';
}
