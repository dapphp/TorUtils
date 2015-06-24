<?php

namespace Dapphp\TorUtils;

/**
 * ProtocolError exception class.
 *
 * This class extends the PHP \Exception class and is thrown if Tor control
 * connection error responses are received or a directory returns an error.
 *
 */
class ProtocolError extends \Exception
{
    /**
     * Get the status code of the controller protocol reply
     */
    public function getStatusCode()
    {
        return parent::getStatusCode();
    }
}
