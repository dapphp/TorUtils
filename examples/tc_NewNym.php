<?php

/**
 * Simple example showing how to send a signal to Tor to change your IP address
 */

require_once 'common.php';

use Dapphp\TorUtils\ControlClient;

$tc = new ControlClient();

try {
    $tc->connect(); // connect to 127.0.0.1:9051
    $tc->authenticate('password');
    $tc->signal(ControlClient::SIGNAL_NEWNYM);
    echo "Signal sent - IP changed successfully!\n";
} catch (\Exception $ex) {
    echo "Signal failed: " . $ex->getMessage() . "\n";
}

