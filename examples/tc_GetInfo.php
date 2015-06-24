<?php

require_once 'common.php';

use Dapphp\TorUtils\ControlClient;
use Dapphp\TorUtils\ProtocolError;

$tc = new ControlClient();

// Uncomment line below to enable debug output showing client<->controller communication
//$tc->setDebug(true);

try {
    $tc->connect(); // connect to 127.0.0.1:9051
    $tc->authenticate();
} catch (\Exception $ex) {
    echo "Failed to create Tor control connection: " . $ex->getMessage() . "\n";
    exit;
}

// ask controller for tor version
$ver = $tc->getVersion();

echo "*** Connected ***\n*** Controller is running Tor $ver ***\n";

try {
    // get tor node's external ip, if known.
    // If Tor could not determine IP, an exception is thrown
    $address = $tc->getInfoAddress();
} catch (ProtocolError $pex) {
    $address = 'Unknown';
}

try {
    // get router fingerprint (if any) - clients will not have a fingerprint
    $fingerprint = $tc->getInfoFingerprint();
} catch (ProtocolError $pex) {
    $fingerprint = $pex->getMessage();
}

echo sprintf("*** Controller IP Address: %s  / Fingerprint: %s ***\n", $address, $fingerprint);

// ask controller how many bytes Tor has transferred
$read = $tc->getInfoTrafficRead();
$writ = $tc->getInfoTrafficWritten();

echo sprintf("*** Tor traffic (read / written): %s / %s ***\n", humanFilesize($read), humanFilesize($writ));

echo "\n";

try {
    // fetch info for this descriptor from controller
    $descriptor = $tc->getInfoDescriptor('drew010relay01');
    // if descriptor found, query directory info to get flags
    $dirinfo    = $tc->getInfoDirectoryStatus($descriptor->fingerprint);

    echo "== Descriptor Info ==\n" .
          "Nickname      : {$descriptor->nickname}\n" .
          "Fingerprint   : {$descriptor->fingerprint}\n" .
          "Running       : {$descriptor->platform}\n" .
          "Uptime        : " . uptimeToString($descriptor->getCurrentUptime(), false) . "\n" .
          "OR Address(es): " . $descriptor->ip_address . ':' . $descriptor->or_port;

    if (sizeof($descriptor->or_address) > 0) {
        echo ', ' . implode(', ', $descriptor->or_address);
    }
    echo "\n" .
          "Contact       : {$descriptor->contact}\n" .
          "BW (observed) : " . number_format($descriptor->bandwidth_observed) . " B/s\n" .
          "BW (average)  : " . number_format($descriptor->bandwidth_average) . " B/s\n" .
          "Flags         : " . implode(' ', $dirinfo->flags) . "\n\n";
} catch (ProtocolError $pe) {
    // doesn't necessarily mean the node doesn't exist
    // the controller may not have updated directory info yet
    echo $pe->getMessage(); // Unrecognized key "desc/name/drew010relay01
}

try {
    echo "Sending heartbeat signal to controller...";

    $tc->signal(ControlClient::SIGNAL_HEARTBEAT);
    // watch tor.log file for heartbeat message

    echo "OK";
} catch (ProtocolError $pe) {
    echo $pe->getMessage();
}

echo "\n\n";

$tc->quit();
