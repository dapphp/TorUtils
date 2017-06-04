<?php

require_once 'common.php';

use Dapphp\TorUtils\ControlClient;
use Dapphp\TorUtils\ProtocolError;
use Dapphp\TorUtils\DirectoryClient;

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
$rec = $tc->getInfoStatusVersionCurrent();
$cur = $tc->getInfoStatusVersionRecommended();

echo "*** Connected to controller***\n*** Controller is running Tor $ver ($rec) ***\n";
echo "Current recommended versions are: " . implode(', ', $cur) . "\n";
echo "\n";

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

$descriptor = null;
$relay      = 'MilesPrower'; // example relay for script

try {
    echo "Fetching relay info for $relay...\n\n";

    // Fetch info for this descriptor from controller.
    // Modern clients don't download full descriptors by default so use getInfoMicroDescriptor.
    // To fetch full info, set the Tor option FetchUselessDescriptors to 1 and call $tc->getInfoDescriptor() instead.
    // When using getInfoDescriptor(), there's no need to use the DirectoryClient below.
    // Microdescriptors include the nickname, onion key, ntor onion key, family, accept/reject rules, and the ed25519 id key
    $descriptor = $tc->getInfoMicroDescriptor($relay);

    // If descriptor found, query directory info to get flags.
    // Directory info is a reduced set of data including consensus data like
    // the consensus weight, relay flags (e.g. Exit, Guard, HSDir etc), the IP
    // and accept/reject list
    $dirinfo    = $tc->getInfoDirectoryStatus($relay);

    // combine the two RouterDescriptor objects from getInfoDescriptor and getInfoDirectoryStatus
    // into one object
    $descriptor->combine($dirinfo);

    // Unless FetchUselessDescriptors (see above) is enabled, uptime, bandwidth, contact info, and version can
    // only be fetched from the directory.
    // If FetchUselessDescriptors is enabled, this is not needed when calling getInfoDescriptor() instead of getInfoMicroDescriptor().
    $dc = new DirectoryClient();
    $dirinfo = $dc->getServerDescriptor($descriptor->fingerprint); // populates uptime, bandwidth, contact info, version

    $descriptor->combine($dirinfo);

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
          "Flags         : " . implode(' ', $descriptor->flags) . "\n\n";
} catch (ProtocolError $pe) {
    // doesn't necessarily mean the node doesn't exist
    // the controller may not have updated directory info yet
    echo $pe->getMessage() . "\n\n"; // Unrecognized key "desc/name/MilesPrower
}

try {
    echo "CIRCUITS\n";
    $circuits = $tc->getInfoCircuitStatus();

    if (sizeof($circuits) > 0) {
        foreach($circuits as $circuit) {
            /** @var $circuit \Dapphp\TorUtils\CircuitStatus */

            echo $circuit; // __toString
        }
    } else {
        echo "No active circuits established\n";
    }
} catch (\Exception $ex) {
    echo "Failed to get circuit status: " . $ex->getMessage() . "\n";
}
echo "\n";

try {
    echo "Sending heartbeat signal to controller...";

    $tc->signal(ControlClient::SIGNAL_HEARTBEAT);
    // watch tor.log file for heartbeat message

    echo "OK";
} catch (ProtocolError $pe) {
    echo $pe->getMessage();
}

echo "\n\n";

if ($descriptor) {
    try {
        $descriptor->country = $tc->getInfoIpToCountry($descriptor->ip_address);
    } catch (ProtocolError $pe) {
        echo "Failed to get IP country for relay at {$descriptor->ip_address}: " . $pe->getMessage() . "\n\n";
    }

    echo "Dumping raw RouterDescriptor object:\n";

    print_r($descriptor);
}

echo "Closing connection to controller\n";
$tc->quit();
