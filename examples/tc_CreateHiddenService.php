<?php

/**
 * Programatically create a new Tor Hidden Service.
 *
 * The hidden service stops running when the client disconnects from the
 * controller, or when Tor shuts down.
 *
 * The client can save the private key returned by the controller to restart
 * the service at a later time.  The ControlClient::ONION_FLAG_DETACH flag can
 * be set to tell the controller to keep the hidden service running after the
 * client disconnects from the controller.
 *
 * This example demonstrates both creating a new hidden service, and how to
 * restart the hidden service at the same address later by calling ADD_ONION
 * again with the key obtained after creating the service.
 *
 * Only v3 onion services are supported.
 */

// virtual port the Tor hidden service listens on
define('HIDDEN_SERVICE_PORT', 80);

// internal port hidden service forwards to
define('HIDDEN_SERVICE_TARGET', 80);

require_once 'common.php';

use Dapphp\TorUtils\ControlClient;
use Dapphp\TorUtils\ProtocolError;

// create a new ControlClient object for connecting to the controller
$tc = new ControlClient();

// Uncomment the line below to see controller commands send & responses
//$tc->setDebug(true);

try {
    $tc->connect(); // connect to 127.0.0.1:9051
    $tc->authenticate();
} catch (\Exception $ex) {
    echo "Failed to create Tor control connection: " . $ex->getMessage() . "\n";
    exit(1);
}

// The types of hidden services keys we can create. Only v3 hidden services are supported.
$keyTypes = [
    ControlClient::ONION_KEYTYPE_CURVE25519 => 'Hidden Service v3 (ED25519-V3)',
];

foreach($keyTypes as $keyType => $keyDesc) {

    try {
        echo "Attempting to create hidden service using $keyDesc key type: ";

        // define options for service creation
        $options = array(
            'KeyType' => ControlClient::ONION_KEYTYPE_NEW,  // default
            'KeyBlob' => $keyType, // create a NEW HS key of this type
            'Flags'   => 0, // option flags for service creation
            'Target'  => HIDDEN_SERVICE_TARGET, // local port the hidden service forwards to
        );

        // Note: acceptable flags are a bitwise combination of:
        ControlClient::ONION_FLAG_DETACH | ControlClient::ONION_FLAG_DISCARDPK | ControlClient::ONION_FLAG_BASICAUTH | ControlClient::ONION_FLAG_NONANON;

        // try to add the hidden service (throws ProtocolError if creation failed)
        $service = $tc->addHiddenService(HIDDEN_SERVICE_PORT, $options);

        echo "Hidden service created!\n\n" .
             "Address = {$service['ServiceID']}.onion\n" .
             "Key     = {$service['PrivateKey']}\n\n";

        break;

    } catch (ProtocolError $pe) {
        // failed to create an ed25519-v3 key *and* an older RSA1024 key :(
        echo "Failed to create hidden service: " . $pe->getMessage() . "\n";
        exit(1);
    } catch (\Exception $ex) {
        echo "Error: " . $ex->getMessage() . "\n";
        exit(1);
    }
}

echo "Press [Enter] to delete the service and re-create it by supplying the private key...";
fread(STDIN, 1);
echo "\n";

// delete the hidden service by supplying its onion address
$tc->delHiddenService($service['ServiceID']);

echo "Hidden service deleted.  Sleeping for 10 seconds before re-creating.\n";
for ($i = 10; $i > 0; --$i) {
    echo "$i   \r";
    sleep(1);
}
echo "      \n\n";

echo "Re-creating hidden service...\n";

// Re-create the service using whichever keytype was used to create the
// service initially.  ed25519 for newer Tor versions, RSA1024 for older.
$keyParts = explode(':', $service['PrivateKey'], 2);
$service['KeyType']    = $keyParts[0];
$service['PrivateKey'] = $keyParts[1];

// options for re-creating hidden service at a later date
$options = array(
    'KeyType' => $service['KeyType'],
    'KeyBlob' => $service['PrivateKey'],
    'Target'  => HIDDEN_SERVICE_TARGET,
    'Flags'   => ControlClient::ONION_FLAG_DISCARDPK,
);

try {
    // re-create the hidden service
    $service = $tc->addHiddenService(HIDDEN_SERVICE_PORT, $options);

    echo "Hidden service running at {$service['ServiceID']}.onion:" . HIDDEN_SERVICE_PORT . "\n\n";
} catch (ProtocolError $pe) {
    echo "Failed to create service!  " . $pe->getMessage() . "\n";
    exit(1);
}

echo "Press Control-C to terminate.\n";

// Run indefinitely, leaving the hidden service accessible until the Tor
// control client disconnects.

for (;;) {
    sleep(10);
}
