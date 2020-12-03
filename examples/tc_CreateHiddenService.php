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
 * Since the hidden service version 3 protocol (224-rend-spec-ng.txt) was
 * introduced, this example tries to create a newer v3 hidden service first
 * (using an ed25519 key).  If v3 is not supported by the Tor version and/or
 * control port, it will fall back to a v2 hidden service RSA1024 key.
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

// the types of hidden services keys we can create
$keyTypes = [
    ControlClient::ONION_KEYTYPE_CURVE25519 => 'Hidden Service v3 (ED25519-V3)',
    //ControlClient::ONION_KEYTYPE_RSA1024    => 'Hidden Service v2 (RSA1024)' // Obselete
];

foreach($keyTypes as $keyType => $keyDesc) {
    // Try to create a newer hidden service v3 ed25519 key first, then fall back to older RSA1024 keys.
    // Release 0.3.2.9 introduced hidden service v3 protocol, but the control port did not support
    // adding them with ADD_ONION until a later version (0.3.3.x-stable?).  Older clients will not support this method.

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
        echo "Failed to create hidden service: " . $pe->getMessage() . "\n";
        if ($keyType == ControlClient::ONION_KEYTYPE_RSA1024) {
            // failed to create an ed25519-v3 key *and* an older RSA1024 key :(
            exit(1);
        }
    } catch (Exception $ex) {
        echo "Error: " . $ex->getMessage() . "\n";
        exit(1);
    }
}

echo "Press [Enter] to delete the service and re-create it by suppling the private key...";
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
