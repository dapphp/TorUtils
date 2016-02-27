<?php

require_once 'common.php';

use Dapphp\TorUtils\ControlClient;

$tc = new ControlClient();

// Uncomment line below to enable debug output
//$tc->setDebug(true);

try {
    $tc->connect(); // connect to 127.0.0.1:9051
    $tc->authenticate();
} catch (\Exception $ex) {
    echo "Failed to create Tor control connection: " . $ex->getMessage() . "\n";
    exit;
}

// register anonymous function as the event handler for async events
$tc->setAsyncEventHandler(function($event, $data) {
    // depending on the $event - data may be an array or ProtocolReply object
    // for NS and NEWCONSENSUS events, $data is an array of RouterDescriptor objects keyed by fingerprint
    echo "Got event $event\n\n";

    var_dump($data);
});

// tell controller to notify of these events; could also pass events as an array
$tc->setEvents('NS NEWCONSENSUS SIGNAL CONF_CHANGED STATUS_GENERAL');

// also subscribe to ADDRMAP event and then try to resolve some names
// resolution is done in the background and nofications sent as ADDRMAP events
$tc->setEvents('ADDRMAP')
   ->resolve(array('phpcaptcha.org', 'thepiratebay.se', 'www.torproject.org'));

// enable debug output and logging to file so we can see events received
// $tc->setDebug(1)->setDebugOutputFile(fopen('/tmp/tor.txt', 'w+'));

while (true) {
    // when reading a reply, if an async event is received then the callback given
    // to setAsyncEventHandler will be called
    // after the event is processed the client will then re-attempt to read
    // reply back from the controller, if there is one.  Otherwise readReply blocks
    // until data is available

    $reply = $tc->readReply(); // blocks until reply received
    sleep(1);
}

$tc->quit();

