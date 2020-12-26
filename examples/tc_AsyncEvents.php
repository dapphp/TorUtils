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

// List of async events the client can receive AsyncEvent objects for, otherwise ProtocolReply objects are returned.
// To maintain compatibility with events added in later versions, callers must explicitly supply the events that are
// expected to be returned as TorUtils/Event/* objects vs. ProtocolReply objects. This helps ensure code doesn't break
// when future versions introduce new Event classes that are not recognized.
$knownEvents = [ 'ADDRMAP', 'GUARD', 'DEBUG', 'INFO', 'NOTICE', 'WARN', 'ERR', 'NEWCONSENSUS', 'STREAM', 'CIRC', 'BW', 'SIGNAL', ];
//$knownEvents = [ 'NS', 'NEWCONSENSUS', ];

// register anonymous function as the event handler for async events
$tc->setAsyncEventHandler(function($event, $data) {
    // depending on the $event - data may be an array or ProtocolReply object
    // for NS and NEWCONSENSUS events, $data is an array of RouterDescriptor objects keyed by fingerprint

    switch($event) {
        case 'ADDRMAP':
            // Address map event
            echo $data;
            break;

        case 'BW':
            // Bandwidth event
            echo $data;
            break;

        case 'INFO':
        case 'NOTICE':
        case 'WARN':
        case 'DEBUG':
            // Log event
            echo $data;
            break;

        case 'CIRC':
            // Circuit status event
            echo $data;
            break;

        case 'GUARD':
            echo $data;
            break;

        case 'NEWCONSENSUS':
            // New network consensus has arrived
            echo $data;
            break;

        case 'NS':
            // Network status changed
            echo $data;
            break;

        case 'STREAM':
            // Stream status event
            echo $data;
            break;

        case 'SIGNAL':
            echo $data;
            break;

        default:
            echo "Got event '$event'\n";
            var_dump($data);
    }

}, $knownEvents);

// tell controller to notify of these events; could also pass events as an array
$tc->setEvents(join(' ', array_filter($knownEvents, function($item) {
    return $item != 'DEBUG';
})));

// enable debug output and logging to file so we can see events received
// $tc->setDebug(1)->setDebugOutputFile(fopen('/tmp/tor.txt', 'w+'));

while (true) {
    // when reading a reply, if an async event is received then the callback given
    // to setAsyncEventHandler will be called
    // after the event is processed the client will then re-attempt to read
    // reply back from the controller, if there is one.  Otherwise readReply blocks
    // until data is available

    $tc->waitForEvent(60); // blocks until event data is received or timeout reached

    $uptime = $tc->getInfoUptime();
}

$tc->quit();

