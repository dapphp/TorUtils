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

    switch($event) {
        case 'ADDRMAP':
            echo sprintf(
                "Resolved %s.  Error: %s.  Address: %s\n",
                $data['ADDRESS'],
                (isset($data['error']) ? 'YES' : 'No'),
                $data['NEWADDRESS']
            );
            break;

        case 'INFO':
        case 'NOTICE':
        case 'WARN':
        case 'DEBUG':
            foreach($data->getReplyLines() as $replyLine) {
                echo sprintf("LOG: %s\n", $replyLine);
            }
            break;

        case 'CIRC':
            foreach($data as $circuit) {
                echo $circuit;
            }
            break;

        case 'SIGNAL':
            $signal = $data[0];
            echo $signal . "\n";
            break;

        default:
            echo "Got event $event\n";
            var_dump($data);
    }
});

// tell controller to notify of these events; could also pass events as an array
$tc->setEvents('ADDRMAP NS NEWCONSENSUS SIGNAL CONF_CHANGED STATUS_GENERAL CIRC INFO NOTICE WARN');

// enable debug output and logging to file so we can see events received
// $tc->setDebug(1)->setDebugOutputFile(fopen('/tmp/tor.txt', 'w+'));

while (true) {
    // when reading a reply, if an async event is received then the callback given
    // to setAsyncEventHandler will be called
    // after the event is processed the client will then re-attempt to read
    // reply back from the controller, if there is one.  Otherwise readReply blocks
    // until data is available

    $read = $tc->getInfoTrafficRead();
    $writ = $tc->getInfoTrafficWritten();

    echo "Traffic = $read / $writ                 \r";
    sleep(1);

    // $reply = $tc->readReply(); // blocks until reply received
    // unless you are ONLY reading events from the controller, don't call
    // readReply() without sending a command first, otherwise it could block
    // the script until an event is received.
    // When an asyncEventHandler function is supplied, events will always be
    // received and dispatched between other command data and responses but if
    // events are infrequently received, don't call readReply without having sent
    // a command first.

}

$tc->quit();

