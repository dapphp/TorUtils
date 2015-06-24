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

try {
    // send arbitrary command; use GETINFO command with 'entry-guards' parameter
    $tc->sendData('GETINFO entry-guards');

    // read and parse controller response into a ProtocolReply object
    $reply = $tc->readReply();

    // show the status code of the command, and output the raw response
    printf("Reply status: %d\n", $reply->getStatusCode());
    echo $reply . "\n\n"; // invokes __toString() to return the server reply

    // get an array of response lines
    $lines = $reply->getReplyLines();

    echo "Entry Guard(s):\n";

    for ($i = 1; $i < sizeof($lines); ++$i) {
        // iterate over each line skipping the first line which was the status
        // match the fingerprint, nickname, and router status of the entry guards
        if (preg_match('/\$?([\w\d]{40})(~|=)([\w\d]{1,19}) ([\w-]+)/', $lines[$i], $match)) {
            echo "  Nickname = '{$match[3]}' / Fingerprint = '{$match[1]}' / Status = '{$match[4]}'\n";
        } else {
            echo "  {$lines[$i]}\n";
        }
    }

    echo "\n";
} catch (ProtocolError $pe) {
    echo sprintf(
        "Command failed: Controller reponse %s: %s\n",
        $pe->getStatusCode(),
        $pe->getMessage()
    );
}

// send unrecognized command - check whether reply was successful
$tc->sendData('FAKE_COMMAND data data data');

// read the reply
$reply = $tc->readReply();

// isPositiveReply returns true if the command returned a successful response.
if (false == $reply->isPositiveReply()) {
    // show the status code and reply from the controller
    echo "Command failed: " . $reply->getStatusCode() . ' ' . $reply[0] . "\n";

    // yields: Command failed: 510 Unrecognized command "FAKE_COMMAND"
}

echo "\n";

$tc->quit();
