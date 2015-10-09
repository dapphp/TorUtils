<?php

use Dapphp\TorUtils\TorDNSEL;

include '../src/TorDNSEL.php';

// Test lookups
// First array index is the remote IP (client/potential exit node)
// Second is the server IP
// Third is the server port
// Fourth is the DNS server to query
$lookups = array(
    array('208.111.35.21',   '50.76.51.20', 80, 'exitlist.torproject.org'),
    array('208.111.35.21',   '50.76.51.20', 80, '10.11.12.13'),
    array('208.111.35.21',   '50.76.51.20', 80, '8.8.8.8'),
    array('104.237.152.195', '50.76.51.20', 80, 'exitlist.torproject.org'),
    array('104.237.152.195', '50.76.51.20', 80, 'exitlist.torproject.org'),
    array('185.72.177.105',  '50.76.51.20', 80, 'exitlist.torproject.org'),
);

foreach($lookups as $lookup) {
    list($remoteIP, $myIp, $myPort, $server) = $lookup;

    try {
        // send DNS request to Tor DNS exit list service
        // returns true if $remoteIP is a Tor exit node that permits connections to $myIp:$myPort
        $isTor = TorDNSEL::IpPort($myIp, $myPort, $remoteIP, $server);

        echo sprintf("Connection to %s:%d from %s *%s* coming from a Tor exit node.\n",
            $myIp, $myPort, $remoteIP, ($isTor ? 'is' : 'is not'));
    } catch (\Exception $ex) {
        echo sprintf("Lookup of %s:%s for %s failed with error '%s'\n",
            $myIp, $myPort, $remoteIP, $ex->getMessage());
    }
}

// Practical usage on a web server:
/*
try {
    $isTor = TorDNSEL::IpPort(
        $_SERVER['SERVER_ADDR'],
        $_SERVER['SERVER_PORT'],
        $_SERVER['REMOTE_ADDR']
    );
    var_dump($isTor);
} catch (\Exception $ex) {
    echo $ex->getMessage() . "\n";
}
*/
