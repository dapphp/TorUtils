<?php

use Dapphp\TorUtils\TorDNSEL;

include __DIR__ . '/../src/TorDNSEL.php';

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

// Test lookups
// First array index is the remote IP (client/potential exit node)
// Second is the server IP
// Third is the server port
// Fourth is the DNS server to query
$lookups = array(
    array('208.111.35.21',   '1.2.3.4', 80, 'exitlist.torproject.org'),
    array('208.111.35.21',   '1.2.3.4', 80, '8.8.8.8'),
    array('208.113.166.5', '1.2.3.4', 80, 'exitlist.torproject.org'),
    array('208.113.166.5', '1.2.3.4', 80, 'exitlist.torproject.org'),
    array('197.231.221.211',  '1.2.3.4', 80, 'exitlist.torproject.org'),
    array('208.111.35.21',   '1.2.3.4', 80, '10.11.12.13'), // should time out
);

foreach($lookups as $lookup) {
    list($remoteIP, $myIp, $myPort, $server) = $lookup;

    try {
        // send DNS request to Tor DNS exit list service
        // returns true if $remoteIP is a Tor exit node that permits connections to $myIp:$myPort
        $isTor = TorDNSEL::IpPort($myIp, $myPort, $remoteIP, $server);

        echo sprintf("Connection to %s:%d from %s *%s* coming from a Tor exit node.\n",
            $myIp, $myPort, $remoteIP, ($isTor ? 'is' : 'is NOT'));
    } catch (\Exception $ex) {
        echo sprintf("Lookup of %s:%s for %s failed with error '%s'\n",
            $myIp, $myPort, $remoteIP, $ex->getMessage());
    }
}
