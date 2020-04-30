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
    array('195.176.3.20',    'check-01.torproject.org'), /* DigiGesTor4e3 */
    array('185.220.103.4',   '1.1.1.1'), /* CalyxInstitute16 */
    array('185.220.103.4',   '9.9.9.9'), /* CalyxInstitute16 */
    array('185.220.101.220', 'check-01.torproject.org'), /* niftyguard */
    array('89.34.27.59',     'check-01.torproject.org'), /* Hydra2 */
    array('104.215.148.63',  'check-01.torproject.org'), /* not a relay */
    array('208.111.35.21',   '10.11.12.13'), // should time out
);

foreach($lookups as $lookup) {
    list($remoteIP, $server) = $lookup;

    try {
        // send DNS request to Tor DNS exit list service
        // returns true if $remoteIP is a Tor exit relay
        $isTor = TorDNSEL::IpPort(null, null, $remoteIP, $server);

        echo sprintf("Connection from %s *%s* a Tor exit relay.\n",
            $remoteIP, ($isTor ? 'is' : 'is NOT'));
    } catch (\Exception $ex) {
        echo sprintf("Query for %s failed. Error: %s\n",
            $remoteIP, $ex->getMessage());
    }
}
