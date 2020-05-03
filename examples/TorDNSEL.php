<?php

use Dapphp\TorUtils\TorDNSEL;

include __DIR__ . '/../src/TorDNSEL.php';

// Practical usage on a web server:
/*
try {
    if (TorDNSEL::isTor($_SERVER['SERVER_ADDR'])) {
        // do something special for Tor users
    } else {
        // not using Tor, educate them! :-D
    }
 } catch (\Exception $ex) {
     error_log("Tor DNSEL query failed: " . $ex->getMessage());
 }
*/

// Test lookups
// First array index is the remote IP (client/potential exit relay)
// second is the DNS server to use for the query (consider using your local caching resolver!)
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
        echo "[o] Checking $remoteIP using server $server...\n";

        // send DNS request to Tor DNS exit list service
        // returns true if $remoteIP is a Tor exit relay
        $isTor = TorDNSEL::isTor($remoteIP, $server);

        if ($isTor) {
            echo "[+] Tor exit relay: *YES*\n";
        } else {
            echo "[-] Tor exit relay: No\n";
            echo "[-] Fingerprint(s): N/A\n";
        }

        if ($isTor) {
            $fingerprints = TorDNSEL::getFingerprints($remoteIP, $server);

            if (!empty($fingerprints)) {
                echo sprintf(
                    "[+] Fingerprint(s): %s\n",
                    join(', ', $fingerprints)
                );
            } else { /* Service should return a fingerprint if address is an exit relay */ }
        }

        echo "\n";

    } catch (\Exception $ex) {
        echo sprintf("[!] Query failed: %s\n",
            $ex->getMessage());
    }
}
