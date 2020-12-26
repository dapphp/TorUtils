<?php

require_once 'common.php';

use Dapphp\TorUtils\ControlClient;
use Dapphp\TorUtils\TorCurlWrapper;
use Dapphp\TorUtils\Event\StreamStatus;

$tc = new ControlClient();

$clients = [];
$targets = [];
$urls = [
    'https://ip.me/',
    'https://openinternet.io/tor/ip.php',
    'https://donate.torproject.org/',
    'https://ipv6.google.com/',
];

// Uncomment line below to enable debug output
$tc->setDebug(true);

try {
    $tc->connect(); // connect to 127.0.0.1:9051
    $tc->authenticate();
} catch (\Exception $ex) {
    echo "Failed to create Tor control connection: " . $ex->getMessage() . "\n";
    exit;
}

$streamIds  = [];
$circuitIds = [];

$tc->setAsyncEventHandler(function($event, $data) use(&$targets, &$streamIds, &$circuitIds) {
    /** @var $data \Dapphp\TorUtils\Event\StreamStatus */

    if ($data->streamStatus == StreamStatus::STATUS_SENTCONNECT) {
        //var_dump($data);
        if (array_key_exists($data->target, $targets)) {
            $streamIds[$data->target]  = $data->streamId;
            $circuitIds[$data->target] = $data->circuitId;
        }
    }
}, [ 'STREAM' ]);

$tc->setEvents('STREAM');

foreach($urls as $url) {
    list($client, $target) = getTorClientWithCircuit($url, sha1($url . microtime(true)));
    $clients[$target] = $client;
    $targets[$target] = $url;
}

foreach($targets as $target => $url) {
    /** @var \Dapphp\TorUtils\TorCurlWrapper $client */
    $client = $clients[$target];

    echo "Trying $url...";

    try {
        $client->httpGet($url);
        echo $client->getHttpStatusLine(), "\n\n";

        //echo "Got response ==========\n";
        //echo $client->getResponseBody(), "\n";
        //echo "End response ==========\n\n";
    } catch (\Exception $ex) {
        echo sprintf("Request failed: %s\n", $ex->getMessage());
    }
}

$circuits = $tc->getInfoCircuitStatus();

if (empty($streamIds) || empty($circuitIds) === null) {
    die("Couldn't find any stream or circuit IDs for any target hosts in Tor events.\n");
}

$siteCircuits = [];

foreach($circuits as $circuit) {
    /** @var \Dapphp\TorUtils\CircuitStatus $circuit */

    foreach($circuitIds as $target => $circuitId) {
        if ($circuit->id == $circuitId) {
            $siteCircuits[$target] = $circuit;
            break;
        }
    }
}

//var_dump($streamIds, $circuitIds, $siteCircuits);

if (!empty(($missing = array_diff_key($circuitIds, $siteCircuits)))) {
    die(sprintf("Didn't find circuit for target(s) %s from circuit-status events!\n", join(', ', array_keys($missing))));
}

foreach(array_keys($targets) as $target) {
    $guard  = $siteCircuits[$target]->path[0];
    $middle = $siteCircuits[$target]->path[1];
    $exit   = $siteCircuits[$target]->path[2];

    $guardInfo = $tc->getInfoDirectoryStatus($guard['fingerprint']);
    $middleInfo = $tc->getInfoDirectoryStatus($middle['fingerprint']);
    $exitInfo = $tc->getInfoDirectoryStatus($exit['fingerprint']);

    try {
        $guardInfo->country = $tc->getInfoIpToCountry($guardInfo->ip_address);
    } catch (\Dapphp\TorUtils\ProtocolError $perr) {
        $guardInfo->country = 'Country Unknown';
    }
    try {
        $middleInfo->country = $tc->getInfoIpToCountry($middleInfo->ip_address);
    } catch (\Dapphp\TorUtils\ProtocolError $perr) {
        $middleInfo->country = 'Country Unknown';
    }
    try {
        $exitInfo->country = $tc->getInfoIpToCountry($exitInfo->ip_address);
    } catch (\Dapphp\TorUtils\ProtocolError $perr) {
        if (strpos($perr->getMessage(), 'GeoIP data not loaded') !== false) {
            $exitInfo->country = 'Country Unknown';
        } else {
            echo "Error getting geo information: " . $perr->getMessage() . "\n";
            exit;
        }
    }

    echo sprintf("== Circuit path for $target ==\n");
    echo sprintf("%s\n", str_repeat('-', 80));
    echo sprintf("  %20s: %-15s (%s) Guard\n", $guardInfo->nickname, $guardInfo->ip_address, $guardInfo->country);
    echo sprintf("  %20s: %-15s (%s)\n", $middleInfo->nickname, $middleInfo->ip_address, $middleInfo->country);
    echo sprintf("  %20s: %-15s (%s)\n", $exitInfo->nickname, $exitInfo->ip_address, $exitInfo->country);
    echo "\n\n";
}

$tc->quit();



function getTorClientWithCircuit($url, $password = 'azkaban')
{
    try {
        $torCurl = new TorCurlWrapper();
    } catch (\Exception $ex) {
        echo "Error creating TorCurlWrapper: " . $ex->getMessage() . "\n";
        exit(2);
    }

    $parsed = parse_url($url);

    if (!@$parsed['port']) {
        if ($parsed['scheme'] == 'https') {
            $parsed['port'] = 443;
        } elseif ($parsed['scheme'] == 'http') {
            $parsed['port'] = 80;
        } else {
            die("URL must use http or https protocol.\n");
        }
    }

    $target = $parsed['host'] . ':' . $parsed['port'];

    $torCurl->setopt(CURLOPT_PROXYUSERPWD, sprintf('%s:%s', urlencode($target), urlencode($password)));

    return [ $torCurl, $target ];
}
