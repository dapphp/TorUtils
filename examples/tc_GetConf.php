<?php

require_once 'common.php';

use Dapphp\TorUtils\ControlClient;
use Dapphp\TorUtils\ProtocolError;

$tc = new ControlClient();

try {
    $tc->connect(); // connect to 127.0.0.1:9051
    $tc->authenticate();
} catch (\Exception $ex) {
    echo "Failed to create Tor control connection: " . $ex->getMessage() . "\n";
    exit;
}

// Get configuration values for 4 Tor options
try {
    $config = $tc->getConf('BandwidthRate Nickname SocksPort ORPort');
    // $config is array where key is the option and value is the current setting

    foreach($config as $keyword => $value) {
        echo "Config value {$keyword} = {$value}\n";
    }
} catch (ProtocolError $pe) {
    echo 'GETCONF failed: ' . $pe->getMessage();
}

echo "\n";

// Get configuration values with non-existent values
// GETCONF fails if any unknown options are present
try {
    $config = $tc->getConf('ORPort NonExistentConfigValue DirPort AnotherFakeValue');
} catch (ProtocolError $pe) {
    echo 'GETCONF failed: ' . $pe->getMessage();
}

echo "\n\n";

// Read config values into array
$config = $tc->getConf('Log CookieAuthentication');
var_dump($config);

//$config['Log'] = 'notice stderr';
//$config['Log'] = 'notice file /var/log/tor/tor.log';

// SETCONF using previously fetched config values
$tc->setConf($config);

// SETCONF with non-existent option
// SETCONF fails and nothing is set if any unknown options are present
try {
    // add non-existent config value to array
    $config['IDontExist'] = 'some string value';
    $tc->setConf($config);
} catch (\Exception $ex) {
    echo $ex->getMessage() . "\n";
}

$tc->quit();
