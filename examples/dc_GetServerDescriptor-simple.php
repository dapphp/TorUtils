<?php

require_once 'common.php';

use Dapphp\TorUtils\DirectoryClient;

$client = new DirectoryClient();
//$client->setPreferredServer('1.2.3.4:80'); // Optional server to always use first for directory lookups

try {
    $descriptor = $client->getServerDescriptor('79E169B25E4C7CE99584F6ED06F379478F23E2B8');
} catch (\Exception $ex) {
    echo "Request to directory failed: " . $ex->getMessage() . "\n";
    exit;
}

echo sprintf("%-19s %40s\n", $descriptor->nickname, $descriptor->fingerprint);
echo sprintf("Running %s\n", $descriptor->platform);
echo sprintf("Online for %s\n", uptimeToString($descriptor->getCurrentUptime(), false));
echo sprintf("OR Address: %s:%s", $descriptor->ip_address, $descriptor->or_port);

if ($descriptor->or_address) {
    foreach ($descriptor->or_address as $address) {
        echo ", $address";
    }
}
echo "\n";

echo sprintf("Exit Policy:\n  Accept:\n    %s\n  Reject:\n    %s\n",
             implode("\n    ", $descriptor->exit_policy4['accept']),
             implode("\n    ", $descriptor->exit_policy4['reject'])
);
