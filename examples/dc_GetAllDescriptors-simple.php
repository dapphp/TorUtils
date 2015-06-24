<?php

require_once 'common.php';

use Dapphp\TorUtils\DirectoryClient;

$client = new DirectoryClient();

$descriptors = $client->getAllServerDescriptors();

echo sprintf("We know about %d descriptors.\n\n", sizeof($descriptors));

foreach($descriptors as $descriptor) {
    echo sprintf("%-19s %s %16s:%s\n", $descriptor->nickname, $descriptor->fingerprint, $descriptor->ip_address, $descriptor->or_port);

    echo sprintf("Running: %s\n", $descriptor->platform);
    echo sprintf("Uptime:  %s\n", uptimeToString($descriptor->getCurrentUptime(), false));
    echo sprintf("Contact: %s\n", $descriptor->contact);
    echo sprintf("Bandwidth (avg / burst / observed): %d / %d / %d\n", $descriptor->bandwidth_average, $descriptor->bandwidth_burst, $descriptor->bandwidth_observed);

    if (sizeof($descriptor->or_address) > 0)
        echo sprintf("OR Address: %68s\n", implode(', ', $descriptor->or_address));

    echo sprintf(
        "Exit Policy:\n  accept: %s\n  reject: %s\n",
        isset($descriptor->exit_policy4['accept']) ? implode(' ', $descriptor->exit_policy4['accept']) : '',
        implode(' ', $descriptor->exit_policy4['reject'])
    );

    echo str_pad('', 80, '-') . "\n";
}
