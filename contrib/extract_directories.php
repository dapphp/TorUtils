<?php

/**
 * PHP script to extract the list of directory authorities from Tor's src/app/config/auth_dirs.inc
 * and print the list as a PHP array for inclusion in DirectoryClient.php
 *
 * To use, place a copy of the most recent auth_dirs.inc in the same directory as this file.
 *
 */

$file = __DIR__ . '/auth_dirs.inc';

if (is_readable($file)) {
    $config = file_get_contents($file);

    if (!preg_match('/^"([\w\d]+) orport=/ism', $config)) {
        die('Could not find directory authorities in auth_dirs.inc');
    }

    $dirs = $config;
    $dirs = explode(',', $dirs);

    printf("Exporting %d directory authorities\n", sizeof($dirs));

    foreach($dirs as $dir) {
        $dir = trim($dir);
        if ($dir == '') continue;

        if (preg_match('/"([\w\d]+) orport=(\d+)[^"]+"\s*(?:"v3ident=[\w\d]+\s*")?(?:\s*"ipv6=(\[[^\]]+]:\d+)\s*")?\s*"(.*?) (.*?)"/is', $dir, $match)) {
            echo "    '" . str_replace(' ', '', $match[5]) . "' => '" . $match[4] . "', // " . $match[1] . "\n";
        }
    }
    echo "\n";
} else {
    echo "$file does not exist or is not readable; skipping authorities.\n";
}

