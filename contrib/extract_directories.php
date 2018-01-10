<?php

/**
 * PHP script to extract the list of directory authorities and fallback
 * directories from Tor's src/or/config.c and src/or/fallback_dirs.c and print
 * the list as a PHP array for inclusion in DirectoryClient.php
 *
 * To use, place a copy of the most recent config.c and fallback_dirs.inc in
 * the same directory as this file.
 *
 */

$file = __DIR__ . '/config.c';

if (is_readable($file)) {
    $config = file_get_contents($file);

    if (!preg_match('/\*default_authorities\[\]\s+=\s+{(.*?)}/is', $config, $match)) {
        die('Could not find directory authorities in config.c');
    }

    $dirs = trim($match[1]);
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

$file = __DIR__ . '/fallback_dirs.inc';

if (is_readable($file)) {
    $fallbacks = file_get_contents($file);

    if (preg_match_all('/"(\d+\.\d+\.\d+\.\d+:\d+) orport=(\d+) id=([\w\d]+).*?nickname=([^\s]+)/is', $fallbacks, $matches)) {
        printf("Exporting %d fallback directories\n", sizeof($matches[0]));
        for ($i = 0; $i < sizeof($matches[0]); ++$i) {
            printf("    '%s' => '%s', // %s\n", $matches[3][$i], $matches[1][$i], $matches[4][$i]);
            //echo "    '" . $matches[3][$i] . "' => '" . $matches[1][$i] . "', // \n";
        }
    }
    echo "\n";
} else {
    echo "$file does not exist or is not readable; skipping fallback directories.\n";
}

