<?php

require_once __DIR__ . '/../src/DirectoryClient.php';
require_once __DIR__ . '/../src/ControlClient.php';

function uptimeToString($seconds, $array = true)
{
    $units = array(
        'years'   => 31536000,
        'days'    => 86400,
        'hours'   => 3600,
        'minutes' => 60,
        'seconds' => 1
    );

    $return = array();

    foreach($units as $unit => $secs) {
        $num = intval($seconds / $secs);

        if ($num > 0) {
            $return[$unit] = $num;
        }
        $seconds %= $secs;
    }

    if ($array) {
        return $return;
    } else {
        $s = '';
        foreach($return as $unit => $value) {
            $s .= "$value $unit, ";
        }
        $s = substr($s, 0, -2);
        return $s;
    }
}

/*
Original author: http://jeffreysambells.com/2012/10/25/human-readable-filesize-php
*/
function humanFilesize($bytes, $decimals = 2) {
    $size = array('B','kB','MB','GB','TB','PB','EB','ZB','YB');
    $factor = floor((strlen($bytes) - 1) / 3);
    return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . @$size[$factor];
}
