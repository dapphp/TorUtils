<?php

require __DIR__ . '/common.php';

// list of country codes to use
$countries = array('US', 'FR', 'RU', 'GB', 'CA');

// get new control client for connecting to Tor's control port
$tc = new Dapphp\TorUtils\ControlClient();

$tc->connect(); // connect
$tc->authenticate(); // authenticate

foreach($countries as $country) {
    $country = '{' . $country . '}'; // e.g. {US}

    $tc->setConf(array('ExitNodes' => $country)); // set config to use exit node from country

    // get new curl wrapped through Tor SOCKS5 proxy
    $curl = new Dapphp\TorUtils\TorCurlWrapper();
    $curl->setopt(CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0');

    // make request - should go through exit node from specified country
    if ($curl->httpGet('https://whatismycountry.com/')) {
        echo "$country:\n";
        echo $curl->getResponseBody();
        echo "\n--\n\n";
    }
}
