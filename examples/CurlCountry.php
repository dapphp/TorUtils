<?php

require __DIR__ . '/../src/ControlClient.php';
require __DIR__ . '/../src/TorCurlWrapper.php';

// list of country codes to use
$countries = array('US', 'FR', 'RU', 'GB', 'CA');

// get new control client for connecting to Tor's control port
$tc = new Dapphp\TorUtils\ControlClient();

$tc->connect(); // connect
$tc->authenticate('password'); // authenticate

foreach($countries as $country) {
    $country = '{' . $country . '}'; // e.g. {US}

    $tc->setConf(array('ExitNodes' => $country)); // set config to use exit node from country

    // get new curl wrapped through Tor SOCKS5 proxy
    $curl = new Dapphp\TorUtils\TorCurlWrapper();
    $curl->setopt(CURLOPT_USERAGENT, 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) Gecko/20100101 Firefox 41.0');

    // make request - should go through exit node from specified country
    if ($curl->httpGet('http://whatismycountry.com')) {
        echo $curl->getResponseBody();
    }
}
