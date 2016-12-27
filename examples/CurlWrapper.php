<?php

error_reporting(E_ALL); ini_set('display_errors', 1);

header('Content-type: text/html; charset=utf-8');

require_once __DIR__ . '/../src/TorCurlWrapper.php';

// initialize a new TorCurlWrapper object
$torcurl = new Dapphp\TorUtils\TorCurlWrapper('127.0.0.1', '9050');

// set cURL options as usual using TorCurlWrapper::setopt()
$torcurl->setopt(CURLOPT_USERAGENT, 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0');
$torcurl->setopt(CURLOPT_TIMEOUT, 15);
$torcurl->setopt(CURLOPT_HTTPHEADER,
    array(
        'Accept-Language: en-US,en;q=0.5',
        'DNT: 1',
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    )
);

// uncomment the follow lines to show verbose output from curl
//$torcurl->setopt(CURLOPT_VERBOSE, true);
//$torcurl->setopt(CURLOPT_STDERR, fopen('php://output', 'w'));

try {
    $torcurl->httpGet('https://check.torproject.org/');

    echo sprintf("Request to %s returned HTTP %d.<br><br>\n\n",
            $torcurl->getInfo()['url'], $torcurl->getHttpStatusCode());

    // show response headers in textarea
    echo "Response Headers:<br>\n<textarea style='width: 500px; height: 140px'>";

    foreach ($torcurl->getResponseHeaders() as $header => $value) {
        // loop over each header
        echo "{$header}: {$value}\n";
    }

    echo "</textarea><br><br>\n\n";

    // show response body in textarea
    echo "Response Body: (Content-Type: " . $torcurl->getInfo()['content_type'] . ")"
         ."<br>\n<textarea style='width: 98%; height: 500px'>" .
         htmlspecialchars($torcurl->getResponseBody()) .
         "</textarea><br><br>\n";

    //print_r($torcurl->getInfo());

    // Example post:
    /*
    $torcurl->httpPost(
        'http://example.com/form',
        http_build_query([ 'name' => 'Your Name', 'email' => 'Your Email', 'message' => 'Hello!' ])
    );
    // OR (sample file upload using CURLFile [PHP >= 5.5])
    $torcurl->httpPost(
        'http://example.com/upload',
        [
            'action' => 'upload',
            'name'   => 'Your Name',
            'file1'  => new CURLFile('/path/to/img.jpg', 'image/jpeg', 'file1'),
            'file2'  => new CURLFile('/path/to/img2.jpg', 'image/jpeg', 'file2'),
            'submit' => 'Submit',
        ]
    );
    */

} catch (\Exception $ex) {
    echo sprintf("Request to %s failed with error %d: %s\n",
            $torcurl->getInfo()['url'],
            $ex->getCode(),
            $ex->getMessage());

    // Inspect $torcurl->getInfo() for more details.
    // The request can fail for a number of reasons including but not limited
    // to: a broken Tor circuit, bad exit, network errors within Tor, etc.
}
