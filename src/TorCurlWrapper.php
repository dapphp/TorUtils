<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     TorCurlWrapper.php
 *
 * Copyright (c) 2015, Drew Phillips
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Any modifications to the library should be indicated clearly in the source code
 * to inform users that the changes are not a part of the original software.
 *
 * @copyright 2015 Drew Phillips
 * @author Drew Phillips <drew@drew-phillips.com>
 *
 */

namespace Dapphp\TorUtils;

/**
 * curl wrapper for Tor SOCKS proxy
 *
 * A class to wrap curl requests through Tor using SOCKS5 with hostname resolution
 *
 * @version    2.0
 * @author     Drew Phillips <drew@drew-phillips.com>
 *
 */
class TorCurlWrapper
{
    private $ch;
    private $info;
    private $statusLine;
    private $responseHeaders;
    private $responseBody;
    private $socksHost;
    private $socksPort;
    private $socks5HostnameSupport = true;
    private $allowUnsafeDnsResolution = false;

    /**
     * TorCurlWrapper constructor.
     *
     * Creates a new TorCurlWrapper and initializes a curl handle with Tor
     * as the SOCKS proxy.  Defaults to 127.0.0.1:9050
     *
     * By default, TorCurlWrapper will have curl track cookies across requests but does not save them.
     * Override this behavior by calling TorCurlWrapper::setopt(CURLOPT_COOKIEJAR|CURLOPT_COOKIEFILE, $value)
     *
     * Other default behavior:
     * - Enables CURLOPT_AUTOREFERER by default
     * - Enables CURLOPT_FOLLOWLOCATION by default
     * - Tells curl to send Accept-Encoding headers with supported encodings (e.g. gzip, deflate)
     *
     * Intelligently tries to get curl to resolve DNS names through Tor, or
     * emits a warning if DNS resolution over Tor is not supported.
     *
     * Example:
     * <code>
     * $torcurl = new Dapphp\TorUtils\TorCurlWrapper('127.0.0.1:9050');
     * // OR
     * $torcurl = new Dapphp\TorUtils\TorCurlWrapper('127.0.0.1', 9050);
     *
     * $torcurl->setopt(CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 6.1; rv:38.0) Gecko/20100101 Firefox/38.0');
     *
     * try {
     *     $torcurl->httpGet('https://check.torproject.org/');
     *
     *     $http_status = $torcurl->getHttpStatusCode();
     *     print_r($torcurl->getResponseBody());
     * } catch (\Exception $ex) {
     *     echo "Request failed.  Curl error " . $ex->getCode() . ": " . $ex->getMessage();
     * }
     * </code>
     *
     * @param string $proxy The address of Tor's SOCKS proxy
     * @param int $port The port of Tor's SOCKS proxy
     * @throws \Exception
     */
    public function __construct(string $proxy = '127.0.0.1', int $port = 9050)
    {
        if (!extension_loaded('curl')) {
            throw new \Exception('curl extension is not loaded');
        }

        $ch = curl_init();

        if (strpos($proxy, ':') !== false) {
            list($proxy, $port) = explode(':', $proxy, 2);
            $port = intval($port);
        }

        $this->socksHost = $proxy;
        $this->socksPort = $port;
        $proxyType       = CURLPROXY_SOCKS5_HOSTNAME;

        $curlVersion = curl_version();
        if (version_compare($curlVersion['version'], '7.18.0') < 0) {
            // curl version does not support DNS resolution over socks
            $proxyType = CURLPROXY_SOCKS5;
            $this->socks5HostnameSupport = false;
        }

        $curlOptions = [
            CURLOPT_PROXY => $proxy,
            CURLOPT_PROXYPORT => $port,
            CURLOPT_FOLLOWLOCATION => 1,
            CURLOPT_AUTOREFERER => 1,
            CURLOPT_ENCODING => '',
            CURLOPT_COOKIEFILE => '',
            CURLOPT_PROXYTYPE => $proxyType,
        ];

        curl_setopt_array($ch, $curlOptions);

        $this->ch = $ch;
    }

    /**
     * Destructor.  Closes curl handle and frees resources.
     */
    public function __destruct()
    {
        curl_close($this->ch);
    }

    /**
     * Wrapper to curl_setopt on the underlying curl handle.
     *
     * @param int $option The CURLOPT_XXX option to set
     * @param mixed $value The value to be set on option
     * @throws \Exception Throws exception if an attempt is made to change the proxy address or type
     * @return bool Returns TRUE on success or FALSE on failure
     */
    public function setopt($option, $value)
    {
        if ($option == CURLOPT_PROXY) {
            throw new \Exception('Cannot set CURLOPT_PROXY - use constructor instead');
        } elseif ($option == CURLOPT_PROXYTYPE) {
            throw new \Exception('Cannot set CURLOPT_PROXYTYPE - SOCKS5_HOSTNAME is required');
        }

        return curl_setopt($this->ch, $option, $value);
    }

    /**
     * Returns TRUE if all options were successfully set. If an option could not be successfully set, FALSE is
     * immediately returned, ignoring any future options in the options array.
     *
     * @param array $options
     * @return bool
     * @throws \Exception
     */
    public function setoptArray(array $options)
    {
        foreach($options as $name => $value) {
            if (!$this->setopt($name, $value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Execute an HTTP GET request to $url using the underlying curl handle
     *
     * @param ?string $url Optional URL to fetch, can also use TorCurlWrapper::setopt(CURLOPT_URL, $url)
     * @throws \Exception Throws exception if curl_exec() fails
     * @return boolean Returns TRUE if the request was successful (does not necessarily indicate a 200 OK response from the server)
     */
    public function httpGet(?string $url = null)
    {
        if (!is_null($url)) {
            $this->setopt(CURLOPT_URL, $url);
        }

        $this->setopt(CURLOPT_HTTPGET, 1);

        return $this->executeRequest();
    }

    /**
     * Execute an HTTP POST request to $url using the underlying curl handle, passing $params as the POST data
     *
     * @param ?string $url Optional URL to fetch, can also use TorCurlWrapper::setopt(CURLOPT_URL, $url)
     * @param mixed $params Passed directly to curl_setopt as CURLOPT_POSTFIELDS.
     *   Be aware of the implications of passing an array vs. a string, or uploading files (CURLFile vs @).
     * @throws \Exception Throws exception if curl_exec() fails
     * @return boolean Returns TRUE if the request was successful (does not necessarily indicate a 200 OK response from the server)
     */
    public function httpPost(?string $url = null, $params = null)
    {
        if (!is_null($url)) {
            $this->setopt(CURLOPT_URL, $url);
        }

        $this->setopt(CURLOPT_POST, 1);
        $this->setopt(CURLOPT_POSTFIELDS, $params);

        return $this->executeRequest();
    }

    /**
     * Close the underlying curl handle and frees the resource.
     *
     * The TorCurlWrapper constructor is called again on the object to re-initialize it with a fresh curl handle.
     *
     * This causes curl to close any connections, and reset any session cookies it may have been tracking
     */
    public function close()
    {
        curl_close($this->ch);
        $this->__construct($this->socksHost, $this->socksPort);
    }

    /**
     * Gets the response headers from the previous request
     *
     * @param string|null $header The header (case-insensitive) to get, or an array of headers if null
     * @return string|array|null Returns an array of headers from the previous request, or the value of a single header if $header was passed and exists, null if no headers or $header is was not set
     */
    public function getResponseHeaders($header = null)
    {
        $return = null;

        if ($header === null) {
            $return = $this->responseHeaders;
        } else {
            foreach($this->responseHeaders as $name => $val) {
                if (strtolower($name) == strtolower($header)) {
                    return $val;
                }
            }
        }

        return $return;
    }

    /**
     * Gets the response body of the previous request
     *
     * @return string|null The contents of the last response, or null if no previous response.  Could return an empty string for empty responses.
     */
    public function getResponseBody()
    {
        return $this->responseBody;
    }

    /**
     * Gets the HTTP status code from the previous request
     *
     * @return int|null The response code of the previous request, or 0 if last response failed or null if not set
     */
    public function getHttpStatusCode()
    {
        if (isset($this->info['http_code'])) {
            return $this->info['http_code'];
        } else {
            return null;
        }
    }

    /**
     * Returns the data from curl_getinfo() for the last request
     *
     * @return array The info from the last request
     */
    public function getInfo()
    {
        return $this->info;
    }

    /**
     * Allow system to perform DNS resolution when curl does not support DNS resolution over SOCKS.
     *
     * @param bool $allow
     * @return $this
     */
    public function allowUnsafeDnsResolution(bool $allow = true)
    {
        $this->allowUnsafeDnsResolution = $allow;
        return $this;
    }

    /**
     * Execute a request on the curl handle
     *
     * @throws \Exception Throws exception if curl_exec() fails
     * @return boolean returns TRUE on success
     */
    private function executeRequest()
    {
        if (!$this->socks5HostnameSupport && !$this->allowUnsafeDnsResolution) {
            throw new \Exception(
                'The curl version on this system does not support DNS name resolution over SOCKS. ' .
                'Hostnames will not be resolved over Tor and .onion addresses will not work. To allow DNS ' .
                'resolution on the system, use the allowUnsafeDnsResolution option.'
            );
        }

        $this->responseHeaders = null;
        $this->responseBody    = null;

        curl_setopt_array($this->ch, [
            CURLOPT_HEADER => 1,
            CURLOPT_RETURNTRANSFER => 1,
        ]);

        $response   = curl_exec($this->ch);
        $this->info = curl_getinfo($this->ch);

        if ($response === false) {
            throw new \Exception(curl_error($this->ch), curl_errno($this->ch));
        } else {
            for ($i = 0; $i < intval($this->info['redirect_count']); ++$i) {
                // remove any headers from previous redirected responses
                list( , $response) = explode("\r\n\r\n", $response, 2);
            }

            list($headers, $this->responseBody) = explode("\r\n\r\n", $response, 2);
            list($this->statusLine, $this->responseHeaders) = $this->parseHeaders($headers);

            return true;
        }
    }

    /**
     * Parse response headers into an array keyed by header name
     *
     * @param string $headers  String of HTTP response headers
     * @return array Returns headers in an array keyed by name
     */
    private function parseHeaders(string $headers)
    {
        $parsed  = array();
        $headers = explode("\r\n", $headers);
        array_shift($headers); // remove http response code

        foreach($headers as $header) {
            list($name, $value) = explode(':', $header, 2);
            $parsed[$name] = ltrim($value);
        }

        return $parsed;
    }
}
