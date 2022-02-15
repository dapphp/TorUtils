<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     DirectoryClient.php
 *
 * Copyright (c) 2017, Drew Phillips
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

require_once 'Parser.php';
require_once 'ProtocolReply.php';

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

/**
 * Class for getting router info from Tor directory authorities
 *
 */
class DirectoryClient
{
    /**
     * @var array $directoryAuthorities List of directory authorities https://gitweb.torproject.org/tor.git/tree/src/app/config/auth_dirs.inc
     */
    protected $directoryAuthorities = array(
        '9695DFC35FFEB861329B9F1AB04C46397020CE31' => '128.31.0.39:9131', // moria1
        '847B1F850344D7876491A54892F904934E4EB85D' => '86.59.21.38:80', // tor26
        '7EA6EAD6FD83083C538F44038BBFA077587DD755' => '45.66.33.45:80', // dizum
        'BA44A889E64B93FAA2B114E02C2A279A8555C533' => '66.111.2.131:9030', // Serge
        'F2044413DAC2E02E3D6BCF4735A19BCA1DE97281' => '131.188.40.189:80', // gabelmoo
        '7BE683E65D48141321C5ED92F075C55364AC7123' => '193.23.244.244:80', // dannenberg
        'BD6A829255CB08E66FBE7D3748363586E46B3810' => '171.25.193.9:443', // maatuska
        'CF6D0AAFB385BE71B8E111FC5CFF4B47923733BC' => '154.35.175.225:80', // Faravahar
        '74A910646BCEEFBCD2E874FC1DC997430F968145' => '199.58.81.140:80', // longclaw
        '24E2F139121D4394C54B5BCC368B3B411857C413' => '204.13.164.118:80', // bastet
    );

    /**
     * @var array Array of directory fallbacks from https://gitweb.torproject.org/tor.git/tree/src/app/config/fallback_dirs.inc
     */
    protected $directoryFallbacks = array(
        // List updated 2022/02/13 (commit blob 87c1886e833e6c3edf024678232089ef42f414d0)
        // version=4.0.0, timestamp=20210412000000 (Generated on: Fri, 04 Feb 2022 15:49:02 +0000)
        // NF = Not found in Tor Metrics (metrics.torproject.org) - The fingerprint was not found in Tor Metrics on the date given
        // TO = Timing out repeatedly on given date
        // RF = Read failed when trying to query for directory info on the date given.
        // Exit Relay = This is a busy exit relay so we should not bug it for directory info.
        // Outdated = Running outdated Tor software, do not use
        '86CDD0D92AB972538416A382D99666736CDDF141' => '88.196.80.132:80', // RyderIII
        '3A1BC65DF03ECD50FDF7CFF9C5A4E049FCB9C1AF' => '199.249.230.179:80', // Quintex90
        '9C5AFD49AAE4E0272BAD780C6DD71CE1A36012A6' => '82.223.14.245:80', // coffswifi4
        '2D8A907F61CAED48170963B76BE4FB0ED33E5E88' => '80.98.81.157:9030', // nCT8d6e5bW2v
        'CB7C0D841FE376EF43F7845FF201B0290C0A239E' => '199.249.230.78:80', // QuintexAirVPN25
        '04A28A62F27D9C4A60F9ED0C4264E98B988C65A3' => '163.172.169.253:9030', // darknebula
        'C473C772282D5078E5137C1DB83B62224D5B42DD' => '24.53.51.144:9032', // ClericalSummoning
        '80654A16C954422C9A1B6DBEFBB6A32157A8BAB5' => '78.42.186.218:9030', // northwind84
        '066FE3C4E07A18EA53B2828F753D3788D58D771D' => '102.130.113.42:9030', // Psyduck
        'FFB605C86D606991ADED7842269FA25A03B4A4D0' => '165.227.174.150:9030', // Unnamed
        'E09782C5F119131D5DF3C77B83E3214697AB6376' => '199.195.251.54:9030', // dappertr
        'BBDE12C320FD1C3FFBEC15202F46D5620FC1444E' => '178.17.174.79:9030', // hanktor
        '823AA81E277F366505545522CEDC2F529CE4DC3F' => '192.160.102.164:80', // snowfall
        'D2169E641B2C10CACEA266D31370479200BB9AD7' => '185.22.174.119:9030', // FlashBear
        '8765C6AFF62C266A38D8C73A76604A5B1669FAA7' => '152.70.64.30:9030', // plithismos
        '79B207AD51842FA215D956B9307B3D01CD347368' => '37.252.187.129:9030', // 1d1dchang3th3c0nf1g
        '90BF7147B422A1BABEFA503656EBD17987424441' => '199.249.230.158:80', // Quintex69
        '1944F3A473CB77B12BDB4E3D15963A24DF58E4E7' => '146.185.189.197:8080', // Thrones
        'C78AFFEEE320EA0F860961763E613FD2FAC855F5' => '199.249.230.69:80', // Quintex46
        '1CD48F4ED0F1821FFBF1940802A13EEFD4C27502' => '176.9.40.131:80', // Piratenpartei00
        '209B6DC8584D0DBC569DBA8DAE88B567A24C9467' => '85.7.221.196:9030', // cercatrova
        '8454D200E13A41A93F4B6523740EBC78505D0DF0' => '5.2.70.141:9030', // Unnamed
        '37FCDCAFAAA17742BE58A36382A768E21B65B34C' => '45.33.123.222:9030', // PictureEnchanter
        '85D3D0C3D4699AFA897FE9DD9270BAACBBE3E3F1' => '185.112.146.188:9030', // Unnamed
        'E8ED405E47A477D92D9EFB201FADF28FF7FBAF5D' => '31.201.16.30:8443', // Tortue
        '5F875CFB7E2ED0D24E85A5A8B8904A3650AB1ED8' => '185.100.85.132:80', // vandergriff
        '139C86C4C9BC94E89BAF79B15EBFDF9396DD5BB0' => '199.249.230.156:80', // Quintex67
        'D25210CE07C49F2A4F2BC7A506EB0F5EA7F5E2C2' => '199.249.230.112:80', // QuintexPhoulRules
        '83AEDBDB4BE3AD0ED91850BF1A521B843077759E' => '198.251.68.144:9030', // focaltohr
        '5414065F98A160F630DAE0689973FC66D7EA62E9' => '170.239.86.145:80', // DTFNODE04
        '13F7EAE731CA4600951986921E08ECAB9B1D2AF6' => '37.9.231.195:80', // CanopoIT
        'B594EFDDBA2A8F12DEF827DFEE6992A6EB310B2A' => '93.115.241.194:80', // heaney
        '42A51FFF7AB2A2F396CB924B56676F09BCB52245' => '157.90.38.9:80', // SoySauceR
        '126E438B6921882FC17F1FC32AAC617300561938' => '212.74.233.19:9033', // Bathtub
        '3DF28C6A21F9F063FA1640F7367BE8143816D40F' => '130.180.111.194:9030', // DerRaffke
        '12836441FEAC9AEE13A144A64E51AB2AD98885B4' => '172.81.131.111:80', // TheEndOfTheInternet
        'ED7FDF68D504AEED4E28C6396B3E4A4ED04406B9' => '163.44.173.37:9030', // Unnamed
        'A636F3A27D9C10713C7A77ED00183DE8727E3D84' => '102.130.119.48:9030', // axeTorA
        '0BADD9510440C9BF3A728F2CB630836FF98142B2' => '138.59.18.106:80', // Albis
        '38F21DEE29E40DCDF9460A80662B7723562CA008' => '94.75.194.221:9030', // trabajando
        '2B34099ED2BC598C4745C96C873FD73A445646BD' => '185.82.219.109:80', // RunningOnFumes4
        '9D07DFA6472B80277798D73234348CEF02F2E7D5' => '159.89.87.126:9030', // incircuitryrelay
    );

    protected $preferredServer;

    protected $connectTimeout = 5;
    protected $readTimeout = 30;
    protected $userAgent = 'dapphp/TorUtils 1.1.13';

    protected $parser;
    protected $serverList;

    /**
     * DirectoryClient constructor
     */
    public function __construct()
    {
        $this->serverList = array_merge($this->directoryAuthorities, $this->directoryFallbacks);
        shuffle($this->serverList);

        $this->parser = new Parser();
    }

    /**
     * Set the preferred directory server to use for lookups.  This server will always be used
     * first.  If the preferred server times out or fails, the lookup will proceed using a random
     * server from the list of directory authorities and fallbacks.
     *
     * @param string $server The directory server to connect to (e.g. 1.2.3.4:80)
     * @return self
     */
    public function setPreferredServer($server)
    {
        $this->preferredServer = $server;

        return $this;
    }

    public function setServerList($list)
    {
        $this->serverList = $list;

        return $this;
    }

    /**
     * Set the connection timeout period (in seconds).  Attempts to connect to
     * directories that take longer than this will time out and try the next host.
     *
     * @param number $timeout  The connection timeout in seconds
     * @throws \InvalidArgumentException If timeout is non-numeric or less than 1
     * @return self
     */
    public function setConnectTimeout($timeout)
    {
        if (!preg_match('/^\d+$/', $timeout) || (int)$timeout < 1) {
            throw new \InvalidArgumentException('Timeout must be a positive integer');
        }

        $this->connectTimeout = (int)$timeout;

        return $this;
    }

    /**
     * Set the read timeout in seconds (default = 30).  Directory requests
     * that fail to receive any data after this many seconds will time out
     * and try the next host.
     *
     * @param number $timeout  The read timeout in seconds
     * @throws \InvalidArgumentException If timeout is non-numeric or less than 1
     * @return self
     */
    public function setReadTimeout($timeout)
    {
        if (!preg_match('/^\d+$/', $timeout) || (int)$timeout < 1) {
            throw new \InvalidArgumentException('Timeout must be a positive integer');
        }

        $this->readTimeout = (int)$timeout;

        return $this;
    }

    public function getReadTimeout()
    {
        return $this->readTimeout;
    }

    /**
     * Get the list of Tor directory authority servers
     *
     * @return array Array of directory authorities, keyed by fingerprint (value may be a string [ip address] or array of IP addresses)
     */
    public function getDirectoryAuthorities()
    {
        return $this->directoryAuthorities;
    }

    /**
     * Get the list of Tor directory authority servers
     *
     * @return array Array of directory fallbacks, keyed by fingerprint (value may be a string [ip address] or array of IP addresses)
     */
    public function getDirectoryFallbacks()
    {
        return $this->directoryFallbacks;
    }

    /**
     * Fetch a list of all known router descriptors on the Tor network
     *
     * @return array Array of RouterDescriptor objects
     * @throws \Exception If directory requests failed
     */
    public function getAllServerDescriptors()
    {
        $reply = $this->request(
            sprintf('/tor/server/all%s', (function_exists('gzuncompress') ? '.z' : ''))
        );

        return $this->parser->parseDirectoryStatus($reply);
    }

    /**
     * Fetch directory information about a router
     * @param string|array $fingerprint router fingerprint or array of fingerprints to get information about
     * @return mixed Array of RouterDescriptor objects, or a single RouterDescriptor object
     * @throws \Exception
     */
    public function getServerDescriptor($fingerprint)
    {
        if (is_array($fingerprint)) {
            $fp = implode('+', $fingerprint);
        } else {
            $fp = $fingerprint;
        }

        $uri = sprintf('/tor/server/fp/%s%s', $fp, (function_exists('gzuncompress') ? '.z' : ''));

        $reply = $this->request($uri);

        $descriptors = $this->parser->parseDirectoryStatus($reply);

        if (sizeof($descriptors) == 1) {
            return array_shift($descriptors);
        } else {
            return $descriptors;
        }
    }

    public function statusVoteCurrentAuthority($address = null)
    {
        $uri = '/tor/status-vote/current/authority.z';

        $reply = $this->_request($uri, $address);

        return $this->parser->parseVoteConsensusStatusDocument($reply);
    }

    public function statusVoteCurrentConsensus($address = null)
    {
        $uri = '/tor/status-vote/current/consensus.z';

        $reply = $this->_request($uri, $address);

        return $this->parser->parseVoteConsensusStatusDocument($reply);
    }

    /**
     * Make an HTTP GET request to a directory server and return the response
     *
     * @param string $uri The URI to fetch (e.g. /tor/server/all.z)
     * @param string|null $directoryServer The host:port or ip:port of the directory server to use, or null to use
     * random selections from the default list
     * @return \Dapphp\TorUtils\ProtocolReply If no error occurs, a ProtocolReply object is returned. The first line may
     * be the HTTP status line. Implementations must tolerate the first reply line being an HTTP response code.
     * @throws \Exception If the request to the directory failed (e.g. 404 Not Found, Connection Timed Out)
     */
    public function get($uri, $directoryServer = null)
    {
        return $this->_request($uri, $directoryServer);
    }

    /**
     * Pick a random dir authority to query and perform the HTTP request for directory info
     *
     * @param string $uri Uri to request
     * @throws \Exception No authorities responded
     * @return \Dapphp\TorUtils\ProtocolReply The reply from the directory authority
     */
    private function request($uri)
    {
        reset($this->serverList);
        $used = false;

        do {
            // pick a server from the list, it is randomized in __construct
            if ($directoryServer && !$used) {
                $server = $directoryServer;
                $used   = true;
            } elseif ($this->preferredServer && !$used) {
                $server = $this->preferredServer;
                $used   = true;
            } else {
                $server = $this->getNextServer();
            }

            if ($server === false) {
                throw new \Exception('No more directory servers available to query');
            }

            list($host, $port) = @explode(':', $server);
            if (!$port) $port = 80;

            $fp = fsockopen($host, $port, $errno, $errstr, $this->connectTimeout);
            if (!$fp) continue;

            $request = $this->getHttpRequest('GET', $host, $uri);

            $written = fwrite($fp, $request);

            if ($written === false) {
                trigger_error("Failed to write directory request to $server", E_USER_NOTICE);
                continue;
            } elseif (strlen($request) != $written) {
                trigger_error("Request to $server failed; could not write all data", E_USER_NOTICE);
                continue;
            }

            $response = '';

            stream_set_blocking($fp, 0);

            $read   = array($fp);
            $write  = null;
            $except = null;
            $err    = false;

            while (!feof($fp)) {
                $changed = stream_select($read, $write, $except, $this->readTimeout);

                if ($changed === false) {
                    trigger_error("stream_select() returned error while reading data from $server", E_USER_NOTICE);
                    $err = true;
                    break;
                } elseif ($changed < 1) {
                    trigger_error("Failed to read all data from $server within timeout", E_USER_NOTICE);
                    $err = true;
                    break;
                } else {
                    $data = fgets($fp);

                    if ($data === false) {
                        trigger_error("Directory read failed while talking to $server", E_USER_NOTICE);
                        $err = true;
                        break;
                    } else {
                        $response .= $data;
                    }
                }
            }

            fclose($fp);

            if ($err) {
                continue;
            }

            list($headers, $body) = explode("\r\n\r\n", $response, 2);
            $headers = $this->parseHttpResponseHeaders($headers);

            if ($headers['status_code'] == '503') {
                trigger_error("Directory $server returned 503 {$headers['message']}", E_USER_NOTICE);
                continue;
            } elseif ($headers['status_code'] == '504') {
                // observed this from various fallback dirs. This code is not defined in dir-spec.txt
                trigger_error("Directory $server returned 504 {$headers['message']}", E_USER_NOTICE);
                continue;
            }

            if ($headers['status_code'] !== '200') {
                throw new \Exception(
                    sprintf(
                        'Directory %s returned a negative response code to request.  %s %s',
                        $server,
                        $headers['status_code'],
                        $headers['message']
                    )
                );
            }

            $encoding = (isset($headers['headers']['content-encoding'])) ? $headers['headers']['content-encoding'] : null;

            if ($encoding == 'deflate') {
                if (!function_exists('gzuncompress')) {
                    throw new \Exception('Directory response was gzip compressed but PHP does not have zlib support enabled');
                }

                $body = gzuncompress($body);
                if ($body === false) {
                    throw new \Exception('Failed to inflate response data');
                }
            } elseif ($encoding == 'identity') {
                // nothing to do
            } else {
                throw new \Exception('Directory sent response in an unknown encoding: ' . $encoding);
            }

            break;
        } while (true);

        $reply = new ProtocolReply();
        $reply->appendReplyLine(
            sprintf('%s %s', $headers['status_code'], $headers['message'])
        );
        $reply->appendReplyLines(explode("\n", $body));

        return $reply;
    }

    /**
     * Construct an http request for talking to a directory server
     *
     * @param string $method GET|POST
     * @param string $host IP/hostname to query
     * @param string $uri The request URI
     * @return string Completed HTTP request
     */
    private function getHttpRequest($method, $host, $uri)
    {
        return sprintf(
            "%s %s HTTP/1.0\r\n" .
            "Host: %s\r\n" .
            "Connection: close\r\n" .
            "User-Agent: %s\r\n" .
            "\r\n",
            $method, $uri, $host, $this->userAgent
        );
    }

    /**
     * Parse HTTP response headers from the directory reply
     *
     * @param string $headers String of http response headers
     * @throws \Exception Response was not a valid http response
     * @return array Array with http status_code, message, and lines of headers
     */
    private function parseHttpResponseHeaders($headers)
    {
        $lines    = explode("\r\n", $headers);
        $response = array_shift($lines);
        $header   = array();

        if (!preg_match('/^HTTP\/\d\.\d (\d{3}) (.*)$/i', $response, $match)) {
            throw new \Exception('Directory server sent a malformed HTTP response');
        }

        $code    = $match[1];
        $message = $match[2];

        foreach($lines as $line) {
            if (strpos($line, ':') === false) {
                throw new \Exception('Directory server sent an HTTP response line missing the ":" separator');
            }
            list($name, $value) = explode(':', $line, 2);
            $header[strtolower($name)] = trim($value);
        }

        return array(
            'status_code' => $code,
            'message'     => $message,
            'headers'     => $header,
        );
    }

    /**
     * Get the next directory authority from the list to query
     *
     * @return string IP:Port of directory
     */
    private function getNextServer()
    {
        $server = current($this->serverList);
        next($this->serverList);
        return $server;
    }
}
