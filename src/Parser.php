<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     Parser.php
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

require_once 'RouterDescriptor.php';
require_once 'ProtocolReply.php';
require_once 'ProtocolError.php';

use Dapphp\TorUtils\RouterDescriptor;
use Dapphp\TorUtils\ProtocolReply;
use Dapphp\TorUtils\ProtocolError;

/**
 * Class for parsing replies from the control connection or directories.
 *
 * Typically, implementors will not need to use this class as it is used by
 * the ControlClient and DirectoryClient to parse responses.
 *
 */
class Parser
{
    private $_descriptorReplyLines = array(
        'router'             => '_parseRouter',
        'platform'           => '_parsePlatform',
        'published'          => '_parsePublished',
        'fingerprint'        => '_parseFingerprint',
        'hibernating'        => '_parseHibernating',
        'uptime'             => '_parseUptime',
        'onion-key'          => '_parseOnionKey',
        'ntor-onion-key'     => '_parseNtorOnionKey',
        'signing-key'        => '_parseSigningKey',
        'accept'             => '_parseAccept',
        'reject'             => '_parseReject',
        'ipv6-policy'        => '_parseIPv6Policy',
        'router-signature'   => '_parseRouterSignature',
        'contact'            => '_parseContact',
        'family'             => '_parseFamily',
        'caches-extra-info'  => '_parseCachesExtraInfo',
        'extra-info-digest'  => '_parseExtraInfoDigest',
        'hidden-service-dir' => '_parseHiddenServiceDir',
        'bandwidth'          => '_parseBandwidth',
        'protocols'          => '_parseProtocols',
        'allow-single-hop-exits'
                             => '_parseAllowSingleHopExits',
        'or-address'         => '_parseORAddress',
        'master-key-ed25519' => '_parseMasterKeyEd25519',
        'router-sig-ed25519' => '_parseRouterSigEd25519',
        'identity-ed25519'   => '_parseIdentityEd25519',
        'onion-key-crosscert'
                             => '_parseOnionKeyCrosscert',
        'ntor-onion-key-crosscert'
                             => '_parseNtorOnionKeyCrosscert',
        'tunnelled-dir-server'
                             => '_parseTunnelledDirServer',
        'proto'              => '_parseProtoVersions',
        'a'                  => '_parseALine',
        'p'                  => '_parseAccept',
        'p6'                 => '_parseIPv6Policy',
        'id'                 => '_parseIdLine',
    );

    /**
     * Parse directory status reply (v3 directory style)
     *
     * @param ProtocolReply $reply The reply to parse
     * @return array Array of \Dapphp\TorUtils\RouterDescriptor objects
     */
    public function parseRouterStatus(ProtocolReply $reply)
    {
        $descriptors = array();
        $descriptor  = null;

        foreach($reply->getReplyLines() as $line) {
            switch($line[0][0]) {
                case 'r':
                    if ($descriptor != null)
                        $descriptors[$descriptor->fingerprint] = $descriptor;

                    $descriptor = new RouterDescriptor();
                    $descriptor->setArray($this->_parseRLine($line));
                    break;

                case 'a':
                    $descriptor->setArray($this->_parseALine($line));
                    break;

                case 's':
                    $descriptor->setArray($this->_parseSLine($line));
                    break;

                case 'v':
                    $descriptor->setArray($this->_parsePlatform($line));
                    break;

                case 'w':
                    $descriptor->setArray($this->_parseWLine($line));
                    break;

                case 'p':
                    $descriptor->setArray($this->_parsePLine($line));
                    break;
            }
        }

        $descriptors[$descriptor->fingerprint] = $descriptor;

        return $descriptors;
    }

    /**
     * Parse a router descriptor or microdescriptor
     *
     * @param ProtocolReply $reply The reply to parse
     * @return array Array of \Dapphp\TorUtils\RouterDescriptor objects
     */
    public function parseDirectoryStatus(ProtocolReply $reply)
    {
        $descriptors = array();
        $descriptor  = new RouterDescriptor();

        foreach($reply as $line) {
            if ($line == 'OK')     continue; // for DirectoryClient HTTP responses
            if (trim($line) == '') continue;

            $opt = false;

            if (substr($line, 0, 4) == 'opt ') {
                $opt = true;
                $line = substr($line, 4);
            }

            $values = explode(' ', $line, 2); if (sizeof($values) < 2) $values[1] = null;
            list ($keyword, $value) = $values;

            if ($keyword == 'router') {
                if ($descriptor && $descriptor->fingerprint)
                    $descriptors[$descriptor->fingerprint] = $descriptor;

                $descriptor = new RouterDescriptor();
            }

            if (array_key_exists($keyword, $this->_descriptorReplyLines)) {
                $descriptor->setArray(
                    call_user_func(
                        array($this, $this->_descriptorReplyLines[$keyword]), $value, $reply
                    )
                );
            } else {
                if (!$opt) {
                    trigger_error('No callback found for keyword ' . $keyword, E_USER_NOTICE);
                }
            }
        }

        $descriptors[$descriptor->fingerprint] = $descriptor;

        return $descriptors;
    }

    public function parseAddrMap($line)
    {
        if (strpos($line, 'ADDRMAP') !== 0) {
            throw new \Exception('Data passed to parseAddrMap must begin with ADDRMAP');
        }

        if (!preg_match('/^ADDRMAP ([^\s]+) ([^\s]+) "([^"]+)"/', $line, $match)) {
            throw new ProtocolError("Failed to parse ADDRMAP line '{$line}'");
        }

        $map = array(
            'ADDRESS'    => $match[1],
            'NEWADDRESS' => $match[2],
            'EXPIRY'     => $match[3],
        );

        if (preg_match('/error="?([^"\s]+)"?/', $line, $match)) {
            $map['error'] = $match[1];
        }
        if (preg_match('/EXPIRES="([^"]+)"/', $line, $match)) {
            $map['EXPIRES'] = $match[1];
        }
        if (preg_match('/CACHED="([^"]+)"/', $line, $match)) {
            $map['CACHED'] = $match[1];
        }

        return $map;
    }

    /**
     * Parase a circuit status (CIRC) response
     *
     * @param string $line  A circuit status line (with or without /^CIRC/)
     * @throws ProtocolError If status line or value is malformed
     * @return \Dapphp\TorUtils\CircuitStatus
     */
    public function parseCircuitStatusLine($line)
    {
        require_once __DIR__ . '/CircuitStatus.php';

        $c = new CircuitStatus();

        if (preg_match('/^\s*CIRC /', $line)) {
            $line = preg_replace('/^\s*CIRC\s*/', '', $line);
        }

        $parts = explode(' ', $line, 3);

        if (sizeof($parts) < 3) {
            throw new ProtocolError('Error parsing circuit status, expected at least 3 parts but got ' . sizeof($parts));
        }

        $c->id     = $parts[0];
        $c->status = $parts[1];
        $line      = $parts[2];

        if (!in_array($c->status, array('LAUNCHED', 'BUILT', 'EXTENDED', 'FAILED', 'CLOSED'))) {
            throw new ProtocolError("Unknown circuit status '{$c->status}'");
        }

        if ($line[0] == '$') {
            list ($temp, $line) = explode(' ', $line, 2);
            $temp = explode(',', $temp);

            foreach($temp as $hop) {
                $fpnick = explode('~', $hop);
                // TODO: check size
                $c->path[] = array($fpnick[0], $fpnick[1]);
            }
        }

        for ($i = 0; $i < 9; ++$i) {
            if (trim($line) == '') break;
            $parts = explode(' ', $line, 2);

            if (sizeof($parts) < 1) break;

            $what = $parts[0];

            if (sizeof($parts) == 2) {
                $line = $parts[1];
            } else {
                $line = '';
            }

            $parts = explode('=', $what, 2);

            if (sizeof($parts) < 2) {
                throw new ProtocolError("Expecting KEY=VALUE; got $what");
            }

            $key = $parts[0];
            $val = $parts[1];

            switch($key) {
                case 'BUILD_FLAGS':
                    $c->buildFlags = explode(',', $val);
                    break;

                case 'PURPOSE':
                    $c->purpose = $val;
                    break;

                case 'HS_STATE':
                    $c->hsState = $val;
                    break;

                case 'REND_QUERY':
                    $c->rendQuery = $val;
                    break;

                case 'TIME_CREATED':
                    $c->created = $val;
                    break;

                case 'REASON':
                    $c->reason = $val;
                    break;

                case 'REMOTE_REASON':
                    $c->remoteReason = $val;
                    break;

                case 'SOCKS_USERNAME':
                    $c->socksUsername = $val;
                    break;

                case 'SOCKS_PASSWORD':
                    $c->socksPassword = $val;
                    break;
            }
        }

        return $c;
    }

    private function _parseRouter($line)
    {
        $values = explode(' ', $line);

        if (sizeof($values) < 5) {
            throw new ProtocolError('Error parsing router line.  Expected 5 values, got ' . sizeof($values));
        }

        return array(
            'nickname'   => $values[0],
            'ip_address' => $values[1],
            'or_port'    => $values[2],
            /* socksport - deprecated */
            'dir_port'   => $values[4],
        );
    }

    private function _parsePlatform($line)
    {
        return array('platform' => $line);
    }

    private function _parsePublished($line)
    {
        $values = explode(' ', $line);

        if (sizeof($values) != 2) {
            throw new ProtocolError('Error parsing published line.  Expected 2 values, got ' . sizeof($values));
        }

        $date = $values[0];
        $time = $values[1];

        // TODO: validate

        return array(
            'published' => $line,
        );
    }

    private function _parseFingerprint($line)
    {
        return array(
            'fingerprint' => str_replace(' ', '', $line),
        );
    }

    private function _parseHibernating($line)
    {
        return array(
            'hibernating' => $line,
        );
    }

    private function _parseUptime($line)
    {
        if (!preg_match('/^\d+$/', $line)) {
            throw new ProtocolError('Invalid uptime, expected numeric value');
        }

        return array(
            'uptime' => $line,
        );
    }

    private function _parseOnionKey($line, ProtocolReply $reply)
    {
        $key = $this->_parseRsaKey($reply);

        return array(
            'onion_key' => $key,
        );
    }

    private function _parseNtorOnionKey($line)
    {
        $len = strlen($line) % 4;
        $line = str_pad($line, strlen($line) + $len, '=');

        if (base64_decode($line) === false) {
            throw new ProtocolError('ntor-onion-key did not contain valid base64 encoded data');
        }

        return array(
            'ntor_onion_key' => $line,
        );
    }

    private function _parseSigningKey($line, ProtocolReply $reply)
    {
        $key = $this->_parseRsaKey($reply);

        return array(
            'signing_key' => $key,
        );
    }

    private function _parseAccept($line)
    {
        $exit = $line;

        return array(
            'exit_policy4' => array('accept' => $exit),
        );
    }

    private function _parseReject($line)
    {
        $exit = $line;

        return array(
            'exit_policy4' => array('reject' => $exit),
        );
    }

    private function _parseIPv6Policy($line)
    {
        list($policy, $portlist) = explode(' ', $line);
        $ports = explode(',', $portlist);
        $p     = array($policy => $ports);

        if (isset($p['reject'])) {
            $p['accept'] = array('*:*');
        } else {
            $p['reject'] = array('*:*');
        }

        return array(
            'exit_policy6' => $p,
        );
    }

    private function _parseRouterSignature($line, ProtocolReply $reply)
    {
        $key = $this->_parseBlockData($reply, '-----BEGIN SIGNATURE-----', '-----END SIGNATURE-----');

        return array(
            'router_signature' => $key,
        );
    }

    private function _parseContact($line)
    {
        return array('contact' => $line);
    }

    private function _parseFamily($line)
    {
        return array(
            'family' => explode(' ', $line),
        );
    }

    private function _parseCachesExtraInfo($line)
    {
        // presence of this field indicates the server caches extra info
        return array('caches_extra_info' => true);
    }

    private function _parseExtraInfoDigest($line)
    {
        return array(
            'extra_info_digest' => $line,
        );
    }

    private function _parseHiddenServiceDir($line)
    {
        if (trim($line) == '') {
            $line = '2';
        }

        return array(
            'hidden_service_dir' => $line,
        );
    }

    private function _parseBandwidth($line)
    {
        $values = explode(' ', $line);

        if (sizeof($values) < 3) {
            throw new ProtocolError('Error parsing bandwidth line.  Expected 3 values, got ' . sizeof($values));
        }

        return array(
            'bandwidth_average'  => $values[0],
            'bandwidth_burst'    => $values[1],
            'bandwidth_observed' => $values[2],
        );
    }

    private function _parseProtocols($line)
    {
        return array(
            'protocols' => $line,
        );
    }

    private function _parseProtoVersions($line)
    {
        $protos  = [];
        $entries = explode(' ', $line);

        // this line looks something like:
        // proto Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1-2 Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2
        // but could include a value like "Something=3,5-6"

        foreach($entries as $entry) {
            list($keyword, $values) = explode('=', $entry);
            $protos[$keyword] = [];

            $values = explode(',', $values);
            foreach($values as $value) {
                if (strpos($value, '-') !== false) {
                    $value = explode('-', $value);
                    $value[0] = (int)$value[0];
                    $value[1] = (int)$value[1];

                    if ($value[0] < $value[1]) {
                        $protos[$keyword] = array_merge($protos[$keyword], range($value[0], $value[1]));
                    }
                } else {
                    $protos[$keyword][] = $value;
                }
            }
        }

        return array(
            'proto' => $protos,
        );
    }

    private function _parseAllowSingleHopExits($line)
    {
        // presence of this line indicates the router allows single hop exits
        return array('allow_single_hop_exits' => true);
    }

    private function _parseORAddress($line)
    {
        return array('or_address' => $line);
    }

    private function _parseMasterKeyEd25519($line)
    {
        return array('ed25519_key' => $line);
    }

    private function _parseRouterSigEd25519($line)
    {
        return array('ed25519_sig' => $line);
    }

    private function _parseIdentityEd25519($line, ProtocolReply $reply)
    {
        $cert = $this->_parseBlockData($reply, '-----BEGIN ED25519 CERT-----', '-----END ED25519 CERT-----');

        return array(
            'ed25519_identity' => $cert,
        );
    }

    private function _parseOnionKeyCrosscert($line, ProtocolReply $reply)
    {
        $cert = $this->_parseBlockData($reply, '-----BEGIN CROSSCERT-----', '-----END CROSSCERT-----');

        return array(
            'onion_key_crosscert' => $cert,
        );
    }

    public function _parseNtorOnionKeyCrosscert($line, ProtocolReply $reply)
    {
        $signbit = $line;
        $cert    = $this->_parseBlockData($reply, '-----BEGIN ED25519 CERT-----', '-----END ED25519 CERT-----');

        return array(
            'ntor_onion_key_crosscert_signbit' => $signbit,
            'ntor_onion_key_crosscert'         => $cert,
        );
    }

    public function _parseTunnelledDirServer($line)
    {
        return array('tunnelled_dir_server' => true);
    }

    public function _parseIdLine($line)
    {
        $ret = array();

        list($keytype, $value) = explode(' ', $line, 2);

        if ($keytype == 'rsa1024') {
            /* base64 encoded fingerprint - implementations should ignore
               bin2hex(base64_decode($value)) == fingerprint */
        } elseif ($keytype == 'ed25519') {
            $ret['ed25519_key'] = $value;
        } else { /* unknown key type - ignore */ }

        return $ret;
    }

    private function _parseRsaKey(ProtocolReply $reply)
    {
        return $this->_parseBlockData($reply, '-----BEGIN RSA PUBLIC KEY-----', '-----END RSA PUBLIC KEY-----');
    }

    private function _parseRLine($line)
    {
        $values = explode(' ', $line);

        return array(
            'nickname'    => $values[1],
            'fingerprint' => substr(self::base64ToHexString($values[2]), 0, 40),
            'digest'      => substr(self::base64ToHexString($values[3]), 0, 40),
            'published'   => $values[4] . ' ' . $values[5],
            'ip_address'  => $values[6],
            'or_port'     => $values[7],
            'dir_port'    => $values[8],
        );
    }

    private function _parseALine($line)
    {
        if (strpos($line, ' ') !== false) {
            $values = explode(' ', $line, 2);
            $line   = $values[1];
        }

        if (preg_match('/\[([^]]+)]+:(\d+)/', $line, $match)) {
            $ip   = $match[1];
            $port = $match[2];
        } else {
            list($ip, $port) = explode(':', $line);
        }

        return array(
            'or_port'      => $port,
            'ipv6_address' => $ip,
        );
    }

    private function _parseSLine($line)
    {
        $values = explode(' ', $line);
        array_shift($values);

        return array(
            'flags' => $values,
        );
    }

    private function _parseWLine($line)
    {
        $bandwidth = $this->_parseDelimitedData($line, 'w');

        if (!isset($bandwidth['bandwidth'])) {
            throw new ProtocolError("Bandwidth value not present in 'w' line");
        }

        return array(
            'bandwidth'            => $bandwidth['bandwidth'],
            'bandwidth_measured'   => (isset($bandwidth['measured']) ? $bandwidth['measured'] : null),
            'bandwidth_unmeasured' => (isset($bandwidth['unmeasured']) ? $bandwidth['unmeasured'] : null),
        );
    }

    private function _parsePLine($line)
    {
        $values = explode(' ', $line);

        return array(
            'exit_policy4' => array($values[1] => $values[2]),
        );
    }

    public function parseProtocolInfo($reply)
    {
        /*
         250-PROTOCOLINFO 1
         250-AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE="/var/run/tor/control.authcookie"
         250-VERSION Tor="0.2.4.24"
         250 OK
         */
        $methods = $cookiefile = $version = null;

        if (isset($reply['AUTH'])) {
            $values = $this->_parseDelimitedData($reply['AUTH']);

            if (!isset($values['methods']) || empty($values['methods'])) {
                throw new ProtocolError('PROTOCOLINFO reply did not contain any authentication methods');
            }

            $methods = $values['methods'];

            if (isset($values['cookiefile'])) {
                $cookiefile = $values['cookiefile'];
            }
        } else {
            throw new ProtocolError('PROTOCOLINFO response did not contain AUTH line');
        }

        if (isset($reply['VERSION'])) {
            $version = $this->_parseDelimitedData($reply['VERSION']);

            if (!isset($version['tor'])) {
                throw new ProtocolError('PROTOCOLINFO version line did not match expected format');
            }

            $version = $version['tor'];
        } else {
            throw new ProtocolError('PROTOCOL INFO response did not contain VERSION line');
        }

        return array(
            'methods'    => explode(',', $methods),
            'cookiefile' => $cookiefile,
            'version'    => $version,
        );
    }

    private function _parseBlockData(ProtocolReply $reply, $startDelimiter, $endDelimter)
    {
        $reply->next();

        $line = $reply->current();

        if ($line != $startDelimiter) {
            throw new ProtocolError('Expected line beginning with "' . $startDelimiter . '"');
        }

        $key = $line . "\n";

        do {
            $reply->next();
            $line = $reply->current();
            $key .= $line . "\n";
        } while ($line && $line != $endDelimter);

        return $key;
    }

    private function _parseDelimitedData($data, $prefix = null, $delimiter = '=', $boundary = ' ')
    {
        $return = array();

        if ($prefix && is_string($prefix)) {
            $data = preg_replace('/^' . preg_quote($prefix) . ' /', '', $data);
        }

        if (strpos($data, $boundary) === false) {
            $items = array($data);
        } else {
            $items = explode($boundary, $data);
        }

        foreach ($items as $item) {
            if (strpos($item, $delimiter) === false) {
                trigger_error("Delimiter not found in data '" . $item . "'");
                continue;
            }

            $values = explode($delimiter, $item, 2);

            $values[1] = trim($values[1], '"');  // remove surrounding quotes from data

            $return[strtolower($values[0])] = $values[1];
        }

        return $return;
    }

    public static function base64ToHexString($base64)
    {
        $padLength = strlen($base64) % 4;
        $base64   .= str_pad($base64, $padLength, '=');
        $identity  = base64_decode($base64);

        return strtoupper(bin2hex($identity));
    }
}
