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

use Dapphp\TorUtils\ProtocolError;
use Dapphp\TorUtils\RouterDescriptor;
use Dapphp\TorUtils\ProtocolReply;

/**
 * Class for parsing replies from the control connection or directories.
 *
 * Typically, implementors will not need to use this class as it is used by
 * the ControlClient and DirectoryClient to parse responses.
 *
 */
class Parser
{
    private $descriptorReplyLines = array(
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
    public function parseVoteConsensusStatusDocument(ProtocolReply $reply)
    {
        $doc = new AuthorityStatusDocument();
        $descriptor  = null;
        $authority   = null;

        $line = $reply->shift();
        if (in_array($line, [ '.', '250 OK', '200 OK', '' ])) {
            $line = $reply->shift();
        }

        if (empty($line)) {
            throw new \Exception('Reply was empty');
        }

        $parts = array_map('trim', explode(' ', $line));

        if ($parts[0] !== 'network-status-version') {
            throw new \Exception('Reply did not begin with network-status-version, got "' . $line . '".');
        }

        $doc->statusVersion = (int)$parts[1];

        foreach($reply as $line) {
            $parts   = explode(' ', $line, 2);
            $keyword = $parts[0];
            $extra   = $parts[1] ?? null;

            switch ($keyword) {
                case 'vote-status':
                    $doc->voteStatus = $extra;
                    break;

                case 'consensus-methods':
                    $doc->consensusMethods = explode(' ', $extra);
                    break;

                case 'consensus-method':
                    $doc->consensusMethod = (int)$extra;
                    break;

                case 'published':
                    $doc->published = $extra;
                    break;

                case 'valid-after':
                    $doc->validAfter = $extra;
                    break;

                case 'fresh-until':
                    $doc->freshUntil = $extra;
                    break;

                case 'valid-until':
                    $doc->validUntil = $extra;
                    break;

                case 'voting-delay':
                    $extra = explode(' ', $extra);
                    $doc->voteDelaySeconds = (int)$extra[0];
                    $doc->distDelaySeconds = (int)$extra[1];
                    break;

                case 'client-versions':
                    $doc->clientVersions = array_map('trim', explode(',', $extra));
                    break;

                case 'server-versions':
                    $doc->serverVersions = array_map('trim', explode(',', $extra));
                    break;

                case 'known-flags':
                    $doc->knownFlags = array_map('trim', explode(' ', $extra));
                    break;

                case 'flag-thresholds':
                    $doc->flagThresholds = $this->parseDelimitedData($extra);
                    break;

                case 'recommended-client-protocols':
                    $doc->recommendedClientProtocols = $this->parseDelimitedData($extra);
                    break;

                case 'recommended-relay-protocols':
                    $doc->recommendedRelayProtocols = $this->parseDelimitedData($extra);
                    break;

                case 'required-client-protocols':
                    $doc->requiredClientProtocols = $this->parseDelimitedData($extra);
                    break;

                case 'required-relay-protocols':
                    $doc->requiredRelayProtocols = $this->parseDelimitedData($extra);
                    break;

                case 'params':
                    $doc->params = $this->parseDelimitedData($extra);
                    break;

                case 'shared-rand-current-value':
                    list($numReveals, $value) = explode(' ', $extra);
                    $doc->sharedRandCurrentValue  = $value;
                    break;

                case 'shared-rand-previous-value':
                    list($numReveals, $value) = explode(' ', $extra);
                    $doc->sharedRandPreviousValue = $value;
                    break;

                case 'dir-source':
                    if (!empty($authority)) {
                        $doc->authorities[] = $authority;
                    }

                    list($nickname, $identity, $hostname, $ip, $dirPort, $orPort) = explode(' ', $extra);
                    $authority = [
                        'nickname' => $nickname,
                        'fingerprint' => $identity,
                        'hostname' => $hostname,
                        'ip_address' => $ip,
                        'dir_port' => $dirPort,
                        'or_port' => $orPort,
                    ];
                    break;

                case 'contact':
                    $authority['contact'] = $extra;
                    break;

                case 'vote-digest':
                    $authority['vote-digest'] = $extra;
                    break;

                case 'shared-rand-participate':
                    $authority['shared-rand-participate'] = true;
                    break;

                case 'shared-rand-commit':
                    if (!isset($authority['shared-rand-commit'])) {
                        // If a vote contains multiple commits from the same authority, the receiver MUST only consider
                        // the first commit listed.
                        $parts = explode(' ', $extra);
                        $authority['shared-rand-commit'] = [
                            'version' => $parts[0],
                            'algname' => $parts[1],
                            'identity' => $parts[2],
                            'commit' => $parts[3],
                            'reveal' => isset($parts[4]) ? $parts[4] : null,
                        ];
                    }
                    break;

                // authority key certificates
                case 'dir-key-certificate-version':
                case 'fingerprint':
                case 'dir-key-published':
                case 'dir-key-expires':
                    $authority[$keyword] = $extra;
                    break;

                case 'dir-identity-key':
                case 'dir-signing-key':
                    $authority[$keyword] = $this->_parseRsaKey($reply);
                    break;

                case 'dir-key-crosscert':
                    // TODO: Implementations MUST verify that the signature is a correct signature of the hash of the identity key using the signing key.
                    $authority[$keyword] = $this->_parseBlockData($reply, '-----BEGIN ID SIGNATURE-----', '-----END ID SIGNATURE-----');
                    break;

                case 'dir-key-certification':
                    $authority[$keyword] = $this->_parseBlockData($reply, '-----BEGIN SIGNATURE-----', '-----END SIGNATURE-----');
                    break;

                case 'r':
                    if (!empty($authority)) {
                        $doc->authorities[] = $authority;
                        $authority = null;
                    }
                    if (isset($descriptor) && $descriptor) {
                        $doc->descriptors[] = $descriptor;
                    }

                    $descriptor = new RouterDescriptor();
                    $descriptor->methods = [];
                    $descriptor->setArray($this->_parseRLine($line));
                    break;

                case 'a':
                    $descriptor->setArray($this->_parseALine($line));
                    break;

                case 's':
                    $descriptor->setArray($this->_parseSLine($line));
                    break;

                case 'v':
                    $descriptor->setArray($this->_parsePlatform($extra));
                    break;

                case 'pr':
                    $descriptor->setArray($this->_parseProtoVersions($extra));
                    break;

                case 'w':
                    $descriptor->setArray($this->_parseWLine($line));
                    break;

                case 'p':
                    $descriptor->setArray($this->_parsePLine($line));
                    break;

                case 'm':
                    list ($methods, $digest) = explode(' ', $extra);
                    $methods = array_map('trim', explode(',', $methods));
                    $digest  = $this->parseDelimitedData($digest);
                    foreach($methods as $method) {
                        $descriptor->methods[$method][array_keys($digest)[0]] = array_values($digest)[0];
                    }
                    break;

                case 'id':
                    $parts = explode(' ', $extra);
                    $descriptor->ed25519_identity = $parts[1];
                    break;

                case 'stats':
                    $descriptor->stats = $this->parseDelimitedData($extra);
                    break;

                case 'directory-footer':
                    if (isset($descriptor) && $descriptor)
                        $doc->descriptors[] = $descriptor;
                    break;

                case 'bandwidth-weights':
                    $doc->bandwidthWeights = array_map('intval', $this->parseDelimitedData($extra));
                    break;

                case 'directory-signature':
                    $parts = explode(' ', $extra);
                    $alg   = 'sha1';
                    if (count($parts) == 3) {
                        $alg = array_shift($parts);
                    }
                    $identity  = $parts[0];
                    $digest    = $parts[1];
                    $signature = $this->_parseBlockData(
                        $reply,
                        '-----BEGIN SIGNATURE-----',
                        '-----END SIGNATURE-----'
                    );

                    $doc->directorySignatures[] = [
                        'algorithm' => $alg,
                        'identity'  => $identity,
                        'digest'    => $digest,
                        'signature' => $signature,
                    ];

                    break;

                default:
                    break;

            }
        }

        return $doc;
    }

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
            if ($line == '.' || $line == '250 OK') {
                continue;
            }

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

                default:
                    //var_dump("UNKNOWN ROUTER STATUS LINE {$line[0][0]}: ", $line);
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
        $mds         = false;

        if (strpos($reply[0], 'onion-key') === 0 || strpos($reply[1], 'onion-key') === 0) {
            $mds = true; // parsing full microdescriptor list
        }

        foreach($reply as $line) {
            if (preg_match('/^200 OK/i', $line)) continue; // for DirectoryClient HTTP responses
            if (trim($line) == '') continue;

            $opt = false;

            if (substr($line, 0, 4) == 'opt ') {
                $opt = true;
                $line = substr($line, 4);
            }

            $values = explode(' ', $line, 2);
            if (sizeof($values) < 2) {
                $values[1] = null;
            }
            list ($keyword, $value) = $values;

            if ($keyword == 'router' || ($keyword == 'onion-key' && $mds)) {
                if ($descriptor && $descriptor->fingerprint) {
                    $descriptors[$descriptor->fingerprint] = $descriptor;
                } elseif ($descriptor && $mds) {
                    $descriptors[] = $descriptor;
                }

                $descriptor = new RouterDescriptor();
            }

            if (array_key_exists($keyword, $this->descriptorReplyLines)) {
                $descriptor->setArray(
                    call_user_func(
                        array($this, $this->descriptorReplyLines[$keyword]), $value, $reply
                    )
                );
            } else {
                if (!$opt) {
                    trigger_error('No callback found for keyword ' . $keyword, E_USER_NOTICE);
                }
            }
        }

        if ($descriptor->fingerprint) {
            $descriptors[$descriptor->fingerprint] = $descriptor;
        } else {
            $descriptors[] = $descriptor;
        }

        return $descriptors;
    }

    public function parseAddrMap($line)
    {
        if (strpos($line, 'ADDRMAP') !== 0) {
            throw new \Exception('Data passed to parseAddrMap must begin with ADDRMAP');
        }

        if (!preg_match('/^ADDRMAP ([^\s]+) ([^\s]+) (?:(NEVER|"[^"]+"))( .*)?$/', $line, $match)) {
            throw new ProtocolError("Invalid ADDRMAP line '{$line}'");
        }

        $map = [
            'ADDRESS'    => $match[1],
            'NEWADDRESS' => $match[2],
            'EXPIRY'     => str_replace('"', '', $match[3]),
        ];

        $map = array_merge($map, $this->parseKeywordArguments($match[4]));

        return $map;
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
        if (empty($line) || ($line && trim($line) == '')) {
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

        if (!isset($bandwidth['Bandwidth'])) {
            throw new ProtocolError("Bandwidth value not present in 'w' line");
        }

        return array(
            'bandwidth'            => $bandwidth['Bandwidth'],
            'bandwidth_measured'   => (isset($bandwidth['Measured']) ? $bandwidth['Measured'] : null),
            'bandwidth_unmeasured' => (isset($bandwidth['Unmeasured']) ? $bandwidth['Unmeasured'] : null),
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
        $info    = $reply[0];
        $auth    = $reply[1];
        $version = $reply[2];

        $pInfo   = array_map('trim', explode(' ', $info, 2));
        if (sizeof($pInfo) != 2 || $pInfo[0] != 'PROTOCOLINFO') {
            throw new ProtocolError(sprintf('Unexpected PROTOCOLINFO response; got "%s"', $info));
        } elseif (!preg_match('/^\d$/', $pInfo[1])) {
            throw new ProtocolError(sprintf('Invalid PROTOCOLINFO version. Expected 1*DIGIT; got "%s"', $pInfo[1]));
        }

        $authInfo = array_map('trim', explode(' ', $auth, 2));
        if (sizeof($authInfo) != 2 || $authInfo[0] != 'AUTH') {
            throw new ProtocolError(sprintf('Expected AUTH line; got "%s"', $auth));
        }

        $values = $this->_parseDelimitedData($authInfo[1]);

        if (!isset($values['METHODS']) || empty($values['METHODS'])) {
            throw new ProtocolError('PROTOCOLINFO reply did not contain any authentication methods');
        }

        $methods = $values['METHODS'];

        if (isset($values['COOKIEFILE'])) {
            $cookiefile = $values['COOKIEFILE'];
        }

        $versionInfo = array_map('trim', explode(' ', $version, 2));
        if (sizeof($versionInfo) != 2 || $versionInfo[0] != 'VERSION') {
            throw new ProtocolError(sprintf('Expected VERSION line; got "%s"', $version));
        }

        $version = $this->_parseDelimitedData($versionInfo[1]);
        if (!isset($version['Tor'])) {
            throw new ProtocolError('PROTOCOLINFO VERSION line did not match expected format');
        }

        $version = $version['Tor'];

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
            throw new ProtocolError('Expected line beginning with "' . $startDelimiter . '", got ' . $line);
        }

        $data = $line;

        do {
            $reply->next();
            if (!$reply->valid()) {
                throw new \Exception('Reached end of reply without matching end delimiter "' . $endDelimter . '"');
            }
            $line  = $reply->current();
            $data .= "\n" . $line;
        } while ($reply->valid() && $line != $endDelimter);

        return $data;
    }

    public function parseKeywordArguments($input)
    {
        $eventData = [];
        $offset    = 0;

        do {
            if ($input[$offset] == ' ') {
                $offset++;
                continue;
            }

            $value   = null;
            $temp    = substr($input, $offset);
            $keyword = $this->parseAlpha($temp);

            $offset += strlen($keyword);

            if ($input[$offset] != '=') {
                throw new \InvalidArgumentException(
                    sprintf('Expected "=" at offset %d, got %s', $offset, $input[$offset])
                );
            }

            $offset++;

            $temp = substr($input, $offset);

            if (0 === strlen($temp)) {
                // empty value, end of line
                $value = '';
            } elseif ($input[$offset] == ' ') {
                // empty value, more keywords remain
                $value = '';
                $offset += 1;
            } elseif ($input[$offset] == '"') {
                $value = $this->parseQuotedString($temp);
                $offset += strlen($value) + 3;
            } else {
                $value = $this->parseNonSpDquote($temp);
                $offset += strlen($value) + 1;
            }

            $eventData[$keyword] = $value;

        } while ($offset < strlen($input));

        return $eventData;
    }

    public function parseAlpha($input)
    {
        if (preg_match('/([a-zA-Z_]{1,})/', $input, $match)) {
            return $match[1];
        } else {
            throw new \InvalidArgumentException("Illegal keyword format");
        }
    }

    public function parseQuotedString($input)
    {
        $len = strlen($input);
        $val = '';
        $terminated = false;

        for ($i = 1; $i < $len; ++$i) {
            $c = $input[$i];

            if ($c == '"') {
                if (strlen($val) > 1 && $val[strlen($val)-1] != '\\') {
                    $terminated = true;
                    break;
                }
            }

            if (preg_match('/[\x01-\x08\x0b\x0c\x0e-\x7f]/', $c)) {
                $val .= $c;
            }
        }

        if (!$terminated) {
            throw new \InvalidArgumentException("Unterminated quote string encountered");
        }

        return $val;
    }

    public function parseNonSpDquote($input)
    {
        if (preg_match('/^([\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]+)(?:\s|$)/', $input, $match)) {
            return $match[1];
        } else {
            throw new \InvalidArgumentException("Illegal keyword argument string encountered: $input");
        }
    }

    public function parseDelimitedData($data, $prefix = null, $delimiter = '=', $boundary = ' ')
    {
        return $this->_parseDelimitedData($data, $prefix, $delimiter, $boundary);
    }

    private function _parseDelimitedData($data, $prefix = null, $delimiter = '=', $boundary = ' ')
    {
        $return = [];

        if ($prefix && is_string($prefix)) {
            $data = preg_replace('/^' . preg_quote($prefix) . ' /', '', $data);
        }

        $eof    = true;
        $item   = '';
        $value  = '';
        $state  = 'i';
        $quoted = false;
        $length = strlen($data);

        for ($p = 0; $p < $length; ++$p) {
            $c   = $data[$p];
            $eof = $p + 1 >= $length;

            switch ($state) {
                case 'i':
                    if ($c == $delimiter) {
                        $state = 'd';
                    } else {
                        $item .= $c;
                    }
                    break;

                case 'd':
                    if ($c == '"') {
                        $quoted = true;
                        $state  = 'dr';
                    } else {
                        $value .= $c;
                        $quoted = false;
                        $state  = 'dr';
                    }
                    break;

                /** @noinspection PhpMissingBreakStatementInspection */
                case 'dr':
                    if ((!$quoted && $c == $boundary) || ($quoted && $c == '"')) {
                        $state = 'n'; // fall through to next case
                    } else {
                        $value .= $c;
                        break;
                    }

                case 'n':
                    $return[$item] = $value;
                    $item = $value = '';
                    $state = 'i';
                    $quoted = false;
                    break;
            }
        }

        if ($eof) {
            if ($quoted) {
                throw new \Exception("EOF encountering while parsing quoted value in delimited data");
            }

            $return[$item] = $value;
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
