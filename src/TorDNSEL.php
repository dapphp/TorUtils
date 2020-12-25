<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     TorDNSEl.php
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
 * Tor DNS Exit List Checker
 *
 * This class contains a simple DNS client meant only to know enough about the DNS protocol in order to perform
 * simple DNSEL queries specific to the Tor Project's Exit List Service. TCP is not supported. Use for anything other
 * than this purpose at your own risk.
 *
 * Other options include PHP's dns_get_record() function, but this lacks any facilities for getting error information.
 * Using Pear Net_DNS2 is an alternative option.
 *
 * @package Dapphp\TorUtils
 */
class TorDNSEL
{
    private $dnsRequestTimeout = 5;

    /** @var string[] Default list of DNS servers used for Tor DNSEL checks */
    private static $dnsServers = [
        'check-01.torproject.org',
    ];

    /**
     * Check if a remote IP address is a Tor exit relay by querying the address against Tor DNS Exit List service.
     * This check sends a DNS "A" query to the $dnsServer (or the default if none is provided) and checks the answer to
     * determine if the visitor is coming from a Tor exit or not.
     *
     * @param $remoteAddr The remote IP address, (e.g. $_SERVER['REMOTE_ADDR']) (IPv4 or IPv6) - Note: IPv6 is not currently supported by TorDNSEL
     * @param null $dnsServer The DNS resolver to query against (if null it will use check-01.torproject.or)
     *  Consider using a local, caching resolver for DNSEL queries!
     * @return bool true if the visitor's IP address is a Tor exit relay, false if it is not
     * @throws \Exception
     */
    public static function isTor($remoteAddr, $dnsServer = null)
    {
        $response = self::query($remoteAddr, 1 /* A */, $dnsServer);

        if (!empty($response['answers']) && $response['answers'][0]['TYPE'] == 1) {
            return '127.0.0.2' == $response['answers'][0]['data'];
        }

        return false;
    }

    /**
     * Query the Tor DNS Exit List service for a list of relay fingerprints that belong to the supplied IP address.
     * If $remoteAddr is not a Tor exit relay, an empty array is returned.
     *
     * @param $remoteAddr The Tor exit relay IP address (IPv4 or IPv6) - Note: IPv6 is not currently supported by TorDNSEL
     * @param null $dnsServer The DNS resolver to query against (if null it will use check-01.torproject.or)
     *  Consider using a local, caching resolver for DNSEL queries!
     * @return array An array of Tor relay fingerprints, if the IP address is a Tor exit relay
     * @throws \Exception If there is a network error or the DNS query fails
     */
    public static function getFingerprints($remoteAddr, $dnsServer = null)
    {
        $response     = self::query($remoteAddr, 16 /* TXT */, $dnsServer);
        $fingerprints = [];

        foreach($response['answers'] as $answer) {
            if ($answer['TYPE'] == 16) {
                $fingerprints[] = $answer['data'];
            }
        }

        return $fingerprints;
    }

    /**
     * Query something
     *
     * @param string $remoteAddr
     * @param int $queryType
     * @param string|null $dnsServer
     * @return array
     * @throws \Exception
     */
    protected static function query($remoteAddr, $queryType, $dnsServer = null)
    {
        $dnsel = new self();

        if (empty($dnsServer)) {
            $servers = self::$dnsServers;
            shuffle($servers);
            $dnsServer = $servers[0];
        }

        return $dnsel->dnsLookup($dnsel->getTorDNSELName($remoteAddr), $queryType, $dnsServer);
    }

    public function __construct() {}

    public function getTorDNSELName($remoteIp)
    {
        // construct a hostname in the format of {remote_ip}.dnsel.torproject.org
        // where {remote_ip} is the remote (client) IP address which may or may not be a Tor exit relay

        if (strpos($remoteIp, ':') !== false) {
            $addr = $this->expandIPv6Address($remoteIp);
        } elseif (strpos($remoteIp, '.') !== false) {
            $addr = implode('.', array_reverse(explode('.', $remoteIp)));
        } else {
            throw new \InvalidArgumentException('Invalid IPv6/IPv6 address');
        }

        return sprintf(
            '%s.%s',
            $addr,
            'dnsel.torproject.org'
        );
    }

    /**
     * Perform a DNS lookup to the Tor DNS exit list service and determine
     * if the remote connection could be a Tor exit node.
     *
     * @param string $host hostname in the designated tordnsel format
     * @param string $dnsServer IP/host of the DNS server to use for querying
     * @throws \Exception DNS failures, socket failures
     * @return boolean
     */
    private function dnsLookup($host, $type, $dnsServer)
    {
        $query    = $this->generateDNSQuery($host, $type);
        $data     = $this->performDNSLookup($query, $dnsServer);

        if (!$data) {
            throw new \Exception('DNS request timed out');
        }

        $response = $this->parseDnsResponse($data);
        $this->assertPositiveResponse($response);

        if (substr($query, 0, 2) != substr($data, 0, 2)) {
            // query transaction ID does not match
            throw new \Exception('DNS answer packet transaction ID mismatch');
        }

        return $response;
    }

    public function assertPositiveResponse($response)
    {
        switch($response['header']['RCODE']) {
            case 0:
                return true;
                break;

            case 1:
                throw new \Exception('The name server was unable to interpret the query.');
                break;

            case 2:
                throw new \Exception('Server failure - The name server was unable to process this query due to a problem with the name server.');
                break;

            case 3:
                // nxdomain
                return false;
                break;

            case 4:
                throw new \Exception('Not Implemented - The name server does not support the requested kind of query.');
                break;

            case 5:
                throw new \Exception('Refused - The name server refuses to perform the specified operation for policy reasons.');
                break;

            default:
                throw new \Exception("Bad RCODE in DNS response.  RCODE = '{$response['RCODE']}'");
                break;
        }
    }

    /**
     * Generate a DNS query to send to the DNS server.  This generates a
     * simple DNS "A" query for the given hostname.
     *
     * @param string $host Hostname used in the query
     * @param int $queryType
     * @return string
     */
    private function generateDNSQuery($host, $queryType)
    {
        $id  = mt_rand(1, 0x7fff);
        $req = pack('n6',
            $id,   // Request ID
            0x100, // standard query
            1,     // # of questions
            0,     // answer RRs
            0,     // authority RRs
            0      // additional RRs
        );

        foreach (explode('.', $host) as $bit) {
            // split name levels into bits
            $l = strlen($bit);
            // append query with length of segment, and the domain bit
            $req .= chr($l) . $bit;
        }

        // null pad the name to indicate end of record
        $req .= "\0";

        $req .= pack('n2',
            $queryType,
            1  // class IN
        );

        return $req;
    }

    /**
     * Send UDP packet containing DNS request to the DNS server
     *
     * @param string $query DNS query
     * @param string $dns_server Server to query
     * @param number $port Port number of the DNS server
     * @throws \Exception Failed to send UDP packet
     * @return string DNS response or empty string if request timed out
     */
    private function performDNSLookup($query, $dns_server, $port = 53)
    {
        $fp = fsockopen('udp://' . $dns_server, $port, $errno, $errstr);

        if (!$fp) {
            throw new \Exception("Failed to send DNS request. Error {$errno}: {$errstr}");
        }

        fwrite($fp, $query);

        socket_set_timeout($fp, $this->dnsRequestTimeout);
        $resp = fread($fp, 8192);

        return $resp;
    }

    /**
     * Parses the DNS response
     *
     * @param string $data DNS response
     * @throws \Exception Failed to parse response (malformed)
     * @return array Array with parsed response
     */
    private function parseDnsResponse($data)
    {
        $p      = 0;
        $offset = array();
        $header = array();
        $rsize  = strlen($data);

        if ($rsize < 12) {
            throw new \Exception('DNS lookup failed.  Response is less than 12 octets');
        }

        // read back transaction ID
        $id = unpack('n', substr($data, $p, 2));
        $p += 2;
        $header['ID'] = $id[1];

        // read query flags
        $flags = unpack('n', substr($data, $p, 2));
        $flags = $flags[1];
        $p    += 2;

        // read flag bits
        $header['QR']     = ($flags >> 15);
        $header['Opcode'] = ($flags >> 11) & 0x0f;
        $header['AA']     = ($flags >> 10) & 1;
        $header['TC']     = ($flags >> 9) & 1;
        $header['RD']     = ($flags >> 8) & 1;
        $header['RA']     = ($flags >> 7) & 1;
        $header['RCODE']  = ($flags & 0x0f);

        if ($header['QR'] != 1) {
            throw new \Exception('DNS response QR flag is not set to response (1)');
        }

        // read count fields
        $counts = unpack('n4', substr($data, $p, 8));
        $p     += 8;

        $header['QDCOUNT'] = $counts[1];
        $header['ANCOUNT'] = $counts[2];
        $header['NSCOUNT'] = $counts[3];
        $header['ARCOUNT'] = $counts[4];

        $records               = array();
        $records['questions']  = array();
        $records['answers']    = array();
        $records['authority']  = array();
        $records['additional'] = array();

        for ($i = 0; $i < $header['QDCOUNT']; ++$i) {
            $records['questions'][] = $this->readDNSQuestion($data, $p);
        }

        for ($i = 0; $i < $header['ANCOUNT']; ++$i) {
            $records['answers'][] = $this->readDNSRR($data, $p);
        }

        for ($i = 0; $i < $header['NSCOUNT']; ++$i) {
            $records['authority'][] = $this->readDNSRR($data, $p);
        }

        for ($i = 0; $i < $header['ARCOUNT']; ++$i) {
            $records['additional'][] = $this->readDNSRR($data, $p);
        }

        return array(
            'header'     => $header,
            'questions'  => $records['questions'],
            'answers'    => $records['answers'],
            'authority'  => $records['authority'],
            'additional' => $records['additional'],
        );
    }

    /**
     * Read a DNS name from a response
     *
     * @param string $data The DNS response packet
     * @param number $offset Starting offset of $data to begin reading
     * @return string  The DNS name in the packet
     */
    private function readDNSName($data, &$offset)
    {
        $name = array();

        do {
            $len     = substr($data, $offset, 1);
            $offset += 1;

            if ($len == "\0") {
                // null terminator
                break;
            } else if ($len == "\xC0") {
                // pointer or sequence of names ending in pointer
                $off     = unpack('n', substr($data, $offset - 1, 2));
                $offset += 1;
                $noff    = $off[1] & 0x3fff;
                $name[]  = $this->readDNSName($data, $noff);
                break;
            } else {
                // name segment precended by the length of the segment
                $len      = unpack('C', $len);
                $name[]   = substr($data, $offset, $len[1]);
                $offset  += $len[1];
            }
        } while (true);

        return implode('.', $name);
    }

    /**
     * Read a DNS question section
     *
     * @param string $data The DNS response packet
     * @param number $offset Starting offset of $data to begin reading
     * @return array Array with question information
     */
    private function readDNSQuestion($data, &$offset)
    {
        $question   = array();
        $name       = $this->readDNSName($data, $offset);

        $type    = unpack('n', substr($data, $offset, 2));
        $offset += 2;
        $class   = unpack('n', substr($data, $offset, 2));
        $offset += 2;

        $question['name']      = $name;
        $question['type']      = $type[1];
        $question['class']     = $class[1];

        return $question;
    }

    /**
     * Read a DNS resource record
     *
     * @param string $data The DNS response packet
     * @param number $offset Starting offset of $data to begin reading
     * @return array Array with RR information
     */
    private function readDNSRR($data, &$offset)
    {
        $rr = array();

        $rr['name'] = $this->readDNSName($data, $offset);

        $fields = unpack('nTYPE/nCLASS/NTTL/nRDLENGTH', substr($data, $offset, 10));
        $offset += 10;

        $rdata = substr($data, $offset, $fields['RDLENGTH']);
        $offset += $fields['RDLENGTH'];

        $rr['TYPE']  = $fields['TYPE'];
        $rr['CLASS'] = $fields['CLASS'];
        $rr['TTL']   = $fields['TTL'];
        $rr['SIZE']  = $fields['RDLENGTH'];
        $rr['RDATA'] = $rdata;

        switch($rr['TYPE']) {
            /*
            A               1 a host address
            NS              2 an authoritative name server
            MD              3 a mail destination (Obsolete - use MX)
            MF              4 a mail forwarder (Obsolete - use MX)
            CNAME           5 the canonical name for an alias
            SOA             6 marks the start of a zone of authority
            MB              7 a mailbox domain name (EXPERIMENTAL)
            MG              8 a mail group member (EXPERIMENTAL)
            MR              9 a mail rename domain name (EXPERIMENTAL)
            NULL            10 a null RR (EXPERIMENTAL)
            WKS             11 a well known service description
            PTR             12 a domain name pointer
            HINFO           13 host information
            MINFO           14 mailbox or mail list information
            MX              15 mail exchange
            TXT             16 text strings
            */
            case 1: // A
                $addr = unpack('Naddr', $rr['RDATA']);
                $rr['data'] = long2ip($addr['addr']);
                break;

            case 2: // NS
                $temp = $offset - $fields['RDLENGTH'];
                $rr['data'] = $this->readDNSName($data, $temp);
                break;

            case 16: // TXT
                $txtLength  = ord(substr($rr['RDATA'], 0, 1));
                $rr['data'] = substr($rr['RDATA'], 1, $txtLength);

                break;
        }

        return $rr;
    }

    public function expandIPv6Address($address)
    {
        if (empty($address)) {
            throw new \InvalidArgumentException('IPv6 address is empty');
        }

        $address = strtolower((string)$address);
        $address = preg_replace('/^\[|\]$/', '', $address);

        if (
            substr_count($address, ':') < 2
            ||
            preg_match('/[^a-f0-9:]/', $address)
        ) {
            throw new \InvalidArgumentException('Invalid IPv6 address');
        }

        $hextets = explode(':', $address);
        $fill    = null;

        for ($i = 0; $i < sizeof($hextets); ++$i) {
            if ($hextets[$i] == '') {
                if (!is_null($fill)) {
                    $hextets[$i] = '0000';
                } else {
                    $fill = $i;
                }
            } else {
                $hextets[$i] = str_pad($hextets[$i], 4, '0', STR_PAD_LEFT);
            }
        }

        if (!is_null($fill)) {
            array_splice($hextets, $fill, 1, '0000');
            while (8 > sizeof($hextets)) {
                array_splice($hextets, $fill, 0, '0000');
            }
        }

        $expanded = join('', $hextets);

        return join('.', array_reverse(preg_split('//', $expanded, -1, PREG_SPLIT_NO_EMPTY)));
    }
}
