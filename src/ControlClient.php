<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     ControlClient.php
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
 * @copyright 2017 Drew Phillips
 * @author Drew Phillips <drew@drew-phillips.com>
 *
 */

namespace Dapphp\TorUtils;

/**
 * Tor ControlClient class
 *
 * A class for interacting with a Tor node using Tor's control protocol.
 *
 * @author     Drew Phillips <drew@drew-phillips.com>
 *
 */
class ControlClient
{
    const GETINFO_VERSION          = 'version';
    const GETINFO_VERSION_CURRENT  = 'status/version/current';
    const GETINFO_VERSION_RECOMMENDED = 'status/version/recommended';
    const GETINFO_CFGFILE          = 'config-file';
    const GETINFO_DESCRIPTOR_ALL   = 'desc/all';
    const GETINFO_DESCRIPTOR_ID    = 'desc/id/%s';
    const GETINFO_DESCRIPTOR_NAME  = 'desc/name/%s';
    const GETINFO_UDECRIPTOR_ALL   = 'md/all'; // All known microdescriptors - first implemented in 0.3.5.1-alpha
    const GETINFO_UDESCRIPTOR_ID   = 'md/id/%s';
    const GETINFO_UDESCRIPTOR_NAME = 'md/name/%s';
    const GETINFO_DORMANT          = 'dormant';
    const GETINFO_NETSTATUS_ALL    = 'ns/all';
    const GETINFO_NETSTATUS_ID     = 'ns/id/%s';
    const GETINFO_NETSTATUS_NAME   = 'ns/name/%s';
    const GETINFO_DIRSTATUS_ALL    = 'dir/server/all';
    const GETINFO_ADDRESS          = 'address';
    const GETINFO_FINGERPRINT      = 'fingerprint';
    const GETINFO_TRAFFICREAD      = 'traffic/read';
    const GETINFO_TRAFFICWRITTEN   = 'traffic/written';
    const GETINFO_ENTRY_GUARDS     = 'entry-guards';
    const GETINFO_IP2COUNTRY       = 'ip-to-country/%s';
    const GETINFO_CONFIGNAMES      = 'config/names';
    const GETINFO_CONFIGTEXT       = 'config-text';
    const GETINFO_CIRCUITSTATUS    = 'circuit-status';
    const GETINFO_CURTIME_LOCAL    = 'current-time/local';
    const GETINFO_CURTIME_UTC      = 'current-time/utc';
    const GETINFO_UPTIME           = 'uptime';

    const GETINFO_STATUS_ORPORT    = 'net/listeners/or';
    const GETINFO_STATUS_DIRPORT   = 'net/listeners/dir';
    const GETINFO_STATUS_SOCKSPORT = 'net/listeners/socks';
    const GETINFO_STATUS_TRANSPORT = 'net/listeners/trans';
    const GETINFO_STATUS_NATDPORT  = 'net/listeners/natd';
    const GETINFO_STATUS_DNSPORT   = 'net/listeners/dns';
    const GETINFO_STATUS_CONTROLPORT = 'net/listeners/control';
    // The extor and httptunnel lists were added in 0.3.2.12, 0.3.3.10, and
    // 0.3.4.6-rc.
    const GETINFO_STATUS_EXTORPORT = 'net/listeners/extor';
    const GETINFO_STATUS_HTTPTUNPORT = 'net/listeners/httptunnel';

    const SIGNAL_RELOAD        = 'RELOAD';
    const SIGNAL_SHUTDOWN      = 'SHUTDOWN';
    const SIGNAL_DUMP          = 'DUMP';
    const SIGNAL_DEBUG         = 'DEBUG';
    const SIGNAL_HALT          = 'HALT';
    const SIGNAL_NEWNYM        = 'NEWNYM';
    const SIGNAL_CLEARDNSCACHE = 'CLEARDNSCACHE';
    const SIGNAL_HEARTBEAT     = 'HEARTBEAT';
    // Signals to tell Tor to become active or dormant (added in 0.4.0.1-alpha)
    const SIGNAL_ACTIVE        = 'ACTIVE';
    const SIGNAL_DORMANT       = 'DORMANT';

    /** @var string addHiddenService flag to create a new private key */
    const ONION_KEYTYPE_NEW     = 'NEW';

    /** @var string addHiddenService flag to create a new 1024 bit RSA private key */
    const ONION_KEYTYPE_RSA1024 = 'RSA1024';

    /** @var string addHiddenService flag to create a next gen onion key using curve25519 */
    const ONION_KEYTYPE_CURVE25519 = 'ED25519-V3';

    /** @var string addHiddenService flag to use the best algorithm for NEW private key generation */
    const ONION_KEYBLOB_BEST    = 'BEST';

    /** @var Don't return the new private key when creating a hidden service.
     * Note that if "DiscardPK" flag is specified, there is no way to recreate
     * the generated keypair and the corresponding Onion Service at a later date) */
    const ONION_FLAG_DISCARDPK  = 0x01;

    /** @var int Keep the hidden service running after the client disconnects from controller */
    const ONION_FLAG_DETACH     = 0x02;

    /** @var int If client authorization is enabled using the "BasicAuth" flag, the
     * service will not be accessible to clients without valid authorization
     * data (configured with the "HidServAuth" option) */
    const ONION_FLAG_BASICAUTH  = 0x04;

    /** @var int To guard against unexpected loss of anonymity, Tor checks that
     * the ADD_ONION "NonAnonymous" flag matches the current hidden service
     * anonymity mode.  The hidden service anonymity mode is configured using
     * the Tor options HiddenServiceSingleHopMode and HiddenServiceNonAnonymousMode */
    const ONION_FLAG_NONANON    = 0x08;

    const AUTH_SAFECOOKIE_SERVER_TO_CONTROLLER = 'Tor safe cookie authentication server-to-controller hash';
    const AUTH_SAFECOOKIE_CONTROLLER_TO_SERVER = 'Tor safe cookie authentication controller-to-server hash';

    protected $host;
    protected $port;
    protected $timeout;
    protected $debug;
    protected $debugFp;
    protected $sock;
    protected $parser;
    protected $protocolInfoResponse;
    protected $eventCallback;
    protected $knownEvents;

    /**
     * ControlClient constructor.
     *
     * The ControlClient connects to and communicates directly with a Tor node
     * over the Tor Control protocol.
     */
    public function __construct()
    {
        $this->host          = '127.0.0.1';
        $this->port          = 9051;
        $this->timeout       = 30;
        $this->debug         = false;
        $this->debugFp       = fopen('php://stderr', 'w');
        $this->parser        = new Parser();
        $this->eventCallback  = null;
        $this->knownEvents    = [];
        $this->protocolInfoResponse = null;
    }

    /**
     * Establish a connection to the controller
     *
     * @param ?string $host  The IP or hostname of the controller
     * @param ?string $port  The port number (default 9051)
     * @throws \Exception   Throws \Exception if the connection fails
     * @return self
     */
    public function connect(?string $host = null, ?string $port = null)
    {
        if (is_null($host)) $host = $this->host;
        if (is_null($port)) $port = $this->port;

        $this->protocolInfoResponse = null;

        $this->sock = fsockopen($host, $port, $errno, $errstr, $this->timeout);

        if (!$this->sock) {
            throw new \Exception(
                sprintf("Failed to connect to host %s on port %d.  Error: %d - %s", $host, $port, $errno, $errstr)
            );
        }

        return $this;
    }

    /**
     * Close the control connection
     *
     * @throws \Exception If the socket is not connected or a read/write error occurs
     * @return boolean true on success, false if an error occurred
     */
    public function quit()
    {
        if (!$this->sock) {
            return true;
        }

        $this->sendData('QUIT');
        $reply = $this->readReply();

        if ($reply->isPositiveReply()) {
            fclose($this->sock);
            return true;
        } else {
            fclose($this->sock);
            return false;
        }
    }

    /**
     * Authenticate with the controller.
     *
     * If the authentication method NONE is supported, it will be used first
     * otherwise the SAFECOOKIE method will be used (if available), and finally
     * if a password is provided the HASHEDPASSWORD authentication method will
     * be used.
     *
     * @param ?string $password Optional password used for authentication
     * @throws \Exception Throws exception if no suitable authentication methods are available or authentication fails
     * @throws ProtocolError Throws ProtocolError if authentication failed (incorrect password or cookie file)
     */
    public function authenticate(?string $password = null): void
    {
        if ($this->protocolInfoResponse === null) {
            // can only be called once per connection
            $pinfo = $this->getProtocolInfo();
            $this->protocolInfoResponse = $pinfo;
        } else {
            $pinfo = $this->protocolInfoResponse;
        }

        if (in_array('NONE', $pinfo['methods'])) {
            $this->authenticateNone();
        } elseif ($password !== null && in_array('HASHEDPASSWORD', $pinfo['methods'])) {
            $this->authenticatePassword($password);
        } elseif (in_array('SAFECOOKIE', $pinfo['methods'])) {
            $this->authenticateSafecookie($pinfo['cookiefile']);
        } else {
            throw new \Exception('No suitable authentication methods available');
        }
    }

    /**
     * Send data or a command to the controller
     *
     * @param string $data The command and data to send
     * @throws \Exception  If the socket is not connected to Tor, or the write failed
     * @return int the number of bytes sent to the controller
     */
    public function sendData(string $data): int
    {
        $data = $data . "\r\n";
        $size = strlen($data);

        if (!is_resource($this->sock)) {
            throw new \Exception('Not connected');
        }

        if ($this->debug) $this->debugOut($data, '>>> ');

        $sent = fwrite($this->sock, $data);

        if ($sent !== $size) {
            throw new \Exception('Failed to write data to control port');
        }

        return $sent;
    }

    /**
     * Read a complete reply from the controller.  Multiple line replies that
     * end with a '250 OK' will have the OK line omitted from the reply.
     *
     * This method will process asynchronous events, call the user callback for
     * async events (if any) and then continue to attempt to read a reply from
     * the controller if data is available.
     *
     * This method blocks if there is nothing to be read from the controller.
     *
     * @param null $cmd The name of the previous command sent to the controller
     * @param bool $single If true, stop reading after reading a single async event, otherwise read and process as
     *   many async events as are available and return the first non-event reply. This should normally be left false.
     * @return ProtocolReply ProtocolReply object containing the response from the controller
     * @throws ProtocolError
     */
    public function readReply($cmd = null, $single = false)
    {
        $reply         = new ProtocolReply($cmd);
        $evreply       = new ProtocolReply();
        $first         = true;
        $dataReply     = false;
        $handlingEvent = false;

        while (true) {
            $data = $this->recvData();
            if ($data === false) break;

            if ($this->isEventReplyLine($data)) {
                $handlingEvent = true;
                $evreply->appendReplyLine($data);

                if ($this->isDataReplyLine($data)) {
                    $dataReply = true;
                    $first = false;
                }
            } elseif ($dataReply && trim($data) == '.') {
                $data = $this->recvData();
                if (!$this->isEndReplyLine($data)) {
                    throw new ProtocolError('Last read "." line - expected EndReplyLine but got "' . trim($data) . '"');
                }

                if ($handlingEvent) {
                    $evreply->appendReplyLine($data);
                } else {
                    if ($first || trim($data) != '250 OK') {
                        $reply->appendReplyLine($data);
                    }
                    break;
                }
            } elseif (!$dataReply && $this->isEndReplyLine($data)) {
                if ($handlingEvent) {
                    $evreply->appendReplyLine($data);
                } else {
                    if ($first || trim($data) != '250 OK') {
                        $reply->appendReplyLine($data);
                    }
                    break;
                }
            } else {
                if ($first && $this->isDataReplyLine($data)) {
                    $dataReply = true;
                }

                if ($dataReply && $handlingEvent) {
                    $evreply->appendReplyLine($data);
                } else {
                    $reply->appendReplyLine($data);
                    $first = false;
                }
            }

            if ($handlingEvent && $this->isEndReplyLine($data)) {
                $handlingEvent = false;
                $this->asyncEventHandler($evreply);
                $first     = true;
                $dataReply = false;
                $evreply   = new ProtocolReply();

                if ($single) break;
            }
        }

        return $reply;
    }

    /**
     * Send the GETINFO command to the controller to retrieve information
     * from the controller.  Use the $keyword parameter to pass a valid
     * option to GETINFO or use a ControlClient::GETINFO_* constant.
     *
     * @param string $keyword The info keyword
     * @param ?string $params  Additional parameters to send if the keyword requires it
     * @throws \Exception     If too few parameters are passed for the $keyword used
     * @return ProtocolReply Protocol reply from the controller
     */
    public function getInfo(string $keyword, ?string $params = null)
    {
        if ($params === null) {
            $cmd = $keyword;
        } else {
            $args = func_get_args();
            array_shift($args);

            $cmd = @vsprintf($keyword, $args);
            if ($cmd === false) {
                throw new \Exception('Too few params passed to getInfo command');
            }
        }

        $this->sendData('GETINFO ' . $cmd);
        return $this->readReply($cmd);
    }

    /**
     * The latest server descriptor for a given OR
     * NOTE: Modern Tor clients do not download server descriptors by default.
     * If you get an exception "unrecognized key desc/*" then you need to use
     * microdescriptors instead (see getInfoMicroDescriptor).
     *
     * This sends a GETINFO command to the controller and parses the response
     * returning a single descriptor or array of descriptors depending on
     * the $descriptorNameOfID parameter
     *
     * @param ?string $descriptorNameOrID If null, get info on ALL descriptors, otherwise gets information based on the fingerprint or nickname given
     * @throws \Exception If $descriptorNameOrID is not a valid fingerprint or nickname
     * @throws ProtocolError If no such descriptor was found or other protocol error
     * @return RouterDescriptor|RouterDescriptor[] Returns array if $descriptorNameOrID is null, otherwise returns a single RouterDescriptor object
     */
    public function getInfoDescriptor(?string $descriptorNameOrID = null)
    {
        if (is_null($descriptorNameOrID)) {
            $cmd = self::GETINFO_DESCRIPTOR_ALL;
        } elseif ($this->isFingerprint($descriptorNameOrID)) {
            $cmd = self::GETINFO_DESCRIPTOR_ID;
            if ($descriptorNameOrID[0] != '$') $descriptorNameOrID = '$' . $descriptorNameOrID;
        } elseif ($this->isNickname($descriptorNameOrID)) {
            $cmd = self::GETINFO_DESCRIPTOR_NAME;
        } else {
            throw new \Exception(sprintf('"%s" is not a valid router fingerprint or nickname', $descriptorNameOrID));
        }

        $reply = $this->getInfo($cmd, $descriptorNameOrID);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        $descriptors = $this->parser->parseDirectoryStatus($reply);

        if (!is_null($descriptorNameOrID)) {
            return array_shift($descriptors);
        } else {
            return $descriptors;
        }
    }

    /**
     * The latest microdescriptor for a given OR.  Modern Tor clients use
     * microdescriptors, so use this, instead of getInfoDescriptor to get
     * info about an OR.
     *
     * $descriptorNameOrId can be null or '*' to fetch a complete list of
     * microdescrptors from the controller. Note: Full microdescriptor lists
     * from the controller do not include relay fingerprints, nicknames, or
     * signing keys, so the usefulness may be limited. Because these elements
     * are not available, the array of descriptors returned is indexed
     * numerically in the order in which the descriptors were returned by the
     * controller.
     *
     * @param null|string $descriptorNameOrID The descriptor nickname or fingerprint, or null|* to fetch all descriptors
     * @throws \Exception If $descriptorNameOrID is not a valid fingerprint or nickname
     * @throws ProtocolError
     *
     * @see \Dapphp\TorUtils\DirectoryClient::getAllServerDescriptors() See also getAllServerDescriptors()
     *
     * @return array|RouterDescriptor
     */
    public function getInfoMicroDescriptor($descriptorNameOrID = null)
    {
        if ($this->isFingerprint($descriptorNameOrID)) {
            $cmd = self::GETINFO_UDESCRIPTOR_ID;
            if ($descriptorNameOrID[0] != '$') $descriptorNameOrID = '$' . $descriptorNameOrID;
        } elseif ($this->isNickname($descriptorNameOrID)) {
            $cmd = self::GETINFO_UDESCRIPTOR_NAME;
        } elseif ($descriptorNameOrID == '*' || is_null($descriptorNameOrID)) {
            $cmd = self::GETINFO_UDECRIPTOR_ALL;
        } else {
            throw new \Exception(sprintf('"%s" is not a valid router fingerprint or nickname', $descriptorNameOrID));
        }

        $reply = $this->getInfo($cmd, $descriptorNameOrID);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        $descriptors = $this->parser->parseDirectoryStatus($reply);

        if (!is_null($descriptorNameOrID) && $descriptorNameOrID != '*') {
            return array_shift($descriptors);
        } else {
            return $descriptors;
        }
    }

    /**
     * The latest router status info which reflects the current beliefs from
     * this Tor client about the router or routers in question.
     *
     * @param ?string $descriptorNameOrID Fingerprint, nickname, or null for all descriptors
     * @throws \Exception If $descriptorNameOrID is not a valid finterprint or nickname
     * @throws ProtocolError If no such descriptor was found or other protocol error
     * @return RouterDescriptor|array Returns array if $descriptorNameOrID is null, otherwise returns a single RouterDescriptor object
     */
    public function getInfoDirectoryStatus(?string $descriptorNameOrID = null)
    {
        if (is_null($descriptorNameOrID)) {
            $cmd = self::GETINFO_NETSTATUS_ALL;
        } elseif ($this->isFingerprint($descriptorNameOrID)) {
            $cmd = self::GETINFO_NETSTATUS_ID;
            if ($descriptorNameOrID[0] != '$') $descriptorNameOrID = '$' . $descriptorNameOrID;
        } elseif ($this->isNickname($descriptorNameOrID)) {
            $cmd = self::GETINFO_NETSTATUS_NAME;
        } else {
            throw new \Exception(sprintf('"%s" is not a valid router fingerprint or nickname', $descriptorNameOrID));
        }

        $reply = $this->getInfo($cmd, $descriptorNameOrID);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        $descriptors = $this->parser->parseRouterStatus($reply);

        if (!is_null($descriptorNameOrID)) {
            return array_shift($descriptors);
        } else {
            return $descriptors;
        }
    }

    /**
     * Return the best guess of Tor's external IP address
     *
     * @throws ProtocolError If address could not be determined
     * @return string Tor's external IP address
     */
    public function getInfoAddress()
    {
        $cmd = self::GETINFO_ADDRESS;
        $reply = $this->getInfo($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        } else {
            return $reply[0];
        }
    }

    /**
     * Returns the country for a given IP address (uses geoipdb)
     *
     * @param string $ip  The IP address
     * @throws ProtocolError If Tor returns an error
     * @return string The 2 letter country code for the IP address
     */
    public function getInfoIpToCountry(string $ip)
    {
        $cmd   = self::GETINFO_IP2COUNTRY;
        $reply = $this->getInfo($cmd, $ip);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        } else {
            return $reply[0];
        }
    }

    /**
     * The contents of the fingerprint file that Tor writes as a relay
     *
     * @throws ProtocolError If we are not currently a relay
     * @return string Fingerprint of relay
     */
    public function getInfoFingerprint()
    {
        $cmd = self::GETINFO_FINGERPRINT;
        $reply = $this->getInfo($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        } else {
            return $reply[0];
        }
    }

    /**
     *
     * @return Event\CircuitStatus[] Array of CircuitStatus event objects
     * @throws ProtocolError
     */
    public function getInfoCircuitStatus()
    {
        $cmd      = self::GETINFO_CIRCUITSTATUS;
        $reply    = $this->getInfo($cmd);
        $circuits = [];
        $parser   = $this->getParser();

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        } else {
            for ($i = 0; $i < count($reply); ++$i) {
                $r = new ProtocolReply();
                $r->appendReplyLine('650 CIRC ' . $reply[$i]);
                $e = new Event\CircuitStatus();
                $circuits[] = $e->parse($r, $parser);
            }
        }

        return $circuits;
    }

    /**
     * Get the uptime (in seconds) of the Tor daemon.
     *
     * Requires Tor 0.3.5.1-alpha or later.
     *
     * @throws ProtocolError
     * @return int Uptime of the Tor daemon (in seconds)
     */
    public function getInfoUptime(): int
    {
        $cmd = self::GETINFO_UPTIME;
        $reply = $this->getInfo($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        } else {
            return intval($reply[0]);
        }
    }

    /**
     * Get the current UTC time as returned by the system.
     * Introduced in 0.3.4.1-alpha.
     *
     * @throws ProtocolError
     * @return string The current system time in UTC
     */
    public function getInfoCurrentTime()
    {
        $cmd = self::GETINFO_CURTIME_UTC;
        $reply = $this->getInfo($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        } else {
            return $reply[0];
        }
    }

    /**
     * Get the current local time as returned by the system.
     * Introduced in 0.3.4.1-alpha.
     *
     * @throws ProtocolError
     * @return string The current system time in the local time zone
     */
    public function getInfoCurrentLocalTime()
    {
        $cmd = self::GETINFO_CURTIME_LOCAL;
        $reply = $this->getInfo($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        } else {
            return $reply[0];
        }
    }

    /**
     * Gets the version of Tor being run by the controller
     *
     * @throws ProtocolError
     * @return string The Tor version and platform in use
     */
    public function getVersion()
    {
        $reply = $this->getInfo(self::GETINFO_VERSION);

        if ($reply->isPositiveReply()) {
            return $reply[0];
        } else {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }
    }

    /**
     * Returns the status of the current version.  One of: new, old,
     * unrecommended, recommended, new in series, obsolete, unknown.
     * @throws ProtocolError
     * @return ProtocolReply
     */
    public function getInfoStatusVersionCurrent()
    {
        $reply = $this->getInfo(self::GETINFO_VERSION_CURRENT);

        if ($reply->isPositiveReply()) {
            return $reply[0];
        } else {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }
    }

    /**
     * Returns array of currently recommended versions.
     *
     * @throws ProtocolError
     * @return array List of recommended Tor versions
     */
    public function getInfoStatusVersionRecommended()
    {
        $reply = $this->getInfo(self::GETINFO_VERSION_RECOMMENDED);

        if ($reply->isPositiveReply()) {
            return explode(',', $reply[0]);
        } else {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }
    }

    /**
     * Get the ports the Tor daemon is listening on as an array.  Each port service
     * is a key in the array.  Values are null if Tor is not listening for that
     * service, or the port number used by the service.
     *
     * Possible keys are:
     * - or: the OR port (if Tor is running in server mode)
     * - dir: the directory port (if Tor is running as a directory)
     * - socks: The SOCKS port for client connections
     * - trans: The transparent proxy port
     * - natd: NATD protocol port
     * - dns: Port to use for anonymously resolving DNS queries over Tor
     * - extorport: The for Extended ORPort connections from your pluggable transports
     * - httptunport: The port for proxy connections using the "HTTP CONNECT" protocol instead of SOCKS
     *
     * @return array Array with keys "or, dir, socks, trans, natd, dns, extorport, httptunport"
     */
    public function getListeners()
    {
        $ports = [
            'or'    => self::GETINFO_STATUS_ORPORT,
            'dir'   => self::GETINFO_STATUS_DIRPORT,
            'socks' => self::GETINFO_STATUS_SOCKSPORT,
            'trans' => self::GETINFO_STATUS_TRANSPORT,
            'natd'  => self::GETINFO_STATUS_NATDPORT,
            'dns'   => self::GETINFO_STATUS_DNSPORT,
            'extorport' => self::GETINFO_STATUS_EXTORPORT,
            'httptunport' => self::GETINFO_STATUS_HTTPTUNPORT,
        ];

        foreach ($ports as $which => $port) {
            try {
                $response = $this->getInfo($port);

                if ($response->isPositiveReply()) {
                    $line = $response[0];
                    if (preg_match('/"([^"]+)"/', $line, $matches)) {
                        $ports[$which] = $matches[1];
                    } else {
                        $ports[$which] = null;
                    }
                } else {
                    $ports[$which] = null;
                }
            } catch (\Exception $ex) {
                $ports[$which] = null;
            }
        }

        return $ports;
    }

    /**
     * Gets the total bytes read (downloaded)
     *
     * @return string The number of bytes read (downloaded)
     */
    public function getInfoTrafficRead()
    {
        $cmd = self::GETINFO_TRAFFICREAD;
        $reply = $this->getInfo($cmd);

        return $reply[0];
    }

    /**
     * Gets the total bytes written (uploaded)
     *
     * @return string The number of bytes written
     */
    public function getInfoTrafficWritten()
    {
        $cmd = self::GETINFO_TRAFFICWRITTEN;
        $reply = $this->getInfo($cmd);

        return $reply[0];
    }

    /**
     * Get the contents of the config that Tor would write if you send it a
     * SAVECONF command.
     *
     * @throws ProtocolError  If the command failed
     * @return string  The contents of the config text
     */
    public function getInfoConfigText()
    {
        $cmd = self::GETINFO_CONFIGTEXT;
        $reply = $this->getInfo($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        $config = '';

        foreach($reply as $line) {
            $parts = explode(' ', $line, 2);
            $config .= $parts[0];
            if (isset($parts[1])) $config .= ' ' . $parts[1];
            $config .= "\n";
        }

        return $config;
    }

    /**
     * Gets the current configuration values of one or more torrc option
     *
     * @param string $keywords Space separated list of keywords to get config values for
     * @throws ProtocolError If one or more options was not recognized
     * @return string[] Array of config values keyed by the option name
     */
    public function getConf(string $keywords)
    {
        $cmd = 'GETCONF';
        $this->sendData(sprintf('%s %s', $cmd, $keywords));
        $reply = $this->readReply($cmd);

        if (!$reply->isPositiveReply()) {
            $message = implode('; ', $reply->getReplyLines());
            throw new ProtocolError($message, $reply->getStatusCode());
        }

        $values = array();

        foreach($reply as $keyword => $value) {
            // $value contains the configuration value and $keyword will be the config option
            // OR $keyword will be numeric and value will look like 'keyword=value'
            if (is_int($keyword)) {
                $parts   = explode('=', $value, 2);
                $keyword = $parts[0];
                $value   = null;

                if (sizeof($parts) == 2) {
                    $value = $parts[1];
                }
            }

            $values[$keyword] = $value;
        }

        return $values;
    }

    /**
     * Set one or more configuration values for Tor
     *
     * @param array $config Array of torrc values keyed by the option name
     * @throws ProtocolError If one or more options was not recognized or could not be set
     * @return self
     */
    public function setConf(array $config)
    {
        $cmd    = 'SETCONF';
        $params = '';

        foreach($config as $keyword => $value) {
            if (strpos($value, ' ') !== false) {
                $value = trim($value, '"\'');
                $value = '"' . $value . '"';
            }

            $params .= ' ' .$keyword . '=' . $value;
        }

        $this->sendData(sprintf('%s%s', $cmd, $params));
        $reply = $this->readReply($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        return $this;
    }

    /**
     * Sends the SIGNAL command to signal the controller to react based on the
     * signal sent.
     *
     * @param string $signal The signal or a ControlClient::SIGNAL_* constant
     * @throws ProtocolError If the signal is not recognized
     * @return self
     */
    public function signal(string $signal)
    {
        $cmd = 'SIGNAL';
        $this->sendData(sprintf('%s %s', $cmd, $signal));
        $reply = $this->readReply($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        return $this;
    }

    /**
     * Tells the server to create a new Onion ("Hidden") Service, with the
     * specified private key and algorithm.  See examples/tc_CreateHiddenService.php
     * for a usage example.
     *
     * $options is an array and can contain the following keys:<br>
     * KeyType : Type of key (NEW, BEST, RSA1024)<br>
     * KeyBlob : NEW or an 1024 bit RSA private key<br>
     * Target  : Internal port the hidden service should proxy traffic to<br>
     * Flags   : Bitwise combination of ONION_FLAG_* values (or comma separate string of flags).
     *   Flags currently supported are: Detach,DiscardPK, BasicAuth, NonAnonymous (see Tor docs).
     *
     * @param int $port  The virtual port the hidden service listens on.  Corresponds to
     *   HiddenServicePort configuration value
     * @param array $options Array of additional options for creating the service
     * @throws \Exception Throws exception invalid Flags are provided
     * @throws ProtocolError If hidden service creation failed for any reason
     * @return array Returns an array with the keys ServiceID and PrivateKey.
     *   ServiceID corresponds to the onion address (without .onion) and the
     *   PrivateKey is the RSA key for the hidden service (null if ControlClient::ONION_FLAG_DISCARDPK is set)
     */
    public function addHiddenService(int $port, array $options = [])
    {
        $cmd  = 'ADD_ONION';

        /*
         The syntax is:
         "ADD_ONION" SP KeyType ":" KeyBlob
         [SP "Flags=" Flag *("," Flag)]
         1*(SP "Port=" VirtPort ["," Target])
         *(SP "ClientAuth=" ClientName [":" ClientBlob]) CRLF
         */

        // TODO: add $options support for ClientAuth.

        $keyType = (isset($options['KeyType'])) ? $options['KeyType'] : self::ONION_KEYTYPE_NEW;
        $keyBlob = (isset($options['KeyBlob'])) ? $options['KeyBlob'] : self::ONION_KEYBLOB_BEST;
        $opts    = sprintf("%s:%s", $keyType, $keyBlob);
        $flags   = '';
        $target  = ''; // target port

        if (isset($options['Flags'])) {
            if (is_string($options['Flags'])) {
                $flags = array(preg_replace('/^flags=/i', '', $flags));
            }

            if (is_array($options['Flags'])) {
                $flags = 'Flags=' . implode(',', $flags);
            } elseif (is_int($options['Flags'])) {
                if ($options['Flags'] > 0) {
                    $flags .= 'Flags=';
                    if (($options['Flags'] & self::ONION_FLAG_DISCARDPK) > 0) $flags .= 'DiscardPK,';
                    if (($options['Flags'] & self::ONION_FLAG_DETACH)    > 0) $flags .= 'Detach,';
                    if (($options['Flags'] & self::ONION_FLAG_BASICAUTH) > 0) $flags .= 'BasicAuth,';
                    if (($options['Flags'] & self::ONION_FLAG_NONANON)   > 0) $flags .= 'NonAnonymous,';
                }
            } else {
                throw new \Exception('Flags must be a combination of ONION_FLAG_* values - see documentation');
            }
        }

        if (isset($options['Target'])) {
            $target = ',' . $options['Target'];
        }

        $addCmd = sprintf("%s %s %s Port=%s%s", $cmd, $opts, rtrim($flags, ','), $port, $target);

        $this->sendData($addCmd);
        $reply = $this->readReply();

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        $values = [];
        foreach($reply->getReplyLines() as $line) {
            $values = array_merge($values, $this->getParser()->parseDelimitedData($line));
        }

        if (empty($values['ServiceID'])) {
            throw new \Exception("Failure creating hidden service. Did not get ServiceID from controller response.");
        }

        return $values;
    }

    /**
     * Delete a hidden service running on this relay by it's onion address.
     * This will usually be a service created by ControlClient::addHiddenService()
     *
     * @param string $serviceId The onion address (without .onion)
     * @throws ProtocolError If service could not be deleted
     * @return boolean Always returns true if no exception thrown
     * @see \Dapphp\TorUtils\ControlClient::addHiddenService()
     */
    public function delHiddenService(string $serviceId)
    {
        $cmd = 'DEL_ONION';

        $this->sendData(sprintf("%s %s", $cmd, $serviceId));
        $reply = $this->readReply($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        return true;
    }

    /**
     * Send the SETEVENTS command to the controller to subscribe to one or more
     * asynchronous events.
     *
     * @param array|string $events An event or array of events to subscribe to
     * @throws \Exception If $events was not a string or array
     * @throws ProtocolError If one or more events was not recognized (no events will be set)
     * @return self
     */
    public function setEvents($events)
    {
        if (is_array($events)) {
            $events = implode(' ', $events);
        } else if (!is_string($events)) {
            throw new \Exception('$events must be a string or array; ' . gettype($events) . ' given');
        }

        $cmd = 'SETEVENTS';
        $this->sendData(sprintf('%s %s', $cmd, $events));
        $reply = $this->readReply($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        return $this;
    }

    /**
     * Instruct the controller to resolve a hostname using DNS over Tor.  The
     * name resolution is done in the background.  Client can see resolved
     * addresses by subscribing to the ADDRMAP event
     *
     * @param array|string $address The hostname(s) to resolve
     * @throws \Exception
     * @throws ProtocolError Invalid address given
     * @return self
     */
    public function resolve($address)
    {
        if (is_array($address)) {
            $address = implode(' ', $address);
        } else if (!is_string($address)) {
            throw new \Exception('$address must be a string or array; ' . gettype($address) . ' given');
        }

        $cmd = 'RESOLVE';
        $this->sendData(sprintf('%s %s', $cmd, $address));
        $reply = $this->readReply($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        return $this;
    }

    /**
     * Get the hostname of the controller
     *
     * @return string The controller IP/hostname
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     * Set the hostname or IP of the controller to connect to
     *
     * @param string $host The hostname or IP
     * @return self
     */
    public function setHost(string $host)
    {
        $this->host = $host;
        return $this;
    }

    /**
     * Get the port number of the controller
     *
     * @return int Port number used by the controller
     */
    public function getPort()
    {
        return $this->port;
    }

    /**
     * Set the port number of the controller to connect to
     *
     * @param int $port The port number to connect to
     * @return self
     */
    public function setPort(int $port)
    {
        $this->port = $port;
        return $this;
    }

    /**
     * Sets the socket timeout for connecting to the controller
     *
     * @param int $timeout Number of seconds to wait for controller connection before timing out
     * @throws \Exception $timeout is not numeric
     * @return self
     */
    public function setTimeout(int $timeout)
    {
        if (!is_numeric($timeout)) {
            throw new \Exception("Timeout must be a numeric value - '{$timeout}' given");
        }

        $this->timeout = (int)$timeout;
        return $this;
    }

    /**
     * Gets the current timeout value for connecting
     *
     * @return int Connection timeout
     */
    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     * Get the setting for debugging controller communication
     *
     * @return boolean true if debug output is enabled, false if not
     */
    public function getDebug()
    {
        return $this->debug;
    }

    /**
     * Set whether or not to enable debug output showing controller communication
     *
     * @param bool $debug true to enable debug output, false to disable
     * @return self
     */
    public function setDebug(bool $debug)
    {
        $this->debug = (bool)$debug;
        return $this;
    }

    /**
     * Set the file debug output will be written to (default stdout)
     * @param resource $handle A valid file handle for writing debug output
     * @return self
     */
    public function setDebugOutputFile($handle)
    {
        if (is_resource($handle)) {
            $this->debugFp = $handle;
        }

        return $this;
    }

    /**
     * Get the Parser object used by the controller
     *
     * @return Parser
     */
    public function getParser()
    {
        return $this->parser;
    }

    /**
     * Specify the user-defined callback for receiving data from asynchronous
     * events sent by the controller.
     *
     * The callback must accept 2 arguments: $event, and $data where $event is
     * the name of the event (e.g. ADDRMAP, NEW_CONSENSUS) and $data is the
     * content of the event (typically ProtocolReply, array, or RouterDescriptor)
     *
     * @param callable $callback A valid callback that will be called after event data is received
     * @param array    $knownEvents An array of async event names that should be
     * parsed and returned as objects. If an event is subscribed to but not known
     * to the async handler, a ProtocolReply will be returned for backwards
     * compatibility instead of an AsyncEvent object. This is to protect clients
     * from changes in future versions where new event objects are introduced, but not
     * expected by the client application.
     *
     * @throws \Exception If the $callback is not a callable function or method
     * @return self
     */
    public function setAsyncEventHandler(callable $callback, array $knownEvents = [])
    {
        if (!is_callable($callback)) {
            throw new \Exception('Callback provided is not callable');
        }

        $ref     = new \ReflectionFunction($callback);
        $numargs = $ref->getNumberOfRequiredParameters();

        if ($numargs < 2) {
            throw new \Exception("Supplied callback must accept 2 arguments but it accepts $numargs");
        }

        $this->eventCallback = $callback;
        $this->knownEvents = array_map('strtoupper', $knownEvents);

        return $this;
    }

    public function waitForEvent(?int $tv_sec = NULL, ?int $tv_usec = 0): void
    {
        $read   = [ $this->sock ];
        $write  = null;
        $except = null;

        $changed = stream_select($read, $write, $except, $tv_sec, $tv_usec);

        if ($changed === false) {
            return;
        } elseif ($changed > 0) {
            $this->readReply(null, true); // invokes event handler
        }
    }

    /**
     * Sends the PROTOCOLINFO command to the controller.
     *
     * This command must only be used once before AUTHENTICATE!
     *
     * @return array Array of protocol info
     */
    private function getProtocolInfo()
    {
        $this->sendData('PROTOCOLINFO 1');
        $reply = $this->readReply();

        return $this->parser->parseProtocolInfo($reply);
    }

    /**
     * Authenticate using NONE if supported
     *
     * @throws ProtocolError Method not supported
     * @return boolean true if authenticated successfully
     */
    private function authenticateNone()
    {
        $cmd = 'AUTHENTICATE';

        $this->sendData($cmd);
        $reply = $this->readReply($cmd);

        if (!$reply->isPositiveReply()) {
            fclose($this->sock); // failed auth closes connection
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        return true;
    }

    /**
     * Authenticate using a password
     *
     * @param ?string $password The password to send to the controller
     * @throws ProtocolError Authentication failed
     * @return boolean true if authenticated successfully
     */
    private function authenticatePassword(?string $password = null)
    {
        $password = str_replace('"', '\\\\"', $password);
        $cmd      = 'AUTHENTICATE';

        $this->sendData(sprintf('%s "%s"', $cmd, $password));
        $reply = $this->readReply($cmd);

        if (!$reply->isPositiveReply()) {
            @fclose($this->sock); // failed auth closes connection
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        return true;
    }

    /**
     * Authenticate using the SAFECOOKIE method.
     *
     * @param string $cookiePath Path to tor's auth cookie file
     * @throws \Exception Cookie file not found or invalid
     * @throws ProtocolError Error with authentication or wrong cookie provided
     * @return boolean true if authenticated successfully
     */
    private function authenticateSafecookie(string $cookiePath)
    {
        if (!file_exists($cookiePath) || !is_readable($cookiePath)) {
            throw new \Exception(
                sprintf('Tor control cookie file "%s" does not exist or is not readble', $cookiePath)
            );
        } else if (filesize($cookiePath) != 32) {
            throw new \Exception('Authentication cookie is the wrong size');
        }

        $cookie = file_get_contents($cookiePath);

        $clientNonce    = $this->generateSecureNonce(32);
        $clientNonceHex = bin2hex($clientNonce);

        $cmd = 'AUTHCHALLENGE';

        $this->sendData(sprintf('%s SAFECOOKIE %s', $cmd, $clientNonceHex));
        $reply = $this->readReply($cmd);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError(
                sprintf('SAFECOOKIE auth failed with code %s: %s', $reply->getStatusCode(), $reply[0]),
                $reply->getStatusCode()
            );
        }

        $serverhash = $servernonce = null;

        // TODO: make sure we have these...
        if (preg_match('/SERVERHASH=([A-F0-9]+)/i', $reply[0], $match))  $serverhash  = $match[1];
        if (preg_match('/SERVERNONCE=([A-F0-9]+)/i', $reply[0], $match)) $servernonce = $match[1];

        $servernonceBin = hex2bin($servernonce);

        $hash = hash_hmac(
            'sha256',
            $cookie . $clientNonce . $servernonceBin,
            self::AUTH_SAFECOOKIE_SERVER_TO_CONTROLLER
        );

        if (hex2bin($hash) != hex2bin($serverhash)) {
            throw new ProtocolError('Tor provided the wrong server nonce');
        }

        $clientHash = hash_hmac(
            'sha256',
            $cookie . $clientNonce . $servernonceBin,
            self::AUTH_SAFECOOKIE_CONTROLLER_TO_SERVER
        );

        $cmd = 'AUTHENTICATE';

        $this->sendData(sprintf('%s %s', $cmd, $clientHash));
        $reply = $this->readReply($cmd);

        if (!$reply->isPositiveReply()) {
            fclose($this->sock);
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        return true;
    }

    /**
     * Check if a string is a valid fingerprint
     *
     * @param string $string The string to check as a fingerprint
     * @return bool true if valid fingerprint
     */
    protected function isFingerprint(string $string)
    {
        return (bool)preg_match('/^\$?[A-F0-9]{40}$/i', $string);
    }

    /**
     * Check if a string is a valid nickname.  Router nicknames are 1-19
     * alphanumeric characters.
     *
     * @param string $string The string to check as a nickname
     * @return boolean true if valid nickname
     */
    protected function isNickname(string $string)
    {
        return (bool)preg_match('/^[A-Z0-9]{1,19}$/i', $string);
    }

    /**
     * Generate a secure nonce for SAFECOOKIE authentication
     *
     * @param int $length Length of the secure nonce to generate
     * @return string secure nonce
     */
    private function generateSecureNonce(int $length)
    {
        if (function_exists('openssl_random_pseudo_bytes')) {
            $nonce = openssl_random_pseudo_bytes($length);
        } else {
            trigger_error('openssl extension not installed - nonce generation may be insecure', E_USER_WARNING);
            $nonce = '';

            do {
                $rand   = mt_rand(mt_getrandmax() / 2, mt_getrandmax());
                $nonce .= sha1(uniqid(microtime(true), true), true) . sha1($rand, true);
                usleep(mt_rand(100, 50000));
            } while (strlen($nonce) < $length);

            $nonce = substr($nonce, 0, $length);
        }

        return $nonce;
    }

    /**
     * Receive data from the controller
     *
     * @return string Data received
     */
    protected function recvData()
    {
        $recv = fgets($this->sock);

        if ($this->debug) $this->debugOut($recv, '<<< ');

        return $recv;
    }

    /**
     * Event handler for processing asynchronous replies.  This method will
     * parse the response and call the user defined callback if one is set.
     *
     * @param ProtocolReply $reply Asynchronous reply sent by the controller
     */
    protected function asyncEventHandler(ProtocolReply $reply)
    {
        // if no callback is set, just return
        // at this point the event has been read and discarded from stream
        if (is_null($this->eventCallback) || !is_callable($this->eventCallback)) return ;

        // EVENTS
        /*
         * x CIRC
         * x STREAM
         * ORCONN
         * x BW
         * x *Log messages (Severity = "DEBUG" / "INFO" / "NOTICE" / "WARN"/ "ERR")
         * NEWDESC
         * x ADDRMAP
         * DESCCHANGED
         * *Status events (StatusType = "STATUS_GENERAL" / "STATUS_CLIENT" / "STATUS_SERVER")
         * x GUARD
         * x NS
         * STREAM_BW
         * CLIENTS_SEEN
         * x NEWCONSENSUS
         * BUILDTIMEOUT_SET
         * x SIGNAL
         * CONF_CHANGED
         * CIRC_MINOR
         * TRANSPORT_LAUNCHED
         * CONN_BW (testing network only)
         * CIRC_BW
         * CELL_STATS (testing network only)
         * TB_EMPTY
         * HS_DESC
         * HS_DESC_CONTENT
         * NETWORK_LIVENESS
         */

        $asyncEvents = [
            'ADDRMAP' => Event\AddrMap::class,

            'BW' => Event\Bandwidth::class,
            'CIRC' => Event\CircuitStatus::class,
            'STREAM' => Event\StreamStatus::class,

            'DEBUG'  => Event\Log\Debug::class,
            'INFO'   => Event\Log\Info::class,
            'NOTICE' => Event\Log\Notice::class,
            'WARN'   => Event\Log\Warn::class,
            'ERR'    => Event\Log\Err::class,

            'GUARD' => Event\Guard::class,
            'NEWCONSENSUS' => Event\NewConsensus::class,
            'NS' => Event\NetworkStatus::class,

            'SIGNAL' => Event\Signal::class,
        ];
        $asyncEventHandlers = [];

        $parser      = $this->getParser();
        list($event) = explode(' ', $reply[0]);

        if (array_key_exists($event, $asyncEvents) && in_array($event, $this->knownEvents)) {
            if (isset($asyncEventHandlers[$event])) {
                $handler = $asyncEventHandlers[$event];
            } else {
                $evClass = $asyncEvents[$event];
                $handler = new $evClass();
            }

            $data = $handler->parse($reply, $parser);
        } else {
            $data = $reply;
        }

        call_user_func($this->eventCallback, $event, $data);
    }

    private function isDataReplyLine($line)
    {
        return (bool)preg_match('/^\d{3}\+/', $line);
    }

    /**
     * Check if a line of data sent from the controller is an "EndReplyLine".
     * An end reply line indicates the entire response to a command has now
     * been sent.
     *
     * @param string $line The reply line to check
     * @return bool true if line is an EndReplyLine
     */
    private function isEndReplyLine(string $line)
    {
        return (bool)preg_match('/^\d{3} .*\r\n$/', $line);
    }

    /**
     * Check if a line of data sent from the controller is an asynchronous
     * event reply line (650).
     *
     * @param string $line The line to check
     * @return boolean true if line is an event reply
     */
    private function isEventReplyLine(string $line)
    {
        return substr($line, 0, 3) === '650';
    }

    /**
     * Write debug output message
     *
     * @param string $message The debug data to write
     * @param string $prefix Prefix to print before the line (<<< indicates data sent from controller, >>> indicates data sent to the controller)
     */
    private function debugOut(string $message, string $prefix)
    {
        fwrite($this->debugFp, $prefix . $message);
    }
}
