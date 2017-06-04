<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     ControlClient.php
 *
 * Copyright (c) 2016, Drew Phillips
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
 * @copyright 2016 Drew Phillips
 * @author Drew Phillips <drew@drew-phillips.com>
 *
 */

namespace Dapphp\TorUtils;

require_once 'Parser.php';
require_once 'ProtocolReply.php';
require_once 'RouterDescriptor.php';
require_once 'ProtocolError.php';

use Dapphp\TorUtils\ProtocolReply;
use Dapphp\TorUtils\ProtocolError;
use Dapphp\TorUtils\RouterDescriptor;

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

    const GETINFO_STATUS_ORPORT    = 'net/listeners/or';
    const GETINFO_STATUS_DIRPORT   = 'net/listeners/dir';
    const GETINFO_STATUS_SOCKSPORT = 'net/listeners/socks';
    const GETINFO_STATUS_TRANSPORT = 'net/listeners/trans';
    const GETINFO_STATUS_NATDPORT  = 'net/listeners/natd';
    const GETINFO_STATUS_DNSPORT   = 'net/listeners/dns';
    const GETINFO_STATUS_CONTROLPORT = 'net/listeners/control';

    const SIGNAL_RELOAD        = 'RELOAD';
    const SIGNAL_SHUTDOWN      = 'SHUTDOWN';
    const SIGNAL_DUMP          = 'DUMP';
    const SIGNAL_DEBUG         = 'DEBUG';
    const SIGNAL_HALT          = 'HALT';
    const SIGNAL_NEWNYM        = 'NEWNYM';
    const SIGNAL_CLEARDNSCACHE = 'CLEARDNSCACHE';
    const SIGNAL_HEARTBEAT     = 'HEARTBEAT';

    /** @var addHiddenService flag to create a new private key */
    const ONION_KEYTYPE_NEW     = 'NEW';

    /** @var addHiddenService flag to create a new 1024 bit RSA private key */
    const ONION_KEYTYPE_RSA1024 = 'RSA1024';

    /** @var addHiddenService flag to use the best algorithm for NEW private key generation */
    const ONION_KEYBLOB_BEST    = 'BEST';

    /** @var addHiddenService flag for creating a new RSA 1024 bit key */
    const ONION_KEYBLOB_RSA1024 = 'RSA1024';

    /** @var Don't return the new private key when creating a hidden service.
     * Note that if "DiscardPK" flag is specified, there is no way to recreate
     * the generated keypair and the corresponding Onion Service at a later date) */
    const ONION_FLAG_DISCARDPK  = 0x01;

    /** @var Keep the hidden service running after the client disconnects from controller */
    const ONION_FLAG_DETACH     = 0x02;

    /** @var If client authorization is enabled using the "BasicAuth" flag, the
     * service will not be accessible to clients without valid authorization
     * data (configured with the "HidServAuth" option) */
    const ONION_FLAG_BASICAUTH  = 0x04;

    /** @var To guard against unexpected loss of anonymity, Tor checks that
     * the ADD_ONION "NonAnonymous" flag matches the current hidden service
     * anonymity mode.  The hidden service anonymity mode is configured using
     * the Tor options HiddenServiceSingleHopMode and HiddenServiceNonAnonymousMode */
    const ONION_FLAG_NONANON    = 0x08;

    const AUTH_SAFECOOKIE_SERVER_TO_CONTROLLER = 'Tor safe cookie authentication server-to-controller hash';
    const AUTH_SAFECOOKIE_CONTROLLER_TO_SERVER = 'Tor safe cookie authentication controller-to-server hash';

    private $_host;
    private $_port;
    private $_debug;
    private $_debugFp;
    private $_sock;
    private $_parser;
    private $_eventCallback;

    /**
     * ControlClient constructor.
     *
     * The ControlClient connects to and communicates directly with a Tor node
     * over the Tor Control protocol.
     */
    public function __construct()
    {
        $this->_host          = '127.0.0.1';
        $this->_port          = 9051;
        $this->_timeout       = 30;
        $this->_debug         = false;
        $this->_debugFp       = fopen('php://stderr', 'w');
        $this->_parser        = new Parser();
        $this->_eventCallback = null;
        $this->_protocolInfoResponse = null;
    }

    /**
     * Establish a connection to the controller
     *
     * @param string $host  The IP or hostname of the controller
     * @param string $port  The port number (default 9051)
     * @throws \Exception   Throws \Exception if the connection fails
     * @return \Dapphp\TorUtils\ControlClient
     */
    public function connect($host = null, $port = null)
    {
        if (is_null($host)) $host = $this->_host;
        if (is_null($port)) $port = $this->_port;

        $this->_protocolInfoResponse = null;

        $this->_sock = fsockopen($host, $port, $errno, $errstr, $this->_timeout);

        if (!$this->_sock) {
            throw new \Exception(
                sprintf("Failed to connect to host %s on port %d.  Error: %d - %s", $host, $port, $errno, $errstr)
            );
        }

        return $this;
    }

    /**
     * Close the control connection
     *
     * @return boolean true on success, false if an error occurred
     */
    public function quit()
    {
        if (!$this->_sock) {
            return true;
        }

        $this->sendData('QUIT');
        $reply = $this->readReply();

        if ($reply->isPositiveReply()) {
            fclose($this->_sock);
            return true;
        } else {
            fclose($this->_sock);
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
     * @param string $password Optional password used for authentication
     * @throws \Exception Throws exception if no suitable authentication methods are available
     * @throws \Dapphp\TorUtils\ProtocolError Throws ProtocolError if authentication failed (incorrect password or cookie file)
     */
    public function authenticate($password = null)
    {
        if ($this->_protocolInfoResponse === null) {
            // can only be called once per connection
            $pinfo = $this->_getProtocolInfo();
            $this->_protocolInfoResponse = $pinfo;
        } else {
            $pinfo = $this->_protocolInfoResponse;
        }

        if (in_array('NONE', $pinfo['methods'])) {
            $this->authenticateNone();
        } else if ($password !== null && in_array('HASHEDPASSWORD', $pinfo['methods'])) {
            $this->authenticatePassword($password);
        } else if (in_array('SAFECOOKIE', $pinfo['methods'])) {
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
    public function sendData($data)
    {
        $data = $data . "\r\n";
        $size = strlen($data);

        if (!is_resource($this->_sock)) {
            throw new \Exception('Not connected');
        }

        if ($this->_debug) $this->_debugOut($data, '>>> ');

        $sent = fwrite($this->_sock, $data);

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
     * @param $cmd  The name of the previous command sent to the controller
     * @return \Dapphp\TorUtils\ProtocolReply ProtocolReply object containing the response from the controller
     */
    public function readReply($cmd = null)
    {
        $reply         = new ProtocolReply($cmd);
        $evreply       = new ProtocolReply();
        $first         = true;
        $dataReply     = false;
        $handlingEvent = false;

        while (true) {
            $data = $this->_recvData();
            if ($data === false) break;

            if ($this->_isEventReplyLine($data)) {
                $handlingEvent = true;
                $evreply->appendReplyLine($data);
            } elseif ($dataReply && trim($data) == '.') {
                $data = $this->_recvData();
                if (!$this->_isEndReplyLine($data)) {
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
            } elseif (!$dataReply && $this->_isEndReplyLine($data)) {
                if ($handlingEvent) {
                    $evreply->appendReplyLine($data);
                } else {
                    if ($first || trim($data) != '250 OK') {
                        $reply->appendReplyLine($data);
                    }
                    break;
                }
            } else {
                if ($first && $this->_isDataReplyLine($data)) {
                    $dataReply = true;
                }

                $reply->appendReplyLine($data);
                $first = false;
            }

            if ($handlingEvent && $this->_isEndReplyLine($data)) {
                $handlingEvent = false;
                $this->_asyncEventHandler($evreply);
                $first     = true;
                $dataReply = false;
                $evreply   = new ProtocolReply();
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
     * @param string $params  Additional parameters to send if the keyword requires it
     * @throws \Exception     If too few parameters are passed for the $keyword used
     * @return \Dapphp\TorUtils\ProtocolReply Protocol reply from the controller
     */
    public function getInfo($keyword, $params = null)
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
        $reply = $this->readReply($cmd);

        return $reply;
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
     * @param string $descriptorNameOrID If null, get info on ALL descriptors, otherwise gets information based on the fingerprint or nickname given
     * @throws \Exception If $descriptorNameOrID is not a valid finterprint or nickname
     * @throws ProtocolError If no such descriptor was found or other protocol error
     * @return \Dapphp\TorUtils\RouterDescriptor|array Returns array if $descriptorNameOrID is null, otherwise returns a single RouterDescriptor object
     */
    public function getInfoDescriptor($descriptorNameOrID = null)
    {
        if (is_null($descriptorNameOrID)) {
            $cmd = self::GETINFO_DESCRIPTOR_ALL;
        } else if ($this->_isFingerprint($descriptorNameOrID)) {
            $cmd = self::GETINFO_DESCRIPTOR_ID;
            if ($descriptorNameOrID[0] != '$') $descriptorNameOrID = '$' . $descriptorNameOrID;
        } else if ($this->_isNickname($descriptorNameOrID)) {
            $cmd = self::GETINFO_DESCRIPTOR_NAME;
        } else {
            throw new \Exception(sprintf('"%s" is not a valid router fingerprint or nickname', $descriptorNameOrID));
        }

        $reply = $this->getInfo($cmd, $descriptorNameOrID);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        $descriptors = $this->_parser->parseDirectoryStatus($reply);

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
     * @param null|string $descriptorNameOrID The descriptor nickname or fingerprint, or null to fetch all descriptors
     * @throws \Exception If $descriptorNameOrID is not a valid finterprint or nickname
     * @throws ProtocolError
     * @return array|RouterDescriptor
     */
    public function getInfoMicroDescriptor($descriptorNameOrID = null)
    {
        if ($this->_isFingerprint($descriptorNameOrID)) {
            $cmd = self::GETINFO_UDESCRIPTOR_ID;
            if ($descriptorNameOrID[0] != '$') $descriptorNameOrID = '$' . $descriptorNameOrID;
        } else if ($this->_isNickname($descriptorNameOrID)) {
            $cmd = self::GETINFO_UDESCRIPTOR_NAME;
        } else {
            throw new \Exception(sprintf('"%s" is not a valid router fingerprint or nickname', $descriptorNameOrID));
        }

        $reply = $this->getInfo($cmd, $descriptorNameOrID);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        $descriptors = $this->_parser->parseDirectoryStatus($reply);

        if (!is_null($descriptorNameOrID)) {
            return array_shift($descriptors);
        } else {
            return $descriptors;
        }
    }

    /**
     * The latest router status info which reflects the current beliefs from
     * this Tor client about the router or routers in question.
     *
     * @param string $descriptorNameOrID Fingerprint, nickname, or null for all descriptors
     * @throws \Exception If $descriptorNameOrID is not a valid finterprint or nickname
     * @throws ProtocolError If no such descriptor was found or other protocol error
     * @return RouterDescriptor|array Returns array if $descriptorNameOrID is null, otherwise returns a single RouterDescriptor object
     */
    public function getInfoDirectoryStatus($descriptorNameOrID = null)
    {
        if (is_null($descriptorNameOrID)) {
            $cmd = self::GETINFO_NETSTATUS_ALL;
        } else if ($this->_isFingerprint($descriptorNameOrID)) {
            $cmd = self::GETINFO_NETSTATUS_ID;
            if ($descriptorNameOrID[0] != '$') $descriptorNameOrID = '$' . $descriptorNameOrID;
        } else if ($this->_isNickname($descriptorNameOrID)) {
            $cmd = self::GETINFO_NETSTATUS_NAME;
        } else {
            throw new \Exception(sprintf('"%s" is not a valid router fingerprint or nickname', $descriptorNameOrID));
        }

        $reply = $this->getInfo($cmd, $descriptorNameOrID);

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        $descriptors = $this->_parser->parseRouterStatus($reply);

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
    public function getInfoIpToCountry($ip)
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

    public function getInfoCircuitStatus()
    {
        $cmd = self::GETINFO_CIRCUITSTATUS;
        $reply = $this->getInfo($cmd);
        $circuits = array();

        if (!$reply->isPositiveReply()) {
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        } else {
            foreach($reply->getReplyLines() as $line) {
                $circuits[] = $this->_parser->parseCircuitStatusLine($line);
            }
        }

        return $circuits;
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
     * @return \Dapphp\TorUtils\ProtocolReply
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
     * @return \Dapphp\TorUtils\ProtocolReply
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
     * @return array Array with keys "or, dir, socks, trans, natd, dns"
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
        ];

        foreach ($ports as $which => $port) {
            try {
                $response = $this->getInfo($port);

                if ($response->isPositiveReply()) {
                    $line = $response[0];
                    if (preg_match_all('/"([^"]+)"/', $line, $matches));
                    $ports[$which] = $matches[1];
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
        $reply = $this->getInfo(self::GETINFO_CONFIGTEXT);

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
     * @return multitype:array Array of config values keyed by the option name
     */
    public function getConf($keywords)
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
     * @return \Dapphp\TorUtils\ControlClient
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
     * @return \Dapphp\TorUtils\ControlClient
     */
    public function signal($signal)
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
    public function addHiddenService($port, $options = array())
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
        $keyBlob = (isset($options['KeyBlob'])) ? ltrim($options['KeyBlob'], 'RSA1024:') : self::ONION_KEYBLOB_BEST;
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

        $lines = $reply->getReplyLines();

        $serviceId  = $lines['ServiceID'];
        $privateKey = (isset($lines['PrivateKey'])) ? $lines['PrivateKey'] : null;

        return array(
            'ServiceID'  => $serviceId,
            'PrivateKey' => $privateKey,
        );
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
    public function delHiddenService($serviceId)
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
     * @return \Dapphp\TorUtils\ControlClient
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
     * @return \Dapphp\TorUtils\ControlClient
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
        return $this->_host;
    }

    /**
     * Set the hostname or IP of the controller to connect to
     *
     * @param string $_host The hostname or IP
     * @return \Dapphp\TorUtils\ControlClient
     */
    public function setHost($_host)
    {
        $this->_host = $_host;
        return $this;
    }

    /**
     * Get the port number of the controller
     *
     * @return int Port number used by the controller
     */
    public function getPort()
    {
        return $this->_port;
    }

    /**
     * Set the port number of the controller to connect to
     *
     * @param int $_port The port number to connect to
     * @return \Dapphp\TorUtils\ControlClient
     */
    public function setPort($_port)
    {
        $this->_port = $_port;
        return $this;
    }

    /**
     * Sets the socket timeout for connecting to the controller
     *
     * @param int $timeout Number of seconds to wait for controller connection before timing out
     * @throws \Exception $timeout is not numeric
     * @return \Dapphp\TorUtils\ControlClient
     */
    public function setTimeout($timeout)
    {
        if (!is_numeric($timeout)) {
            throw new \Exception("Timeout must be a numeric value - '{$timeout}' given");
        }

        $this->_timeout = (int)$timeout;
        return $this;
    }

    /**
     * Gets the current timeout value for connecting
     *
     * @return int Connection timeout
     */
    public function getTimeout()
    {
        return $this->_timeout;
    }

    /**
     * Get the setting for debugging controller communcation
     *
     * @return boolean true if debug output is enabled, false if not
     */
    public function getDebug()
    {
        return $this->_debug;
    }

    /**
     * Set whether or not to enable debug output showing controller communication
     *
     * @param bool $_debug true to enable debug output, false to disable
     * @return \Dapphp\TorUtils\ControlClient
     */
    public function setDebug($_debug)
    {
        $this->_debug = (bool)$_debug;
        return $this;
    }

    /**
     * Set the file debug output will be written to (default stdout)
     * @param resource $handle A valid file handle for writing debug output
     * @return \Dapphp\TorUtils\ControlClient
     */
    public function setDebugOutputFile($handle)
    {
        if (is_resource($handle)) {
            $this->_debugFp = $handle;
        }

        return $this;
    }

    /**
     * Specify the user-defined callback for receiving data from asynchronous
     * events sent by the controller.
     *
     * The callback must accept 2 arguments: $event, and $data where $event is
     * the name of the event (e.g. ADDRMAP, NEW_CONSENSUS) and $data is the
     * content of the event (typically ProtocolReply, array, or RouterDescriptor)
     *
     * @param callback $callback A valid callback that will be called after event data is received
     * @throws \Exception If the $callback is not a callable function or method
     * @return \Dapphp\TorUtils\ControlClient
     */
    public function setAsyncEventHandler($callback)
    {
        if (!is_callable($callback)) {
            throw new \Exception('Callback provided is not callable');
        }

        $ref     = new \ReflectionFunction($callback);
        $numargs = $ref->getNumberOfRequiredParameters();

        if ($numargs < 2) {
            throw new \Exception("Supplied callback must accept 2 arguments but it accepts $numargs");
        }

        $this->_eventCallback = $callback;

        return $this;
    }

    /**
     * Sends the PROTOCOLINFO command to the controller.
     *
     * This command must only be used once before AUTHENTICATE!
     *
     * @return array Array of protocol info
     */
    private function _getProtocolInfo()
    {
        $this->sendData('PROTOCOLINFO 1');
        $reply = $this->readReply();

        $protocolInfo = $this->_parser->parseProtocolInfo($reply);

        return $protocolInfo;
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
            fclose($this->_sock); // failed auth closes connection
            throw new ProtocolError($reply[0], $reply->getStatusCode());
        }

        return true;
    }

    /**
     * Authenticate using a password
     *
     * @param string $password The password to send to the controller
     * @throws ProtocolError Authentication failed
     * @return boolean true if authenticated successfully
     */
    private function authenticatePassword($password = null)
    {
        $password = str_replace('"', '\\\\"', $password);
        $cmd      = 'AUTHENTICATE';

        $this->sendData(sprintf('%s "%s"', $cmd, $password));
        $reply = $this->readReply($cmd);

        if (!$reply->isPositiveReply()) {
            @fclose($this->_sock); // failed auth closes connection
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
    private function authenticateSafecookie($cookiePath)
    {
        if (!file_exists($cookiePath) || !is_readable($cookiePath)) {
            throw new \Exception(
                sprintf('Tor control cookie file "%s" does not exist or is not readble', $cookiePath)
            );
        } else if (filesize($cookiePath) != 32) {
            throw new \Exception('Authentication cookie is the wrong size');
        }

        $cookie = file_get_contents($cookiePath);

        $clientNonce    = $this->_generateSecureNonce(32);
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
            fclose($this->_sock);
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
    private function _isFingerprint($string)
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
    private function _isNickname($string)
    {
        return (bool)preg_match('/^[A-Z0-9]{1,19}$/i', $string);
    }

    /**
     * Generate a secure nonce for SAFECOOKIE authentication
     *
     * @param int $length Length of the secure nonce to generate
     * @return string secure nonce
     */
    private function _generateSecureNonce($length)
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
    protected function _recvData()
    {
        $recv = fgets($this->_sock);

        if ($this->_debug) $this->_debugOut($recv, '<<< ');

        return $recv;
    }

    /**
     * Event handler for processing asynchronous replies.  This method will
     * parse the response and call the user defined callback if one is set.
     *
     * @param ProtocolReply $reply Asynchronous reply sent by the controller
     */
    private function _asyncEventHandler(ProtocolReply $reply)
    {
        // if no callback is set, just return
        // at this point the event has been read and discarded from stream
        if (is_null($this->_eventCallback) || !is_callable($this->_eventCallback)) return ;

        // EVENTS
        /*
         * CIRC
         * STREAM
         * ORCONN
         * BW
         * *Log messages (Severity = "DEBUG" / "INFO" / "NOTICE" / "WARN"/ "ERR")
         * NEWDESC
         * ADDRMAP
         * AUTHDIR_NEWDESCS
         * DESCCHANGED
         * *Status events (StatusType = "STATUS_GENERAL" / "STATUS_CLIENT" / "STATUS_SERVER")
         * GUARD
         * NS
         * STREAM_BW
         * CLIENTS_SEEN
         * NEWCONSENSUS
         * BUILDTIMEOUT_SET
         * SIGNAL
         * CONF_CHANGED
         * CIRC_MINOR
         * TRANSPORT_LAUNCHED
         * CONN_BW
         * CIRC_BW
         * CELL_STATS
         * TB_EMPTY
         * HS_DESC
         * HS_DESC_CONTENT
         * NETWORK_LIVENESS
         */
        $parser      = new Parser();
        list($event) = explode(' ', $reply[0]);

        switch($event) {
            case 'NEWCONSENSUS':
            case 'NS':
                $data = $parser->parseRouterStatus($reply);
                break;

            case 'ADDRMAP':
                $data = $parser->parseAddrMap($reply[0]);
                break;

            case 'BW':
                list($bw, $read, $written) = explode(' ', $reply[0]);
                $data = array($read, $written);
                break;

            case 'CIRC':
                $data = array();

                foreach($reply->getReplyLines() as $line) {
                    $data[] = $this->_parser->parseCircuitStatusLine($line);
                }
                break;

            // TODO: add more built-in parsing of events

            default:
                $data = $reply;
                break;
        }

        call_user_func($this->_eventCallback, $event, $data);
    }

    /**
     * Check if a line of data sent from the controller is a positive reply (2xy)
     *
     * @param string $line The reply line to check
     * @return boolean true if the response is of the 200 class of responses
     */
    private function _isPositiveReply($line)
    {
        return substr($line, 0, 1) === '2'; // reply begins with 2xy
    }

    /**
     * Check if a line of data sent from the controller is a "MidReplyLine". A
     * MidReplyLine is additional data belonging to a reply
     *
     * @param string $line The line to check
     * @return bool true if line is a MidReplyLine
     */
    private function _isMidReplyLine($line)
    {
        return (bool)preg_match('/^\d{3}-/', $line);
    }

    private function _isDataReplyLine($line)
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
    private function _isEndReplyLine($line)
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
    private function _isEventReplyLine($line)
    {
        return substr($line, 0, 3) === '650';
    }

    /**
     * Write debug output message
     *
     * @param string $string The debug data to write
     * @param string $prefix Prefix to print before the line (<<< indicates data sent from controller, >>> indiates data sent to the controller)
     */
    private function _debugOut($string, $prefix)
    {
        fwrite($this->_debugFp, $prefix . $string);
    }
}
