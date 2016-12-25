<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     RouterDescriptor.php
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
 * RouterDescriptor class.  This class holds all the data relating to a Tor
 * node on the network such as nickname, fingerprint, IP address etc.
 *
 */
class RouterDescriptor
{
    /** @var string The OR's nickname */
    public $nickname;

    /** @var string Hash of its identity key, encoded in base64, with trailing equals sign(s) removed */
    public $fingerprint;

    /** @var string Hash of its most recent descriptor as signed, encoded in base64 */
    public $digest;

    /** @var string Publication time of its most recent descriptor as YYYY-MM-DD HH:MM:SS, in UTC */
    public $published;

    /** @var string OR's current IP address */
    public $ip_address;

    /** @var string OR's current IPv6 address (if using IPv6) */
    public $ipv6_address;

    /** @var int OR's current port */
    public $or_port;

    /** @var int OR's current directory port, or 0 for none */
    public $dir_port;

    /** @var array Additional IP addresses of the OR */
    public $or_address = array();

    /** @var string The version of the Tor protocol that this relay is running */
    public $platform;

    /** @var string Contact info for the OR as given by the operator */
    public $contact;

    /** @var array Array of relay nicknames or hex digests run by an operator */
    public $family;

    /** @var int OR uptime in seconds at the time of publication */
    public $uptime;

    /** @var bool resent only if the router allows single-hop circuits to make exit connections.  Most Tor relays do not support this */
    public $allow_single_hop_exits = false;

    /** @var bool Present only if this router is a directory cache that provides extra-info documents */
    public $caches_extra_info = false;

    /** @var string a public key in PEM format. This key is used to encrypt CREATE cells for this OR */
    public $onion_key;

    /** @var string base-64-encoded-key. A public key used for the ntor circuit extended handshake */
    public $ntor_onion_key;

    /** @var a public key in PEM format. The OR's long-term identity key.  It MUST be 1024 bits. */
    public $signing_key;

    /** @var string The "SIGNATURE" object contains a signature of the PKCS1-padded hash of the entire server descriptor */
    public $router_signature;

    /** @var string Ed25519 master key */
    public $ed25519_key;

    /** @var string Ed25519 router signature */
    public $ed25519_sig;

    /** @var string Ed25519 identity key in PEM format */
    public $ed25519_identity;

    /** @var string RSA signature of sha1 hash of identity key & ed25519 identity key */
    public $onion_key_crosscert;

    /** @var string Ed25519 certificate */
    public $ntor_onion_key_crosscert;

    /** @var string sign bit of the ntor_onion_key_crosscert */
    public $ntor_onion_key_crosscert_signbit;

    /** @var string space-separated sequences of numbers, to indicate which protocols the server supports.  As of 30 Mar 2008, specified protocols are "Link 1 2 Circuit 1" */
    public $protocols;

    /** @var array Array of protocols (Cons, Desc, DirCache, HSDir, HSIntro,
     * HSRend, Link, LinkAuth, Microdesc) and versions supported by a relay.
     * Each protocol key contains an array with each invididual version of
     * that protocol supported. */
    public $proto = array();

    /** @var string a hex-encoded digest of the router's extra-info document, as signed in the router's extra-info */
    public $extra_info_digest;

    /** @var bool Present only if this router stores and serves hidden service descriptors. */
    public $hidden_service_dir;

    /** @var int An estimate of the bandwidth of this relay, in an arbitrary unit (currently kilobytes per second) */
    public $bandwidth;

    /** @var int indicates a measured bandwidth currently produced by measuring stream capacities */
    public $bandwidth_measured;

    /** @var int From consensus when bandwidth value is not based on a threshold of 3 or more measurements for this relay */
    public $bandwidth_unmeasured;


    /** @var int volume per second that the OR is willing to sustain over long periods */
    public $bandwidth_average;

    /** @var int volume that the OR is willing to sustain in very short intervals */
    public $bandwidth_burst;

    /** @var int Estimate of the capacity this relay can handle */
    public $bandwidth_observed;

    /** @var array Node status flags (e.g. Exit, Fast, Guard, Running, Stable, Valid) */
    public $flags = array();

    /** @var bool Proposal 237 - This relay accepts tunnelled directory requests */
    public $tunnelled_directory_server = false;

    /** @var array IPv4 exit policy $exit_policy4['reject'] = array() and $exit_policy4['accept'] = array() */
    public $exit_policy4 = array();

    /** @var array IPv6 exit policy $exit_policy6['reject'] = array() and $exit_policy6['accept'] = array() */
    public $exit_policy6 = array();

    /** @var string 2 letter country code of the relay IP address */
    public $country = null;

    /**
     * Set one or more descriptor values from an array
     *
     * @param array $values Array of key=>value properties to set
     * @return \Dapphp\TorUtils\RouterDescriptor
     */
    public function setArray(array $values)
    {
        foreach ($values as $key => $value) {
            if ($key === 'exit_policy4' || $key === 'exit_policy6') {
                if (!is_array($this->$key))
                    $this->$key = array();

                if (!isset($this->{$key}['accept']))
                    $this->{$key}['accept'] = array();

                if (!isset($this->{$key}['reject']))
                    $this->{$key}['reject'] = array();

                if (isset($value['accept'])) {
                    if (is_array($value['accept'])) {
                        $this->{$key}['accept'] = array_merge($this->{$key}['accept'], $value['accept']);
                    } else {
                        array_push($this->{$key}['accept'], $value['accept']);
                    }
                }
                if (isset($value['reject'])) {
                    if (is_array($value['reject'])) {
                        $this->{$key}['reject'] = array_merge($this->{$key}['reject'], $value['reject']);
                    } else {
                        array_push($this->{$key}['reject'], $value['reject']);
                    }
                }
            } else if ($key === 'or_address') {
                array_push($this->{$key}, $value);
            } else if (property_exists($this, $key)) {
                $this->$key = $value;
            }
        }

        return $this;
    }

    /**
     * Get the properties of this descriptor as an array
     *
     * @return array Array of descriptor information
     */
    public function getArray()
    {
        $return = array();

        foreach ($this as $key => $value) {
            $return[$key] = $value;
        }

        return $return;
    }

    /**
     * Combine information from a second descriptor with this one.
     * Information from the second descriptor not present in $this is added.
     *
     * @param RouterDescriptor $descriptor The descriptor information to merge
     * @return RouterDescriptor $this
     */
    public function combine(RouterDescriptor $descriptor)
    {
        foreach($this as $prop => $val) {
            if (empty($val) && !empty($descriptor->$prop)) {
                $this->$prop = $descriptor->$prop;
            }
        }

        return $this;
    }

    /**
     * Return the current calculated uptime of the node based on when the
     * descriptor was published and the current time
     *
     * @return int|NULL null if $published was not set, or # of seconds the node has been up
     */
    public function getCurrentUptime($returnArray = false)
    {
        if (isset($this->published) && isset($this->uptime)) {
            $uptime = $this->uptime + time() - strtotime($this->published . ' GMT');

            if ((bool)$returnArray === false) {
                return $uptime;
            } else {
                $units = array(
                    'days'    => 86400,
                    'hours'   => 3600,
                    'minutes' => 60,
                    'seconds' => 1
                );

                $return = array();

                foreach($units as $unit => $secs) {
                    $num = intval($uptime / $secs);

                    if ($num > 0) {
                        $units[$unit] = $num;
                    } else {
                        $units[$unit] = 0;
                    }
                    $uptime %= $secs;
                }

                return $units;
            }
        } else {
            return null;
        }
    }

    public function __toString()
    {
        $str = '';

        $str .= sprintf("Nickname: %s  Fingerprint: %s\n", $this->nickname, $this->fingerprint);
        if (!empty($this->uptime)) {
            $uptime = $this->getCurrentUptime(true);
            $u      = '';
            $u     .= ($uptime['days'] > 0) ? "{$uptime['days']}d " : '';
            $u     .= ($uptime['hours'] > 0) ? "{$uptime['hours']}h " : '';
            $u     .= ($uptime['minutes'] > 0) ? "{$uptime['minutes']}m " : '';
            $u     .= ($uptime['seconds'] > 0) ? "{$uptime['seconds']}s" : '';
            $str .= sprintf("Uptime:   %s\n", trim($u));
        }
        if (!empty($this->flags)) {
            $str .= sprintf("Flags:    %s\n", implode(' ', $this->flags));
        }
        if (!empty($this->bandwidth)) {
            $str .= sprintf("Weight:   %d\n", $this->bandwidth);
        }
        if ($this->bandwidth_observed > 0) {
            $str .= sprintf("Bandwidth: %s MB/s\n", number_format($this->bandwidth_observed / 1000000.0, 2));
        }
        $str .= sprintf("Platform: %s\n", $this->platform);
        $str .= sprintf("Contact:  %s\n", $this->contact);
        $str .= sprintf("IP Addr:  %s\n", $this->ip_address);
        if (!empty($this->country)) {
            $str .= sprintf("Country:  %s\n", strtoupper($this->country));
        }
        $str .= sprintf("OR Port:  %d  Dir Port: %d\n", $this->or_port, $this->dir_port);
        $str .= sprintf("Exit Policy:\n    %s\n    %s\n", 'accept ' . (str_replace('accept ', '', implode(' ', $this->exit_policy4['accept']))),
                                                          'reject ' . (str_replace('reject ', '', implode(' ', $this->exit_policy4['reject']))));

        return $str;
    }
}
