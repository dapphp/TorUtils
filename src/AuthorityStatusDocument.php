<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     CircuitStatus.php
 *
 * Copyright (c) 2022, Drew Phillips
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
 * @copyright 2022 Drew Phillips
 * @author Drew Phillips <drew@drew-phillips.com>
 *
 */

namespace Dapphp\TorUtils;

/**
 * AuthorityStatusDocument class.  This class models a Tor circuit.
 *
 */
class AuthorityStatusDocument
{
    /** @var int A document format version.  For this code, the latest version known is "3". */
    public $statusVersion = 0;

    /** @var string "vote" or "consensus", depending on the type of the document */
    public $voteStatus = '';

    /** @var int[] A list of supported methods for generating consensuses from votes.  Does not occur in consensuses. */
    public $consensusMethods = [];

    /** @var string The consensus method; does not occur in votes */
    public $consensusMethod = '';

    /** @var string|null The publication time for this status document (if a vote)  */
    public $published = null;

    /** @var string The start of the Interval for this vote.  Before this time, the consensus document produced from
     * this vote is not officially in use.
     */
    public $validAfter = '';

    /** @var string The time at which the next consensus should be produced; before this time, there is no point in
     * downloading another consensus, since there won't be a new one.
     */
    public $freshUntil = '';

    /** @var string The end of the Interval for this vote.  After this time, all clients should try to find a more
     * recent consensus.
     */
    public $validUntil = '';

    /** @var int The number of seconds allowed to collect votes from all authorities */
    public $voteDelaySeconds = 0;

    /** @var int The number of seconds allowed to collect signatures from all authorities */
    public $distDelaySeconds = 0;

    /** @var string[] A list of recommended Tor versions for client usage. The versions are given as defined by
     * version-spec.txt. If absent, no opinion is held about client versions.
     */
    public $clientVersions = [];

    /** @var string[] A list of recommended Tor versions for relay usage. The versions are given as defined by
     * version-spec.txt. If absent, no opinion is held about server versions.
     */
    public $serverVersions = [];

    /** @var string[] A space-separated list of all of the flags that this document might contain. */
    public $knownFlags = [];

    /** @var array A list of the internal performance thresholds that the directory authority had at the moment it was
     * forming a vote.
     */
    public $flagThresholds = [];

    /** @var string[]  */
    public $recommendedClientProtocols = [];

    /** @var string[]  */
    public $recommendedRelayProtocols = [];

    /** @var string[]  */
    public $requiredClientProtocols = [];

    /** @var string[]  */
    public $requiredRelayProtocols = [];

    /** @var array The parameters list, if present, contains a space-separated list of case-sensitive key-value pairs.
     * See param-spec.txt for a list of parameters and their meanings.
     */
    public $params = [];

    /** @var string The shared random value that was generated during the second-to-last shared randomness protocol run,
     * encoded in base64.
     */
    public $sharedRandPreviousValue = '';

    /** @var string The shared random value that was generated during the latest shared
    randomness protocol run, encoded in base64. */
    public $sharedRandCurrentValue = '';

    /** @var array  */
    public $authorities = [];

    /** @var RouterDescriptor[] A list of relays along with their information and status according to the document. */
    public $descriptors = [];

    /** @var array List of optional weights to apply to router bandwidths during path selection. Appears at most once
     * for a consensus. Does not appear in votes. */
    public $bandwidthWeights = [];

    /** @var array his is a signature of the status document, with the initial item "network-status-version", and the
     * signature item "directory-signature", using the signing key. Only one entry for a vote, and at least one for a
     * consensus.
     */
    public $directorySignatures = [];

}