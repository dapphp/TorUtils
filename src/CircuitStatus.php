<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     CircuitStatus.php
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

/**
 * CircuitStatus class.  This class models a Tor circuit.
 *
 */
class CircuitStatus
{
    public $id;

    public $status;

    public $path = array();

    public $buildFlags = array();

    public $purpose;

    public $hsState;

    public $rendQuery;

    public $created;

    public $reason;

    public $remoteReason;

    public $socksUsername;

    public $socksPassword;

    public function __toString()
    {
        $type = array('Guard', 'Middle', 'Exit');
        $path = '';
        if (sizeof($this->path) > 0) {
            $i = 1;

            foreach($this->path as $p) {
                $what  = (isset($type[$i - 1]) ? $type[$i - 1] : '');
                $path .= sprintf("  %s  %-19s", $p[0], $p[1]);

                if (!in_array('ONEHOP_TUNNEL', $this->buildFlags) && sizeof($this->path) == 3) {
                    $path .= "   $i / $what";
                }

                $path .= "\n";
                $i++;
            }
        }

        return sprintf(
            "Purpose: %-8s  Flags: %s   Circuit ID: %d   %s  %s\n" .
            "%s\n",
            $this->purpose, implode(' ', $this->buildFlags), $this->id, $this->status, $this->getAge(), $path
        );
    }

    protected function getAge()
    {
        if ($this->created) {
            $dt  = new \DateTime($this->created, new \DateTimeZone('UTC'));
            $now = new \DateTime(null, new \DateTimeZone('UTC'));
            $int = $dt->diff($now);
            return $int->format('%hh%im');
        }
    }
}
