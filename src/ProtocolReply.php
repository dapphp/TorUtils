<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     ProtocolReply.php
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
 * Tor ProtocolReply object.
 *
 * This object represents a reply from the Tor control protocol or directory
 * server.  The ProtocolReply holds the status code of the reply and gives
 * access to individual lines of data from the response.
 *
 */
class ProtocolReply implements \Iterator, \ArrayAccess, \Countable
{
    private $statusCode;
    private $command;
    private $dataReply = false;
    private $position = 0;
    private $lines = array();
    private $dirty = true;
    private $keys  = array();

    /**
     * ProtocolReply constructor.
     *
     * @param ?string $command The command for which the reply will be read
     * Certain command responses reply with the command that was sent.  Giving
     * the command is not necessary, but will remove it from the first line of
     * the reply *if* the command name was present in the reply and matched
     * what was given.
     */
    public function __construct(?string $command = null)
    {
        $this->command = $command;
    }

    /**
     * Get the name of the command set in the constructor.
     *
     * Note: this method will not return the actual name of the command in the
     * reply, it is only set if a $command was passed to the constructor.
     *
     * @return string Name of the command being parsed.
     */
    public function getCommand()
    {
        return $this->command;
    }

    /**
     * Gets the status code of the reply (if set)
     *
     * @return int Response status code.
     */
    public function getStatusCode()
    {
        return $this->statusCode;
    }

    /**
     * Returns a string representation of the reply
     *
     * @return string The reply from the controller
     */
    public function __toString()
    {
        return implode("\n", $this->lines);
    }

    /**
     * Get the reply as an array of lines
     *
     * @return array Array of response lines
     */
    public function getReplyLines()
    {
        return $this->lines;
    }

    /**
     * Append a line to the reply and process it.  Typically this function
     * should not be called as it is only used by the classes for building
     * the intial reply object
     *
     * @param string $line A line of data from the reply to append
     */
    public function appendReplyLine(string $line)
    {
        $this->dirty = true;
        $status = null;
        $first  = sizeof($this->lines) == 0;
        $line   = rtrim($line, "\r\n");

        if (preg_match('/^(\d{3})-' . preg_quote($this->command, '/') . '=(.*)$/', $line, $match)) {
            // ###-COMMAND=data reply...
            $status        = $match[1];

            if (strlen(trim($match[2])) > 0) {
                $this->lines[]= $match[2];
            }
        } elseif ($first && preg_match('/^(\d{3})\+' . preg_quote($this->command, '/') . '=$/', $line, $match)) {
            // ###+COMMAND=
            $status = $match[1];
            $this->dataReply = true;
        } elseif (preg_match('/^650[+\-]/', $line)) {
            $status = 650;
            $this->lines[] = substr($line, 4);
        } elseif (preg_match('/^(\d{3})-(.*)$/', $line, $match)) {
            // ###-DATA RESPONSE
            // or
            // ###-Key=Value response
            $status = $match[1];
            $this->lines[] = $match[2];
        } elseif (
            !$this->dataReply && (
              preg_match('/^(25\d)\s*(.*)$/', $line, $match)
              ||
              preg_match('/^([456][015]\d)\s*(.*)$/', $line, $match)
            )
        ) {
            // ### STATUS
            // https://gitweb.torproject.org/torspec.git/tree/control-spec.txt - Section 4. Replies
            // Positive completion replies begin with 25x
            if (!$this->statusCode) {
                $status = $match[1];
            }
            $this->lines[] = $match[2];
        } else {
            // other data from multi-line reply
            $this->lines[] = $line;
        }

        if ($status != null && $first) $this->statusCode = $status;
    }

    /**
     * Append multiple lines of data to the reply.  Typically this should not
     * be used as it is used by the classes constructing replies.
     *
     * @param array $lines Array of response lines to append
     */
    public function appendReplyLines(array $lines)
    {
        $this->lines = array_merge($this->lines, $lines);
        $this->dirty = true;
    }

    /**
     * Tell if the status code of this reply indicates success or not
     *
     * @return boolean true if reply indicates success, false otherwise
     */
    public function isPositiveReply()
    {
        if (strlen($this->statusCode) > 0) {
            return substr($this->statusCode, 0, 1) === '2'; // reply begins with 2xy
        } else {
            return false;
        }
    }

    public function shift(): mixed
    {
        $this->dirty = true;
        return array_shift($this->lines);
    }

    /**
     * (non-PHPdoc)
     * @see Iterator::rewind()
     */
    public function rewind()
    {
        $this->position = 0;
    }

    /**
     * (non-PHPdoc)
     * @see Iterator::current()
     */
    public function current()
    {
        $key = $this->key();
        return $this->lines[$key];
    }

    /**
     * (non-PHPdoc)
     * @see Iterator::key()
     */
    public function key()
    {
        if ($this->dirty) {
            $this->keys = array_keys($this->lines);
            $this->dirty = false;
        }
        if (isset($this->keys[$this->position])) {
            return $this->keys[$this->position];
        } else {
            return null;
        }
    }

    /**
     * (non-PHPdoc)
     * @see Iterator::next()
     */
    public function next()
    {
        ++$this->position;
    }

    /**
     * (non-PHPdoc)
     * @see Iterator::valid()
     */
    public function valid()
    {
        return ($this->key() !== null);
    }

    /**
     * (non-PHPdoc)
     * @param $offset
     * @return bool
     * @see ArrayAccess::offsetExists()
     */
    public function offsetExists($offset)
    {
        return isset($this->lines[$offset]);
    }

    /**
     * (non-PHPdoc)
     * @param $offset
     * @return mixed|null
     * @see ArrayAccess::offsetGet()
     */
    public function offsetGet($offset)
    {
        return isset($this->lines[$offset]) ? $this->lines[$offset] : null;
    }

    /**
     * (non-PHPdoc)
     * @param $offset
     * @param $value
     * @see ArrayAccess::offsetSet()
     */
    public function offsetSet($offset, $value)
    {
        if (is_null($offset)) {
            $this->lines[] = $value;
            $this->dirty   = true;
        } else {
            $this->lines[$offset] = $value;
        }
    }

    /**
     * (non-PHPdoc)
     * @param $offset
     * @see ArrayAccess::offsetUnset()
     */
    public function offsetUnset($offset)
    {
        unset($this->lines[$offset]);
        $this->dirty = true;
    }

    public function count()
    {
        return count($this->lines);
    }
}
