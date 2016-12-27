<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     ProtocolReply.php
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
 * Tor ProtocolReply object.
 *
 * This object represents a reply from the Tor control protocol or directory
 * server.  The ProtocolReply holds the status code of the reply and gives
 * access to individual lines of data from the response.
 *
 */
class ProtocolReply implements \Iterator, \ArrayAccess
{
    private $_statusCode;
    private $_command;
    private $_position = 0;
    private $_lines = array();
    private $_dirty = true;
    private $_keys  = array();

    /**
     * ProtocolReply constructor.
     *
     * @param string $command The command for which the reply will be read
     * Certain command responses reply with the command that was sent.  Giving
     * the command is not necessary, but will remove it from the first line of
     * the reply *if* the command name was present in the reply and matched
     * what was given.
     */
    public function __construct($command = null)
    {
        $this->_command = $command;
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
        return $this->_command;
    }

    /**
     * Gets the status code of the reply (if set)
     *
     * @return int Response status code.
     */
    public function getStatusCode()
    {
        return $this->_statusCode;
    }

    /**
     * Returns a string representation of the reply
     *
     * @return string The reply from the controller
     */
    public function __toString()
    {
        return implode("\n", $this->_lines);
    }

    /**
     * Get the reply as an array of lines
     *
     * @return array Array of response lines
     */
    public function getReplyLines()
    {
        return $this->_lines;
    }

    /**
     * Append a line to the reply and process it.  Typically this function
     * should not be called as it is only used by the classes for building
     * the intial reply object
     *
     * @param string $line A line of data from the reply to append
     */
    public function appendReplyLine($line)
    {
        $this->_dirty = true;
        $status = null;
        $first  = sizeof($this->_lines) == 0;
        $line   = rtrim($line, "\r\n");

        if (preg_match('/^(\d{3})-' . preg_quote($this->_command, '/') . '=(.*)$/', $line, $match)) {
            // ###-COMMAND=data reply...
            $status        = $match[1];

            if (strlen(trim($match[2])) > 0) {
                $this->_lines[]= $match[2];
            }
        } else if (preg_match('/^(\d{3})\+' . preg_quote($this->_command, '/') . '=$/', $line, $match)) {
            // ###+COMMAND=
            $status = $match[1];
        } else if (preg_match('/^650(?:\+|-)/', $line)) {
            $status = 650;
            $this->_lines[] = substr($line, 4);
        } else if (preg_match('/^(\d{3})-(\w+)(?:=|\s*)(.*)$/', $line, $match)) {
            // ###-DATA RESPONSE
            // or
            // ###-Key=Value response
            $status = $match[1];

            if ($match[1][0] != '2') {
                // GETCONF can return multiple lines like "552-Unrecognized configuration key xxx"
                $this->_lines[] = $match[2] . ' ' . $match[3];
            } else {
                $this->_lines[$match[2]] = $match[3];
            }
        } else if (preg_match('/^(\d{3})\s*(.*)$/', $line, $match)) {
            // ### STATUS
            if (!$this->_statusCode) {
                $status         = $match[1];
            }
            $this->_lines[] = $match[2];
        } else {
            // other data from multi-line reply
            $this->_lines[] = $line;
        }

        if ($status != null && $first) {
            $this->_statusCode = $status;
        }
    }

    /**
     * Append multiple lines of data to the reply.  Typically this should not
     * be used as it is used by the classes constructing replies.
     *
     * @param array $lines Array of response lines to append
     */
    public function appendReplyLines(array $lines)
    {
        $this->_lines = array_merge($this->_lines, $lines);
        $this->_dirty = true;
    }

    /**
     * Tell if the status code of this reply indicates success or not
     *
     * @return boolean true if reply indicates success, false otherwise
     */
    public function isPositiveReply()
    {
        if (strlen($this->_statusCode) > 0) {
            return substr($this->_statusCode, 0, 1) === '2'; // reply begins with 2xy
        } else {
            return false;
        }
    }

    /**
     * (non-PHPdoc)
     * @see Iterator::rewind()
     */
    public function rewind()
    {
        $this->_position = 0;
    }

    /**
     * (non-PHPdoc)
     * @see Iterator::current()
     */
    public function current()
    {
        $key = $this->key();
        return $this->_lines[$key];
    }

    /**
     * (non-PHPdoc)
     * @see Iterator::key()
     */
    public function key()
    {
        if ($this->_dirty) {
            $this->_keys = array_keys($this->_lines);
            $this->_dirty = false;
        }
        if (isset($this->_keys[$this->_position])) {
            return $this->_keys[$this->_position];
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
        ++$this->_position;
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
     * @see ArrayAccess::offsetExists()
     */
    public function offsetExists($offset)
    {
        return isset($this->_lines[$offset]);
    }

    /**
     * (non-PHPdoc)
     * @see ArrayAccess::offsetGet()
     */
    public function offsetGet($offset)
    {
        return isset($this->_lines[$offset]) ? $this->_lines[$offset] : null;
    }

    /**
     * (non-PHPdoc)
     * @see ArrayAccess::offsetSet()
     */
    public function offsetSet($offset, $value)
    {
        if (is_null($offset)) {
            $this->_lines[] = $value;
            $this->_dirty   = true;
        } else {
            $this->_lines[$offset] = $value;
        }
    }

    /**
     * (non-PHPdoc)
     * @see ArrayAccess::offsetUnset()
     */
    public function offsetUnset($offset)
    {
        unset($this->_lines[$offset]);
        $this->_dirty = true;
    }
}
