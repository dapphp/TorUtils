<?php

/**
 * This class is a stub of the old CircuitStatus object which existed before
 * the \Dapphp\TorUtils\Event namespace
 */

namespace Dapphp\TorUtils\Event;

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolError;
use Dapphp\TorUtils\ProtocolReply;

class CircuitStatus extends AsyncEvent
{
    public $id;

    public $status;

    public $path = array();

    public $buildFlags = array();

    public $purpose;

    public $hsState;

    public $rendQuery;

    public $timeCreated;

    public $reason;

    public $remoteReason;

    public $socksUsername;

    public $socksPassword;

    protected $asyncEventName = 'CIRC';

    public function parse(ProtocolReply $eventReply, Parser $parser)
    {
        $line = $eventReply[0];

        if (preg_match('/^\s*CIRC /', $line)) {
            $line = preg_replace('/^\s*CIRC\s*/', '', $line);
        }

        $parts = explode(' ', $line, 3);

        if (sizeof($parts) < 3) {
            throw new ProtocolError('Error parsing circuit status, expected at least 3 parts but got ' . sizeof($parts));
        }

        $this->id     = $parts[0];
        $this->status = $parts[1];
        $line         = $parts[2];

        if (!in_array($this->status, array('LAUNCHED', 'BUILT', 'GUARD_WAIT', 'EXTENDED', 'FAILED', 'CLOSED'))) {
            throw new ProtocolError("Unknown circuit status '{$this->status}'");
        }

        if ($line[0] == '$') {
            list ($temp, $line) = explode(' ', $line, 2);
            $temp = explode(',', $temp);

            foreach($temp as $hop) {
                $fpnick = explode('~', $hop);
                // TODO: check size
                $this->path[] = array($fpnick[0], $fpnick[1], 'fingerprint' => $fpnick[0], 'nickname' => $fpnick[1]);
            }
        }

        $fields = $parser->parseKeywordArguments($line);

        foreach ($fields as $key => $value) {
            $key = $this->eventNameToProperty($key);
            $this->{$key} = $value;
        }

        if (!empty($this->buildFlags)) $this->buildFlags = explode(',', $this->buildFlags);

        return $this;
    }

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
        if ($this->timeCreated) {
            $dt  = new \DateTime($this->timeCreated, new \DateTimeZone('UTC'));
            $now = new \DateTime(null, new \DateTimeZone('UTC'));
            $int = $dt->diff($now);
            return $int->format('%hh%im');
        }
    }
}
