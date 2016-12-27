<?php

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\CircuitStatus;
use Dapphp\TorUtils\ProtocolReply;
use Dapphp\TorUtils\RouterDescriptor;
use Dapphp\TorUtils\ProtocolError;

class ParserTest extends PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider getRouterStatusReplies
     */
    public function testParseRouterStatus(ProtocolReply $reply, $expected)
    {
        $p    = new Parser();
        $desc = $p->parseRouterStatus($reply);

        $this->assertEquals($expected, array_shift($desc));
    }

    /**
     * @dataProvider getDirectoryStatusReplies
     */
    public function testParseDirectoryStatus(ProtocolReply $reply, $expected)
    {
        $p     = new Parser();
        $descs = $p->parseDirectoryStatus($reply);

        foreach($descs as $fp => $desc) {
            $this->assertArrayHasKey($fp, $expected);
            $this->assertEquals($expected[$fp], $desc);
        }
    }

    /**
     * @dataProvider getCircuitStatusLines
     */
    public function testParseCircuitStatus($line, $expected)
    {
        $p = new Parser();

        $status = $p->parseCircuitStatusLine($line);

        $this->assertEquals($expected, $status);
    }

    public function testParseProtocolInfo()
    {
        $p     = new Parser();
        $reply = new ProtocolReply('PROTOCOLINFO 1');
        $reply->appendReplyLine("250-PROTOCOLINFO 1\n");
        $reply->appendReplyLine("250-AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE=\"/var/run/tor/control.authcookie\"\n");
        $reply->appendReplyLine("250-VERSION Tor=\"0.2.9.8\"\n");
        $reply->appendReplyLine("250 OK\n");

        $info  = $p->parseProtocolInfo($reply);

        $expected = array(
            'methods'    => array('COOKIE', 'SAFECOOKIE', 'HASHEDPASSWORD'),
            'cookiefile' => '/var/run/tor/control.authcookie',
            'version'    => '0.2.9.8',
        );

        $this->assertEquals($expected, $info);
    }

    /**
     * @expectedException \Dapphp\TorUtils\ProtocolError
     */
    public function testParseBadProtocolInfo()
    {
        $p     = new Parser();
        $reply = new ProtocolReply('PROTOCOLINFO 1');
        $reply->appendReplyLine("250-PROTOCOLINFO 1\n");
        $reply->appendReplyLine("250-AUTH junk=yes\n");
        $reply->appendReplyLine("250-VERSION Tor=\"0.2.9.8\"\n");
        $reply->appendReplyLine("250 OK\n");

        $info  = $p->parseProtocolInfo($reply);
    }

    // DATA PROVIDERS
    public function getCircuitStatusLines()
    {
        // examples
//      650 CIRC 57 LAUNCHED BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:11:06.611813
//      650 CIRC 57 EXTENDED $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:11:06.611813
//      650 CIRC 57 EXTENDED $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel,$CDA994EF01449CDD2E9410709563A3FA3B92ED41~Iridium11 BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:11:06.611813
//      650 CIRC 57 EXTENDED $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel,$CDA994EF01449CDD2E9410709563A3FA3B92ED41~Iridium11,$6E94866ED8CA098BACDFD36D4E8E2B459B8A734E~niftybeaver BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:11:06.611813
//      650 CIRC 57 BUILT $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel,$CDA994EF01449CDD2E9410709563A3FA3B92ED41~Iridium11,$6E94866ED8CA098BACDFD36D4E8E2B459B8A734E~niftybeaver BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:11:06.611813
//      650 CIRC 53 CLOSED $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel,$976694388963EDC057DFEB38D013648B5986C7D8~ruselzusel,$779A383A4D0C2BE56700483353B4A5BA443DB4B2~JC BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:01:04.709941 REASON=FINISHED
//      650 CIRC 55 CLOSED $E3FC463D3072410F6618809FF6CBE97276A61B82~yoctoMCLgg BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:01:44.028248 REASON=FINISHED
//      650 CIRC 56 CLOSED $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:01:44.028326 REASON=FINISHED
//      650 CIRC 58 LAUNCHED BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:44.035229
//      650 CIRC 58 EXTENDED $E3FC463D3072410F6618809FF6CBE97276A61B82~yoctoMCLgg BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:44.035229
//      650 CIRC 58 BUILT $E3FC463D3072410F6618809FF6CBE97276A61B82~yoctoMCLgg BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:44.035229
//      650 CIRC 59 LAUNCHED BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:48.305324
//      650 CIRC 60 LAUNCHED BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:48.305396
//      650 CIRC 59 EXTENDED $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:48.305324
//      650 CIRC 59 BUILT $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:48.305324
//      650 CIRC 60 EXTENDED $FB879163DB5CAC39E936F799D599E76A1C0F6E7A~servingsize BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:48.305396
//      650 CIRC 60 BUILT $FB879163DB5CAC39E936F799D599E76A1C0F6E7A~servingsize BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:48.305396
//      595 BUILT $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel,$0D5147ED1B34FA9CFF47CFA26A9BE45DAC422E98~Moooooooooooon,$E8E71987BCB8C24DBDF1C3BB0BF3B6C76550A108~xshells BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-26T23:03:30.912344 SOCKS_USERNAME="1063549068" SOCKS_PASSWORD="3125842993"

        $data = array();

        $c = new CircuitStatus();
        $c->id = 57;
        $c->status = 'LAUNCHED';
        $c->buildFlags = array('NEED_CAPACITY');
        $c->purpose = 'GENERAL';
        $c->created = '2016-12-22T06:11:06.611813';

        $data[] = array(
            'CIRC 57 LAUNCHED BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:11:06.611813',
            $c
        );

        // next
        $c = new CircuitStatus();
        $c->id = 57;
        $c->status = 'EXTENDED';
        $c->path = array(
            array('$844AE9CAD04325E955E2BE1521563B79FE7094B7', 'Smeerboel'),
            array('$CDA994EF01449CDD2E9410709563A3FA3B92ED41', 'Iridium11'),
            array('$6E94866ED8CA098BACDFD36D4E8E2B459B8A734E', 'niftybeaver'),
        );
        $c->buildFlags = array('NEED_CAPACITY');
        $c->purpose = 'GENERAL';
        $c->created = '2016-12-22T06:11:06.611813';

        $data[] = array(
            'CIRC 57 EXTENDED $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel,$CDA994EF01449CDD2E9410709563A3FA3B92ED41~Iridium11,$6E94866ED8CA098BACDFD36D4E8E2B459B8A734E~niftybeaver BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:11:06.611813',
            $c
        );

        // next
        $c = new CircuitStatus();
        $c->id = 58;
        $c->status = 'EXTENDED';
        $c->path = array(array('$E3FC463D3072410F6618809FF6CBE97276A61B82', 'yoctoMCLgg'));
        $c->buildFlags = array('ONEHOP_TUNNEL', 'IS_INTERNAL', 'NEED_CAPACITY');
        $c->purpose = 'GENERAL';
        $c->created = '2016-12-22T06:16:44.035229';

        $data[] = array(
            'CIRC 58 EXTENDED $E3FC463D3072410F6618809FF6CBE97276A61B82~yoctoMCLgg BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:44.035229',
            $c
        );

        // next
        $c = new CircuitStatus();
        $c->id = 57;
        $c->status = 'BUILT';
        $c->path = array(
            array('$844AE9CAD04325E955E2BE1521563B79FE7094B7', 'Smeerboel'),
            array('$CDA994EF01449CDD2E9410709563A3FA3B92ED41', 'Iridium11'),
            array('$6E94866ED8CA098BACDFD36D4E8E2B459B8A734E', 'niftybeaver'),
        );
        $c->buildFlags = array('NEED_CAPACITY');
        $c->purpose = 'GENERAL';
        $c->created = '2016-12-22T06:11:06.611813';

        $data[] = array(
            'CIRC 57 BUILT $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel,$CDA994EF01449CDD2E9410709563A3FA3B92ED41~Iridium11,$6E94866ED8CA098BACDFD36D4E8E2B459B8A734E~niftybeaver BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:11:06.611813',
            $c
        );

        // next
        $c = new CircuitStatus();
        $c->id = 59;
        $c->status = 'BUILT';
        $c->path = array(
            array('$844AE9CAD04325E955E2BE1521563B79FE7094B7', 'Smeerboel'),
        );
        $c->buildFlags = array('ONEHOP_TUNNEL', 'IS_INTERNAL', 'NEED_CAPACITY');
        $c->purpose = 'GENERAL';
        $c->created = '2016-12-22T06:16:48.305324';
        $data[] = array(
            'CIRC 59 BUILT $844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:48.305324',
            $c
        );

        // next
        $c = new CircuitStatus();
        $c->id = 60;
        $c->status = 'BUILT';
        $c->path = array(
            array('$FB879163DB5CAC39E936F799D599E76A1C0F6E7A', 'servingsize')
        );
        $c->buildFlags = array('ONEHOP_TUNNEL', 'IS_INTERNAL', 'NEED_CAPACITY');
        $c->purpose = 'GENERAL';
        $c->created = '2016-12-22T06:16:48.305396';
        $data[] = array(
            'CIRC 60 BUILT $FB879163DB5CAC39E936F799D599E76A1C0F6E7A~servingsize BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:16:48.305396',
            $c
        );

        // next
        $c = new CircuitStatus();
        $c->id = 287;
        $c->status = 'CLOSED';
        $c->path = array(array('$0CF8F3E6590F45D50B70F2F7DA6605ECA6CD408F', 'torpidsFRonline4'));
        $c->buildFlags = array('ONEHOP_TUNNEL', 'IS_INTERNAL', 'NEED_CAPACITY');
        $c->purpose = 'GENERAL';
        $c->created = '2016-12-25T19:32:55.738758';
        $c->reason = 'DESTROYED';
        $c->remoteReason = 'FINISHED';

        $data[] = array(
            'CIRC 287 CLOSED $0CF8F3E6590F45D50B70F2F7DA6605ECA6CD408F~torpidsFRonline4 BUILD_FLAGS=ONEHOP_TUNNEL,IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-25T19:32:55.738758 REASON=DESTROYED REMOTE_REASON=FINISHED',
            $c
        );

        return $data;
    }

    public function getRouterStatusReplies()
    {
        $data = array();

        /* ------------------------------------------------------------------*/
        $r = new ProtocolReply();
        $r->appendReplyLine("250+ns/name/pp14guard=\n");
        $r->appendReplyLine("r pp14guard vJJNUAeGZqAgj5118pynNkX7YE0 o+XqpANtCKGFyjA38nXCNiuamIY 2016-12-25 12:38:16 50.116.4.107 443 0\n");
        $r->appendReplyLine("s Fast Guard Running Stable V2Dir Valid\n");
        $r->appendReplyLine("w Bandwidth=6370\n");
        $r->appendReplyLine(".\n");
        $r->appendReplyLine("250 OK\n");

        $desc = new RouterDescriptor();
        $desc->setArray(array(
            'fingerprint' => 'BC924D50078666A0208F9D75F29CA73645FB604D',
            'digest'      => 'A3E5EAA4036D08A185CA3037F275C2362B9A9886',
            'nickname'    => 'pp14guard',
            'ip_address'  => '50.116.4.107',
            'or_port'     => '443',
            'dir_port'    => '0',
            'flags'       => array('Fast', 'Guard', 'Running', 'Stable', 'V2Dir', 'Valid'),
            'bandwidth'   => '6370',
            'published'   => '2016-12-25 12:38:16',
        ));

        $data[] = array($r, $desc);
        /* ------------------------------------------------------------------*/
        /* ------------------------------------------------------------------*/
        $r = new ProtocolReply();
        $r->appendReplyLine("250+ns/id/7BE683E65D48141321C5ED92F075C55364AC7123=\n");
        $r->appendReplyLine("r dannenberg e+aD5l1IFBMhxe2S8HXFU2SscSM bOHeJADtRkbq8N9SUAuJcSK1gX8 2016-12-25 15:48:22 193.23.244.244 443 80\n");
        $r->appendReplyLine("s Authority Running Stable V2Dir Valid\n");
        $r->appendReplyLine("w Bandwidth=20\n");
        $r->appendReplyLine(".\n");
        $r->appendReplyLine("250 OK\n");

        $desc = new RouterDescriptor();
        $desc->setArray(array(
            'fingerprint' => '7BE683E65D48141321C5ED92F075C55364AC7123',
            'digest'      => '6CE1DE2400ED4646EAF0DF52500B897122B5817F',
            'nickname'    => 'dannenberg',
            'ip_address'  => '193.23.244.244',
            'or_port'     => '443',
            'dir_port'    => '80',
            'flags'       => array('Authority', 'Running', 'Stable', 'V2Dir', 'Valid'),
            'bandwidth'   => '20',
            'published'   => '2016-12-25 15:48:22',
        ));

        $data[] = array($r, $desc);
        /* ------------------------------------------------------------------*/
        /* ------------------------------------------------------------------*/
        $r = new ProtocolReply();
        $r->appendReplyLine("250+ns/name/MilesPrower=\n");
        $r->appendReplyLine("r MilesPrower eeFpsl5MfOmVhPbtBvN5R48j4rg 2ZsXaEd6IVmi8bIxSfhC0UjNztQ 2016-12-25 04:18:42 62.210.129.246 443 80\n");
        $r->appendReplyLine("s Exit Fast Guard HSDir Running Stable V2Dir Valid\n");
        $r->appendReplyLine("w Bandwidth=59200\n");
        $r->appendReplyLine("p accept 43,53,80,443,6660-6669,6679,6697,8008,8080,8332-8333,8888,11371,19294\n");
        $r->appendReplyLine(".\n");
        $r->appendReplyLine("250 OK\n");

        $desc = new RouterDescriptor();
        $desc->setArray(array(
            'fingerprint' => '79E169B25E4C7CE99584F6ED06F379478F23E2B8',
            'digest'      => 'D99B1768477A2159A2F1B23149F842D148CDCED4',
            'nickname'    => 'MilesPrower',
            'ip_address'  => '62.210.129.246',
            'or_port'     => '443',
            'dir_port'    => '80',
            'flags'       => array('Exit', 'Fast', 'Guard', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid'),
            'bandwidth'   => '59200',
            'published'   => '2016-12-25 04:18:42',
            'exit_policy4' => array(
                'accept' => '43,53,80,443,6660-6669,6679,6697,8008,8080,8332-8333,8888,11371,19294',
            ),
        ));

        $data[] = array($r, $desc);

        return $data;
    }

    public function getDirectoryStatusReplies()
    {
        $status = file_get_contents(__DIR__ . '/data/dir-status-1');
        $reply  = new ProtocolReply();
        $reply->appendReplyLines(explode("\n", $status));

        $desc1  = new RouterDescriptor();
        $desc1->setArray(array(
            'fingerprint' => '79E169B25E4C7CE99584F6ED06F379478F23E2B8',
            'nickname'    => 'MilesPrower',
            'ip_address'  => '62.210.129.246',
            'or_port'     => '443',
            'dir_port'    => '80',
            'platform'    => 'Tor 0.2.9.8 on Linux',
            'published'   => '2016-12-25 04:18:42',
            'contact'     => 'sysop[at]openinternet.io BTC: 1N1s2BmWqbRH4Af5jjrNkm8XChnsRmPgA5',
            'uptime'      => '460860',
            'family'      => array(
                '$383B7179FEE38D6773D4327F4B5856798BD85202',
                '$BC924D50078666A0208F9D75F29CA73645FB604D',
                '$BE953C95C98D207742A66DDC05B0A476FF2225C9',
                '$FE32CAC855ABC707ED7FEDAF720046FE914EB491',
            ),
            'bandwidth_average'    => '19660800',
            'bandwidth_burst'      => '26214400',
            'bandwidth_observed'   => '22719552',
            'hidden_service_dir'   => '2',
            'tunnelled_dir_server' => true,
            'proto' => array(
                'Cons'      => array(1, 2),
                'Desc'      => array(1, 2),
                'DirCache'  => array(1),
                'HSDir'     => array(1),
                'HSIntro'   => array(3),
                'HSRend'    => array(1, 2),
                'Link'      => array(1, 2, 3, 4),
                'LinkAuth'  => array(1),
                'Microdesc' => array(1, 2),
                'Relay'     => array(1, 2),
            ),
            'router_signature'    => "-----BEGIN SIGNATURE-----\nMzkuT987jIcEbdI2U1X5UeN7/sEHCx0Ci981bULK8P1pBaxotbJg0CaeDA2bqpYW\nHGFnvCRbXs2ChKiZgOEFhUbpCAQhbiOO5mmRLhQUlwlvyh+/9PlTn/cddQwtZkcA\nF43fc8318iP8ypVmvbHCZeryJPZLeGdMHzxTET9RWeo=\n-----END SIGNATURE-----\n",
            'ed25519_key'         => '5QeZaAtvHl7nTzSSkkkZiJ3nS52rjFHR22bunWqhsjo',
            'ed25519_identity'    => "-----BEGIN ED25519 CERT-----\nAQQABkpoAf+DJAKIzwhjVPYx9mb6gDqoQlSwXy7XShUUODjX8t6DAQAgBADlB5lo\nC28eXudPNJKSSRmInedLnauMUdHbZu6daqGyOr3J7A2Vqah4nOwhP3UIjI7Iyb+s\n9JBg0x8J/t73itfaEJt+vK+MNwroUsHaVKqGnqTyhB9B84548MF55CI/EAw=\n-----END ED25519 CERT-----\n",
            'ed25519_sig'         => 'oe+otEbietfKZxmdWDpOZ8Xhg78xjSoRLl6izosiwONLuNCSuHdY/dOEdpRakzSTk7pwYQyWfxgcybsyAziDAQ',
            'extra_info_digest'   => '2435753908F3A7C24CCABD0EA6D336C7F4B36932 j5q4h6/dTpPIyYuM2+ABiQi6gPkMpAPgu3MrUZAAEF0',
            'onion_key'           => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBALipQFp0vo/wxvUBrDbw5SamdFhLHlA9GepSauOnZA5nY1FKOW1pjygp\nDZeU1RAUqj7ST4xD6CH8IA1mAs95GIp9LrwuYunbw7NeuxELhCXwK1WphqoAw97t\n4S/sbl72lZ2b29eHxbPoNFPO+2jQbqCPcCM3kGbqWsNef4WZP5ydAgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'signing_key'         => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAMX8r0RFoXr7etUrzJqOAQx1hAeqLwMyMU3xbkBBlLXn+8wTcOvyOAKP\n3+MP3pQZyI/+oK2D0N3PLQk4CyrigF8AjR91QVAHcVxC1DOouA54seki5JoTWbZ2\nz45XOAsoekZM1K0Mb2LF6Z+7gjdtdl5D5Cdp5THpcekJDqhjuBo3AgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'onion_key_crosscert' => "-----BEGIN CROSSCERT-----\no39cQgODkckCXMWaUFjtK2txEsJHQF+xtmY58HiZUfh+IMyDNS4ulfvNCKnqEgkb\nYkeavB+buvmiPSTFreYVuIXCwzcRhlPoI7aOFpuSwnLQBf78GqK/6gigS/FCRCgp\nMnEOw5XSii/mE6eiyDYFZprEDuG+CZ5xpcaSKJdLPDA=\n-----END CROSSCERT-----\n",
            'ntor_onion_key'      => '0dmEb3q00YCLRBwacEbHtq7QashHn5ikuG8eoJ8Iwio=',
            'ntor_onion_key_crosscert_signbit' => '0',
            'ntor_onion_key_crosscert'         => "-----BEGIN ED25519 CERT-----\nAQoABkltAeUHmWgLbx5e5080kpJJGYid50udq4xR0dtm7p1qobI6ADH2H9oTEUVO\nLOw4UBPbuOBIIfhk9oMBjAPMafZGhZ97jLml49L2nv7FXPH2LqS14Rc4fYZMAO5z\np7YdmuNWrQY=\n-----END ED25519 CERT-----\n",
        ));
        $desc1->exit_policy4 = array(
            'accept' => array('*:43', '*:53', '*:80', '*:443', '*:6660-6669', '*:6679', '*:6697', '*:8008', '*:8080', '*:8332-8333', '*:8888', '*:11371', '*:19294'),
            'reject' => array('0.0.0.0/8:*', '169.254.0.0/16:*', '127.0.0.0/8:*', '192.168.0.0/16:*', '10.0.0.0/8:*', '172.16.0.0/12:*', '62.210.129.246:*', '*:*'),
        );

        $desc2 = new RouterDescriptor();
        $desc2->setArray(array(
            'fingerprint' => 'E2EC4A6D3E002866C2A49207109F72812F9D2E62',
            'nickname'    => 'OpenInternetDotIO',
            'ip_address'  => '208.113.166.5',
            'or_port'     => '443',
            'dir_port'    => '80',
            'platform'    => 'Tor 0.2.9.8 on Linux',
            'published'   => '2016-12-25 08:00:32',
            'contact'     => 'sysop[at]openinternet.io BTC: 1HYR9K2zvqTLx3nMhYJNnAGeQzMLxrfZbT',
            'uptime'      => '28859',
            'family'      => array(
                '$383B7179FEE38D6773D4327F4B5856798BD85202',
                '$BC924D50078666A0208F9D75F29CA73645FB604D',
                '$BE953C95C98D207742A66DDC05B0A476FF2225C9',
                '$FE32CAC855ABC707ED7FEDAF720046FE914EB491',
            ),
            'bandwidth_average'    => '19660800',
            'bandwidth_burst'      => '26214400',
            'bandwidth_observed'   => '697305',
            'hidden_service_dir'   => '2',
            'tunnelled_dir_server' => true,
            'proto' => array(
                'Cons'      => array(1, 2),
                'Desc'      => array(1, 2),
                'DirCache'  => array(1),
                'HSDir'     => array(1),
                'HSIntro'   => array(3),
                'HSRend'    => array(1, 2),
                'Link'      => array(1, 2, 3, 4),
                'LinkAuth'  => array(1),
                'Microdesc' => array(1, 2),
                'Relay'     => array(1, 2),
            ),
            'router_signature'    => "-----BEGIN SIGNATURE-----\nNrumpuEA8G3J/ERfcsgF/h7Id/qxXbGxRFrdV5HBQbb+Q+4buntOWLHllQNJsmEv\nhtUWkMyAdCvgqN7i+NqDO+YdqoKz1HAvBAApc4Qu6Cwdekn6jJjG4tXycooKDsWr\nG2ghL2xsYqXN4alStDjJxk+FsmG5qBgMZg/SKE+bMlM=\n-----END SIGNATURE-----\n",
            'ed25519_key'         => 'ZaYwGFMmYqv9YR3aUsQcQWiyxOFxWnHq2r8AqBHw6TA',
            'ed25519_identity'    => "-----BEGIN ED25519 CERT-----\nAQQABkuQAbKMCo8awjBiyM4JWUYWtmvi6Cg1Zzffp4MXxyDtPBmAAQAgBABlpjAY\nUyZiq/1hHdpSxBxBaLLE4XFaceravwCoEfDpMH2GK5kUYHozkNxHyHdGrS3cFRUl\npwBuHOcRPs+vodqTMyKdAAtlystrB8+n0HN2zmyIRVHMxyY8+zLdsO0pogE=\n-----END ED25519 CERT-----\n",
            'ed25519_sig'         => '1REeM71XSNVVALIC3egQ/loiA/GCmELexapyumNq8SmN42CDDb4hYj8IG3i1q3kM74hgHI2fl/SVW2oqYcMzBA',
            'extra_info_digest'   => '9C1FA959CD66521B70A8E4CA559B1933F0AE921F uPcGZnTCmVguXR6iJHO/sxgAIdMYjObZyomlU5b8hQY',
            'onion_key'           => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAMOeZHEh+rWA6Z/9CB2zi6NixxXl9SLDwYHPJOe71mtElcUXuVqBUTfg\n393ywiC3n9/cLMPGTYuVb/dJo845GwgqlePphzUrHU7yiEG07GiVa8aV8J/ScoJB\nkcqFM8hX4Bg04wfeEDVwL9qH6kr/p8UJ5cY6CbgcMj1d8I3GA/xNAgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'signing_key'         => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBALrtNxJ5y3TTToqJdmajzosf+nX4tONSQ9F4jEtbg9qEN88G57X3WdFd\nN30o0XfR1HsZ0sBiDCPOGjBzHY9/q5Y6iHOh0uocY9Jg+OH1m3oPupOfkUOcCaKe\nk3EWeR4o01mv+m+Z3gJXWN4SF4tz0gKz3hgRMVA8YTH7aZPP9bmdAgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'onion_key_crosscert' => "-----BEGIN CROSSCERT-----\nuwkh/WYZ6CaCCHZew5+7RmwvkxJI3+Lt1Vyv4z/xi3uecGlrhw7OP6hrG/9BKvRo\nUzN01Ev1/BWhcXuFqb3C/h/hna4sbhzC/XpBGL28/LtWuBQO0lbWp+xtpRMrggRt\nduvGJBR7eoV5lkPpu37Btxnb8KDd8JeC27bl0SZVkVs=\n-----END CROSSCERT-----\n",
            'ntor_onion_key'      => 'c1CpCkTTM/qnMq+W/OgA6xrXcgLW2S/A1ooENA8WsXg=',
            'ntor_onion_key_crosscert_signbit' => '0',
            'ntor_onion_key_crosscert'         => "-----BEGIN ED25519 CERT-----\nAQoABklxAWWmMBhTJmKr/WEd2lLEHEFossThcVpx6tq/AKgR8OkwAIrjVqnSM8Uh\ngFbXmowxmMxETtlC9QKCQFphBd0iEWNGO3d++5wK3SisIj8Z96JwtcMnW/eT2AtL\nDYeX/IxYQAA=\n-----END ED25519 CERT-----\n",
        ));
        $desc2->exit_policy4 = array(
            'accept' => array('*:43', '*:53', '*:80', '*:443', '*:6660-6669', '*:6679', '*:6697', '*:8008', '*:8080', '*:8332-8333', '*:8888', '*:11371', '*:19294'),
            'reject' => array('0.0.0.0/8:*', '169.254.0.0/16:*', '127.0.0.0/8:*', '192.168.0.0/16:*', '10.0.0.0/8:*', '172.16.0.0/12:*', '208.113.166.5:*', '*:*'),
        );

        $desc3 = new RouterDescriptor();
        $desc3->setArray(array(
            'fingerprint' => '988063DF0FBD3DB73A8FE1F5820712B95D248C78',
            'nickname'    => 'freedominsteadofnsa',
            'ip_address'  => '136.243.102.134',
            'or_port'     => '9001',
            'dir_port'    => '0',
            'platform'    => 'Tor 0.2.7.6 on Linux',
            'published'   => '2016-12-25 03:37:50',
            'uptime'      => '15683100',
            'protocols'   => 'Link 1 2 Circuit 1',
            'bandwidth_average'    => '550000',
            'bandwidth_burst'      => '1250000',
            'bandwidth_observed'   => '674776',
            'hidden_service_dir'   => '2',
            'router_signature'    => "-----BEGIN SIGNATURE-----\nFemsovP4PcJVbjghtwY51IDtqms2PTbVxqNBM5gnPe1CD7h1i2UTPe4V49aXs9uw\neABnOXAIgnhjwgEewqYVl6tLqU20P34RJ5z+11yxz2xaUREJwTgAuQS1lP6rjS8a\nnNvrXQksryIw5JiXE2ggECuj6boBxcgHiLnYsPjGAUw=\n-----END SIGNATURE-----\n",
            'ed25519_key'         => 'zfmHiuGm3IV4b7QbdlARTVqHuin1S7Puk0cxOOhnMn8',
            'ed25519_identity'    => "-----BEGIN ED25519 CERT-----\nAQQABkrmAZo7Mju4R2yXCW7IkJA8V/eQjSN7tUkAfoe+vp+tfnF/AQAgBADN+YeK\n4abchXhvtBt2UBFNWoe6KfVLs+6TRzE46Gcyf+EW1AN5a2DvVYiPFMaZxlL6g6ZA\nnhmxRAMa3tLiUgnS5Pje/MbCxacLzOu/IAhiHC02mABn3puRh1mqrAwFKQQ=\n-----END ED25519 CERT-----\n",
            'ed25519_sig'         => '6X8OuMRv8ieaAYrPMcH7WaDIE/kpKgkG/9rmqk4QK5Cnq3nerPwTGz7fW5kOaQdU324m6PZ1+hU4Af5x3QgEBw',
            'extra_info_digest'   => '83A0901FA2D67C12F222CC59540044C82BD27780 0g7aooa9WHEGfqfzcDBOV5MW/7g9FCBGxZpMYsWJ3QY',
            'onion_key'           => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAPOkQB6IHcNN5nMGs4Y5EoxSb5SFhB0zn7pfN1XAMoWsVehutP45+alQ\nAJOjdN+/AGRYOuodDHYE4afTmoIXox+ojS8jCS4UuE/tkpevISMXVxRklJg0mKZT\n+QAvqkxthbfsfQnWIa/A8sqm9mCg3fFANmk4pMugiIAyxIouUanhAgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'signing_key'         => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAOE88fRvAKN+vPA+Dtkq4Cpdk+ssG4gq7gtyar7qXHC+ukn+xA6e1m0p\nydVElSgSbOGMQrVTqWnGkXbf/Qe+9nu/CjclBRqAU2txIu/UEfBl5FPRdCgz6WWE\nNIKNMFG1nS6Ax9yPvYl6nct4tsYMEFOhPXi0trybl/KfPtoU4QnHAgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'onion_key_crosscert' => "-----BEGIN CROSSCERT-----\nEBV5Lwnnit96jdWp/0fGzuji0Cvz4icTlslaR+HbR77sTVpXL4FHWfKnksdvLi0+\nJ13E1eM6cfganVeLqMPKVNLxaIPNC9dGmulqaTn1DPGdok0CvQZ/Ws7ij/oVcRMI\n9EfDFXtnkA53+vP0NtN7/p2j355AgsT7wumWchMhw6g=\n-----END CROSSCERT-----\n",
            'ntor_onion_key'      => '+dnBNPxQ+ovac5yMxaTCMX66hVzr9Waw/lnRYjr5/EA=',
            'ntor_onion_key_crosscert_signbit' => '0',
            'ntor_onion_key_crosscert'         => "-----BEGIN ED25519 CERT-----\nAQoABklsAc35h4rhptyFeG+0G3ZQEU1ah7op9Uuz7pNHMTjoZzJ/ANXyfnnNZgZk\nBraUyNM4nZmvQ3SiGZ18abdj9f7HXLS44wmzZE/bwZP73UjA3ugmUyHXrBi1sR6P\nulw0KVjGtws=\n-----END ED25519 CERT-----\n",
        ));
        $desc3->exit_policy4 = array(
            'accept' => array('*:53', '*:1194'),
            'reject' => array('0.0.0.0/8:*', '169.254.0.0/16:*', '127.0.0.0/8:*', '192.168.0.0/16:*', '10.0.0.0/8:*', '172.16.0.0/12:*', '136.243.102.134:*', '*:*'),
        );

        $desc4 = new RouterDescriptor();
        $desc4->setArray(array(
            'fingerprint' => '8096EA61F733C3030351401944F54F254185098C',
            'nickname'    => 'FreeLauriLove',
            'ip_address'  => '178.62.66.18',
            'or_port'     => '9001',
            'dir_port'    => '9030',
            'platform'    => 'Tor 0.2.4.27 on Linux',
            'contact'     => 'email@redacted - 1MAdEpv9UP7FRUigtDP39c6c9nPf64eSjw',
            'published'   => '2016-12-25 09:11:24',
            'uptime'      => '376492',
            'protocols'   => 'Link 1 2 Circuit 1',
            'family'      => array('$4B37E840A7F26F85BA363927D6C6F2769EB4C918', '$73067CD4ADD8A294BDA913DF45B63190A52B5F9F', '$C50A2620C520D5751392DC1FD3CB1A26CA255ED0', 'Cyberia'),
            'bandwidth_average'    => '1073741824',
            'bandwidth_burst'      => '1073741824',
            'bandwidth_observed'   => '13298235',
            'hidden_service_dir'   => '2',
            'router_signature'    => "-----BEGIN SIGNATURE-----\nIH4/7VY0qcOynDwac2DspRqtuP28Pyp271ksJjwpSrzURWQ5o0PrkfMUAEPLFhOj\naf2UiwRCDissqCFgZ+G8UU9EXNY/Xqyou2Txu+J7VMpKm2iYxuVsRcVz6YyRGOxJ\nBtfuB08P+oopuJcJi/AtnqW/sjlsx16Y4MPfmgCPgds=\n-----END SIGNATURE-----\n",
            'extra_info_digest'   => 'F68A8E125732C8EFF93B640CFCCD3F4E0001D245',
            'onion_key'           => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAJ7dnYMII0RqtcFS+FSVE42yZCYPfkp5f4Haoe+WaMG45lEc8o18WrVg\nncGp+RN4UjY4zMb4wj85Af4T+yPQy3AruHXvJXyQVrJG1fVBMPE8Eu1cElOO8TBQ\nfA0a0ulN6eDFZHlelXSjvOS3WFssIb49UrO90NwvT5NW0lZz28+fAgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'signing_key'         => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAL/ZLEl8kjMM+PzriratNY9anZSPq++6GugQF8afLe1e66JXvSLL0SIN\nCvyahU/+AFE33lzzGywIMEmJKlbLZV1JbHxbAVQ0T1FNg/ppU93cF6npNRYs1R5w\naTb6my6YVVrltCO4yasNbqTEd158DzfJdDEg2hHiMLgPj8f5UuPrAgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'ntor_onion_key'      => 'BUDBZIeQ4LJBpIi+99rY7XsAbAT0RsXNGdaCGInVaH8=',
        ));
        $desc4->exit_policy4 = array(
            'accept' => array(),
            'reject' => array('*:*'),
        );

        $desc5 = new RouterDescriptor();
        $desc5->setArray(array(
            'fingerprint' => 'BC630CBBB518BE7E9F4E09712AB0269E9DC7D626',
            'nickname'    => 'IPredator',
            'ip_address'  => '197.231.221.211',
            'or_port'     => '9001',
            'dir_port'    => '9030',
            'platform'    => 'Tor 0.3.0.1-alpha on Linux',
            'published'   => '2016-12-25 11:01:38',
            'contact'     => 'tor@ipredator.se - 1Q3mjKbZwZFEigC8edUZ8ywX4QD7kxFzNC',
            'uptime'      => '194525',
            'bandwidth_average'    => '268435456',
            'bandwidth_burst'      => '402653184',
            'bandwidth_observed'   => '95030633',
            'hidden_service_dir'   => '2',
            'tunnelled_dir_server' => true,
            'proto' => array(
                'Cons'      => array(1, 2),
                'Desc'      => array(1, 2),
                'DirCache'  => array(1),
                'HSDir'     => array(1),
                'HSIntro'   => array(3),
                'HSRend'    => array(1, 2),
                'Link'      => array(1, 2, 3, 4),
                'LinkAuth'  => array(1, 3),
                'Microdesc' => array(1, 2),
                'Relay'     => array(1, 2),
            ),
            'router_signature'    => "-----BEGIN SIGNATURE-----\npzUSv+rE59u4AC2XfSWFkJ0bzjeq2hxqQUhRZ7pILUm6/nV4hzjNhVB8lPzroBKf\nlPG1WKgMey1j417O0Jrwp285xYDK4Z0BUpuxtu84vBmSmlrnfm81+Vjpj95ESUsZ\nGQ+iO0/jXVtQWvyX5kAPyHmPtUOvNhMDt+naNbYq+VM=\n-----END SIGNATURE-----\n",
            'ed25519_key'         => 'XlzTM3oGodQO9Te/Tdd9ZTjA7sU49LibpyZexos7/4Y',
            'ed25519_identity'    => "-----BEGIN ED25519 CERT-----\nAQQABklxAZv9QJ8v921eVF6Cl7oMDIJJsk+0WKGjsjcvPrhPBGX2AQAgBABeXNMz\negah1A71N79N131lOMDuxTj0uJunJl7Gizv/hvDT7q0LtNP914HQizTQjRl9skc0\ngJ6S+77ad68eTLAwD7Cp4xEznIjXtnxduhR1+LzXUy03GHeBHFN5eMxJvA4=\n-----END ED25519 CERT-----\n",
            'ed25519_sig'         => 'xrS6JUgL1KmqrYMbDzp/eLAwGW7bJTJe2S11th66SSjZYoIUd63zr7dA8km00eEZrY9Lg7lnX/ml45sambCECQ',
            'extra_info_digest'   => 'BC2FB1C74513ED1F8EFF2526D8A789BD7A3857E8 6QAr7ErEImvT6XTqFyGrf1XigO7DvDK/6oj4Fcaw6WM',
            'onion_key'           => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBANoCeAvwYgdo6FLLtj7vN9/NQmOVpocwfXRgbK2eRxV2QfO91uNpTl3V\nlpA5KzW2ICSFrzr1VjsQ3h6IbmVanVdJ5tq2dzUwDZW47tqvQ0jRYN+AuQ94ylpu\nW07TCZb3XTFDikLOf/lZ+Rv9yLeEO7UxdK9vL0HmUgFtib0ZkNn3AgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'signing_key'         => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAM/+LB3FL6nwSQJ7NoBiC6Gt43bE2lr/wCNS5JB/4Gkux7pOjLF3Ae2d\nhYrhgVx9Zk8kLWhJ9Rn0rY1qZ7QUbDbykpjH5Rjm8o5CtzD1aYL0csmWvGCUvIWo\nwAvMZktSBaGdU42wNDlBHRbn/dZns1+xrL3I2jV65EuT3D07UbgRAgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'onion_key_crosscert' => "-----BEGIN CROSSCERT-----\nrwag0ZcFW34PBJ78zmocv/6F1Xzr50fQb7vqJitMV1BOi37U6sYcyKvS27INXjnW\n7nuedSaQCywg2RRf1f8+Lqaz2/mQDHf+WbVyG7J92sO+u295P5D1O8ge9zTg61gN\nJ1rwxs3z+82dL7ak9WXNzEgYrrYCAajq5bkXSYjdaAg=\n-----END CROSSCERT-----\n",
            'ntor_onion_key'      => 'p2SSQYN9XDYaqF6k/PJ8BU0y1nV6TI4eTyK9LjF9uFg=',
            'ntor_onion_key_crosscert_signbit' => '1',
            'ntor_onion_key_crosscert'         => "-----BEGIN ED25519 CERT-----\nAQoABkl0AV5c0zN6BqHUDvU3v03XfWU4wO7FOPS4m6cmXsaLO/+GACOC8J2QX9dc\nvdbWOnT5/yAYt3IzzVSjNI625sNRtjK58Y6ZKPmgW2BsqwSZS5z1gfjA5KvoHk9i\njOFT8+MHcwI=\n-----END ED25519 CERT-----\n",
        ));
        $desc5->exit_policy4 = array(
            'accept' => array('*:*'),
            'reject' => array('0.0.0.0/8:*', '169.254.0.0/16:*', '127.0.0.0/8:*', '192.168.0.0/16:*', '10.0.0.0/8:*', '172.16.0.0/12:*', '197.231.221.211:*', '*:109', '*:110', '*:143', '*:25', '*:119', '*:135-139', '*:445', '*:563', '*:1214', '*:4661-4666', '*:6346-6429', '*:6699', '*:6881-6999'),
        );
        $desc5->exit_policy6 = array(
            'accept' => array('*:*'),
            'reject' => array('25', '109-110', '119', '135-139', '143', '445', '563', '1214', '4661-4666', '6346-6429', '6699', '6881-6999'),
        );

        $desc6 = new RouterDescriptor();
        $desc6->setarray(array(
            'fingerprint' => 'BE953C95C98D207742A66DDC05B0A476FF2225C9',
            'nickname'    => 'pp14relay',
            'ip_address'  => '212.47.246.18',
            'or_port'     => '443',
            'dir_port'    => '80',
            'platform'    => 'Tor 0.2.8.6 on Linux',
            'published'   => '2016-12-25 05:23:58',
            'contact'     => '0x6E7B19EE BTC: 14Z2dRe2RBS8jcpYHExVQzkcsDMxuPJWEr',
            'uptime'      => '10575016',
            'family'      => array(
                '$383B7179FEE38D6773D4327F4B5856798BD85202',
                '$79E169B25E4C7CE99584F6ED06F379478F23E2B8',
                '$BC924D50078666A0208F9D75F29CA73645FB604D',
                '$DD116ACB4D775A04D7D0A7D8C6E41DDC7FA5F8BC',
                '$FE32CAC855ABC707ED7FEDAF720046FE914EB491'
            ),
            'bandwidth_average'    => '20480000',
            'bandwidth_burst'      => '25600000',
            'bandwidth_observed'   => '10856489',
            'hidden_service_dir'   => '2',
            'tunnelled_dir_server' => true,
            'protocols'            => 'Link 1 2 Circuit 1',
            'router_signature'    => "-----BEGIN SIGNATURE-----\nQP8QPC/IFwil1VnJRG1iGSELGaULFbLR0Cn1Ea2KErbyU9QOPd/PFF+lM1Ts5vH4\ny4C1LJtI1U96+qIYcmj+zIC95workDPDw7PdAs6mOgLq4oVwBIo941I14XfCD0Q2\n7EuYxSIX/fVyuXUjUrxCHgoylHzcX9/6x/uN1d4kMPA=\n-----END SIGNATURE-----\n",
            'ed25519_key'         => 'cHt6rMQp4I4DPeL8VF1u3y2qkgKn73ZPBe/pKbGBWMU',
            'ed25519_identity'    => "-----BEGIN ED25519 CERT-----\nAQQABkmzAU2SQFG9lwjVz5p6x6220c2lvwjlgpbMAm+vkDZRJW86AQAgBABwe3qs\nxCngjgM94vxUXW7fLaqSAqfvdk8F7+kpsYFYxVMKpWW8wJZ65XhzKdfOSMwdDVRn\nLve7jlohxKGJIw+8kbmfDEvJsKpU7SubrT7Ne+8gaCNdAes3xo76Xzx5ZQg=\n-----END ED25519 CERT-----\n",
            'ed25519_sig'         => 'yd1P/PHHhJDVGpZ4YjLdNAn8KE3wbp5R1hQqRTVsCIStGPxWFytwBa0Uhs15gcn5WoIGq9ju7wpPNOgj/JDFDA',
            'extra_info_digest'   => 'F5396C2BB9D73726468E49044C76F0FF0BC83E6E 9g9bJZ7p5ORZmHppkiN0eAFRCUmJ1oT0mY54uL6ov4I',
            'onion_key'           => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBANHTJ8IbS3fXzw6QdFNmCmr0Kt5tLUZAo3b/40DhiF6xvotfIQbSl0kC\nSeLvopDOStRC5m6W6I8gHsBIXX83aCwap1iWT+KWQKARCy9pINHFaZ2waf+/xDUL\n6OVwLHh/9UtknvFCtJ2arZaUcAGpVo0LekpT8KYrvT7eHDM2NYpDAgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'signing_key'         => "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBANUXrccYX0LzzuhTMV+JVLhEfMy4r9rPUz0PPSmZBD4+Q2MvYaVio8iG\nYrfOkbns2ICweirC3F4urASwZAfrIq/nn/POU3ZRbVf+GYeJNRQK8LNnBjLwHris\nYqBPJG3v0xhK9BqqYlDsAj1cxzdC5TaoqSSLBiQRbA8WA3DM92y7AgMBAAE=\n-----END RSA PUBLIC KEY-----\n",
            'onion_key_crosscert' => "-----BEGIN CROSSCERT-----\nQNi/PxW1pZ9YisdoDLZckVzgke5kxfIpYiO/ZaDvxexVmNtpZ+ZaVoSJpj2uadbz\nntLE11MefMA82aKpzRO9BXijvjo++Ps6oBPdkf8jRKgRUCmamnK4t9+qaNZTCvTe\nmQWdAARKGO9ns8t+kuLqB+v4hs6B7AowIOglnNF0AQI=\n-----END CROSSCERT-----\n",
            'ntor_onion_key'      => 'cqLoInsBOmaak2N/POzo0r5nY0lONaQ6AFP5ZxraNFQ=',
            'ntor_onion_key_crosscert_signbit' => '1',
            'ntor_onion_key_crosscert'         => "-----BEGIN ED25519 CERT-----\nAQoABkluAXB7eqzEKeCOAz3i/FRdbt8tqpICp+92TwXv6SmxgVjFAKBZ6BkVCJ7I\n4Lks3i8JV0NSJsFW2y4aX4WlLfdOrzWN1Ixb+Ku5T/Xf4Mc7rjO5paf2XYEavwVN\niJxbTNfuEwM=\n-----END ED25519 CERT-----\n",
        ));
        $desc6->exit_policy4 = array(
            'accept' => array(),
            'reject' => array('*:*'),
        );

        $descriptors = array(
            '79E169B25E4C7CE99584F6ED06F379478F23E2B8' => $desc1,
            'E2EC4A6D3E002866C2A49207109F72812F9D2E62' => $desc2,
            '988063DF0FBD3DB73A8FE1F5820712B95D248C78' => $desc3,
            '8096EA61F733C3030351401944F54F254185098C' => $desc4,
            'BC630CBBB518BE7E9F4E09712AB0269E9DC7D626' => $desc5,
            'BE953C95C98D207742A66DDC05B0A476FF2225C9' => $desc6,
        );

        $data[] = array(
            $reply, $descriptors,
        );

        return $data;
    }
}
