<?php

use Dapphp\TorUtils\ControlClient;
use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

use PHPUnit\Framework\TestCase;

final class ControlClientTest extends TestCase
{
    protected function getMockControlClient($data = null)
    {
        $tc = new ControlClientMock();

        if (is_array($data)) {
            $tc->recvData = $data;
        }

        return $tc;
    }

    public function testSingleLinePositiveReply()
    {
        $response = array("250 OK\r\n");
        $tc       = $this->getMockControlClient($response);
        $reply    = $tc->readReply();

        $this->assertEquals(250, $reply->getStatusCode());
    }

    public function testReadMultiReply()
    {
        $cmd      = 'testing';
        $response = array(
            "250+{$cmd}=\r\n",
            "this is some data for a reply line\r\n",
            "this is some data for another line\r\n",
            "and finally the last line of reply\r\n",
            ".\r\n",
            "250 OK\r\n",
        );

        $tc    = $this->getMockControlClient($response);
        $reply = $tc->readReply($cmd);

        $this->assertEquals(250, $reply->getStatusCode());
        $this->assertEquals(rtrim($response[1], "\r\n"), $reply[0]);
        $this->assertEquals(rtrim($response[2], "\r\n"), $reply[1]);
        $this->assertEquals(rtrim($response[3], "\r\n"), $reply[2]);
    }

    public function testReadMultiReply2()
    {
        $cmd      = 'option/value';
        $response = array(
            "250-{$cmd}=answer\r\n",
            "250 OK\r\n",
        );

        $tc    = $this->getMockControlClient($response);
        $reply = $tc->readReply($cmd);

        $this->assertEquals(250, $reply->getStatusCode());
        $this->assertEquals('answer', $reply[0]);
        $this->assertEquals(1, sizeof($reply->getReplyLines()));
    }

    public function testReadLongMultiReply()
    {
        $cmd      = 'getinfo/testing';
        $response = array(
            "250+{$cmd}=\r\n",
        );

        for ($i = 0; $i < 1000; ++$i) {
            $response[] = str_repeat('x', 80) . "\r\n";
        }

        $response[] = ".\r\n";
        $response[] = "250 OK\r\n";

        $tc    = $this->getMockControlClient($response);
        $reply = $tc->readReply($cmd);

        $this->assertEquals(250, $reply->getStatusCode());
        $this->assertEquals(1000, sizeof($reply->getReplyLines()));
        $this->assertEquals(str_repeat('x', 80), $reply[500]);
    }

    public function testParseReplyWithAsyncEvent()
    {
        $response = array(
            "650 CIRC 212 EXTENDED \$844AE9CAD04325E955E2BE1521563B79FE7094B7~Smeerboel BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2016-12-22T06:11:06.611813\r\n",
            "250-SOCKSPORT=9050\r\n",
            "250 ORPORT=0\r\n",
        );

        $asyncEventName = '';
        $asyncEvent     = null;

        $tc     = $this->getMockControlClient($response);
        $events = [ 'STREAM', 'CIRC', ];

        $tc->setAsyncEventHandler(function($event, $data) use (&$asyncEventName, &$asyncEvent) {
            $asyncEventName = $event;
            $asyncEvent     = $data;
        }, $events);

        $ports = $tc->getConf('SOCKSPORT ORPORT');

        // the async event data comes first, but it should be read and handled
        // by the async event handler, and then the response to the issued

        $this->assertEquals('CIRC', $asyncEventName);
        $this->assertInstanceOf(Dapphp\TorUtils\Event\CircuitStatus::class, $asyncEvent);
        $this->assertEquals('212', $asyncEvent->id);
        $this->assertEquals('EXTENDED', $asyncEvent->status);
        $this->assertEquals('GENERAL', $asyncEvent->purpose);
        $this->assertEquals('2016-12-22T06:11:06.611813', $asyncEvent->timeCreated);
        $this->assertContains('NEED_CAPACITY', $asyncEvent->buildFlags);
        $this->assertCount(1, $asyncEvent->path);
        $this->assertEquals('$844AE9CAD04325E955E2BE1521563B79FE7094B7', $asyncEvent->path[0]['fingerprint']);
        $this->assertEquals('Smeerboel', $asyncEvent->path[0]['nickname']);

        $this->assertEquals(9050, $ports['SOCKSPORT']);
        $this->assertEquals(0,    $ports['ORPORT']);
    }

    public function testNewConsensusAsyncEvent()
    {
        $response = array_map(function($item) {
            return $item . "\r\n";
        }, explode("\n", file_get_contents(__DIR__ . '/data/newconsensus-1')));

        $asyncEventName = '';
        $asyncEvent     = null;

        $tc     = $this->getMockControlClient($response);
        $events = [ 'NEWCONSENSUS', ];

        $tc->setAsyncEventHandler(function($event, $data) use (&$asyncEventName, &$asyncEvent) {
            $asyncEventName = $event;
            $asyncEvent     = $data;
        }, $events);

        $tc->waitForEvent();

        // the async event data comes first, but it should be read and handled
        // by the async event handler, and then the response to the issued

        $this->assertEquals('NEWCONSENSUS', $asyncEventName);
    }

    public function testAuthentication()
    {
        $response = array(
            "250-PROTOCOLINFO 1\r\n",
            "250-AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE=\"/var/run/tor/control.authcookie\"\r\n",
            "250-VERSION Tor=\"0.2.9.8\"\r\n",
            "250 OK\r\n",
            "250 OK\r\n", // authenticate reply
        );

        $tc = $this->getMockControlClient($response);

        $tc->authenticate("password");

        $this->addToAssertionCount(1);
    }

    public function testAuthentication2()
    {
        $response = array(
            "250-PROTOCOLINFO 1\r\n",
            "250-AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE=\"/Users/nosx/Library/Application Support/TorBrowser-Data/Tor/control_auth_cookie\"\r\n",
            "250-VERSION Tor=\"0.4.3.6\"\r\n",
            "250 OK\r\n",
            "250 OK\r\n", // authenticate reply
        );

        $tc = $this->getMockControlClient($response);

        $tc->authenticate("password");

        $this->addToAssertionCount(1);
    }

    public function testFailedAuthentication()
    {
        $response = array(
            "250-PROTOCOLINFO 1\r\n",
            "250-AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE=\"/var/run/tor/control.authcookie\"\r\n",
            "250-VERSION Tor=\"0.2.9.8\"\r\n",
            "250 OK\r\n",
            "515 Authentication failed: Password did not match HashedControlPassword *or* authentication cookie.\r\n",
        );

        $this->expectException(\Dapphp\TorUtils\ProtocolError::class);
        $this->expectExceptionCode(515);
        $this->expectExceptionMessage('Authentication failed: Password did not match HashedControlPassword *or* authentication cookie.');

        $tc = $this->getMockControlClient($response);
        $tc->authenticate("this is most definitely the wrong password ;)");
    }

    public function testGetInfoCircuitStatus()
    {
        $cmd  = 'GETINFO circuit-status';
        $data = [
            "250+circuit-status=\r\n",
            "4302 BUILT $614094CAF0701EB568106E60EC12A785E704AE0F~Srv3MuchRelay,$94EC34B871936504BE70671B44760BC99242E1F3~unix4lyfe,$980B28A19B0A66948035A3FE143E5CF613C84122~zeus04,\$B22C4BF9747DBBC843F1BBBA272FDB7B6045EB01~3VirtualMachineOrg BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED REND_QUERY=wqnzr6nayo2lfml6sz6y5z6rdwa74h3u456kwl76t6icggzmlmehvkyd TIME_CREATED=2020-12-05T20:58:47.146324\r\n",
            "4234 BUILT $614094CAF0701EB568106E60EC12A785E704AE0F~Srv3MuchRelay,$81A59766272894D27FE8375C4F83A6BA453671EF~chutney,$7A3E534C033E3836BD5AF223B642853C502AB33A~Unnamed,$0C8A49FE62B7C7DED64B7C6A941EF5240E4F3F74~doppelganger BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED REND_QUERY=wqnzr6nayo2lfml6sz6y5z6rdwa74h3u456kwl76t6icggzmlmehvkyd TIME_CREATED=2020-12-05T20:23:27.288651\r\n",
            "3761 BUILT $614094CAF0701EB568106E60EC12A785E704AE0F~Srv3MuchRelay,$15BE17C99FACE24470D40AF782D6A9C692AB36D6~rofltor07,$18F34AE6567F5FB081C4353D5EDA5CEE155810C4~homez,\$DE8A58FCD4B84ADEC1F25078CD63F4BFC3DC9C80~mehcloud BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED REND_QUERY=l3xjw42mqxdiaxxyverbxerer2brwbtem73i3yyfeyqaksef2phkahid TIME_CREATED=2020-12-05T14:41:35.001993\r\n",
            "3794 BUILT $614094CAF0701EB568106E60EC12A785E704AE0F~Srv3MuchRelay,$96560F12D1FD54131C59A2352829C2750E5EB796~Unnamed,$5F276A6F7AA74AFB2AF100EADA28C7A6F48BA50F~Planetclaire61,\$CD0F9AA1A5064430B1DE8E645CBA7A502B27ED5F~jaures4 BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED REND_QUERY=l3xjw42mqxdiaxxyverbxerer2brwbtem73i3yyfeyqaksef2phkahid TIME_CREATED=2020-12-05T14:51:32.657853\r\n",
            "4476 BUILT $614094CAF0701EB568106E60EC12A785E704AE0F~Srv3MuchRelay,$2D8AFA912E2B8623BB2CDACD19332209D524D1A3~sauronkingofmortor,$3E09AEF0B44E9416BC2D87032D3416431E8231DC~QuantumOnion254,$706B1ED9AF5CCAC90AD488AE2691B358FA598CBB~SSA8MyBZYXduYm94 BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY PURPOSE=HS_SERVICE_HSDIR HS_STATE=HSSI_CONNECTING TIME_CREATED=2020-12-05T23:56:51.398464\r\n",
            "4477 BUILT $614094CAF0701EB568106E60EC12A785E704AE0F~Srv3MuchRelay,$0AD3B16ADF3EED3E5962FA944CD501352E790814~ritirong,$9D3FFCD4C4719688355A0DBA55A0592CFF6B13BE~Unnamed,$68E6BBB65656F2CECBB75BAFD0362F43A38DF076~tirz BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY PURPOSE=HS_SERVICE_HSDIR HS_STATE=HSSI_CONNECTING TIME_CREATED=2020-12-05T23:56:51.406984\r\n",
            "4478 BUILT $614094CAF0701EB568106E60EC12A785E704AE0F~Srv3MuchRelay,\$DA580E4EB2A453298D40F73ECFC78E896B001182~BKA,\$DC400303E7A1E03C092694E8021B9EC9EC6C9F5E~lexam,$10644CF3D7F555F10FE28EB1D520111F56FE7180~relayon0333 BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY PURPOSE=HS_SERVICE_HSDIR HS_STATE=HSSI_CONNECTING TIME_CREATED=2020-12-05T23:56:51.416239\r\n",
            "4481 BUILT $614094CAF0701EB568106E60EC12A785E704AE0F~Srv3MuchRelay,$64E257D94E739278D5954CC820C9D7EAC4E7A7B7~l3v3lup,$2D97C1A7D5A06530F3B2B291F8F2C10CB313DC10~Unnamed,$38E48C9509E18F405749859EEF299EBC1B829602~pastly03 BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=CIRCUIT_PADDING REND_QUERY=tp7mtouwvggdlm73vimqkuq7727a4ebrv4vf4cnk6lfg4fatxa6p2ryd TIME_CREATED=2020-12-05T23:56:51.443545\r\n",
            "4483 BUILT $614094CAF0701EB568106E60EC12A785E704AE0F~Srv3MuchRelay,$9B047A91AC809AA020A1F42E3E785DBCEBF3652F~420isGay,\$C6466E1A11C1CE9DE30B39F28747E226BBC139A7~Eliise04,$1C79261551E0F938A0D3959E1F2D74A4B48263FA~RIGALAND BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=HS_CLIENT_HSDIR HS_STATE=HSCI_CONNECTING TIME_CREATED=2020-12-05T23:56:53.377939\r\n",
            "4484 BUILT $614094CAF0701EB568106E60EC12A785E704AE0F~Srv3MuchRelay,\$B25427A8F4A485E03EDA31757AB1C33DBE587428~DefinitelyNotTheFBI,$7E44E0D39CE8666A98EA5DEBCBB8E12B3906410F~torexit42 BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=GENERAL TIME_CREATED=2020-12-05T23:57:44.581436\r\n",
            "4486 BUILT $614094CAF0701EB568106E60EC12A785E704AE0F~Srv3MuchRelay,$51064561203E97716372E12CAAA85A93CEC70621~Unnamed,\$BB0C636DE89CAC6C995CB380AAC8C4AAAB731BA8~0ZQIX7g6 BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=GENERAL TIME_CREATED=2020-12-05T23:57:46.588998\r\n",
            ".\r\n",
            "250 OK\r\n",
        ];

        $tc       = $this->getMockControlClient($data);
        $circuits = $tc->getInfoCircuitStatus();

        $this->assertCount(11, $circuits);

        $this->assertInstanceOf(\Dapphp\TorUtils\Event\CircuitStatus::class, $circuits[0]);

        $this->assertEquals(4302, $circuits[0]->id);
        $this->assertCount(4, $circuits[0]->path);
        $this->assertEquals('$614094CAF0701EB568106E60EC12A785E704AE0F', $circuits[0]->path[0]['fingerprint']);
        $this->assertEquals('Srv3MuchRelay', $circuits[0]->path[0]['nickname']);
        $this->assertEquals('$94EC34B871936504BE70671B44760BC99242E1F3', $circuits[0]->path[1]['fingerprint']);
        $this->assertEquals('unix4lyfe', $circuits[0]->path[1]['nickname']);
        $this->assertEquals('$980B28A19B0A66948035A3FE143E5CF613C84122', $circuits[0]->path[2]['fingerprint']);
        $this->assertEquals('zeus04', $circuits[0]->path[2]['nickname']);
        $this->assertEquals('$B22C4BF9747DBBC843F1BBBA272FDB7B6045EB01', $circuits[0]->path[3]['fingerprint']);
        $this->assertEquals('3VirtualMachineOrg', $circuits[0]->path[3]['nickname']);
        $this->assertEquals('HS_SERVICE_INTRO', $circuits[0]->purpose);
        $this->assertEquals('HSSI_ESTABLISHED', $circuits[0]->hsState);
        $this->assertCount(3, $circuits[0]->buildFlags);
        $this->assertContains('IS_INTERNAL', $circuits[0]->buildFlags);
        $this->assertContains('NEED_CAPACITY', $circuits[0]->buildFlags);
        $this->assertContains('NEED_UPTIME', $circuits[0]->buildFlags);
        $this->assertEquals('wqnzr6nayo2lfml6sz6y5z6rdwa74h3u456kwl76t6icggzmlmehvkyd', $circuits[0]->rendQuery);
        $this->assertEquals('2020-12-05T20:58:47.146324', $circuits[0]->timeCreated);

        $this->assertEquals(4477, $circuits[5]->id);
        $this->assertCount(4, $circuits[5]->path);
        $this->assertCount(2, $circuits[5]->buildFlags);
        $this->assertContains('IS_INTERNAL', $circuits[5]->buildFlags);
        $this->assertContains('NEED_CAPACITY', $circuits[5]->buildFlags);
        $this->assertEquals('HS_SERVICE_HSDIR', $circuits[5]->purpose);
        $this->assertEquals('HSSI_CONNECTING', $circuits[5]->hsState);
        $this->assertEquals('2020-12-05T23:56:51.406984', $circuits[5]->timeCreated);

    }

    public function testGetInfoCircuitStatus2()
    {
        $cmd  = 'GETINFO circuit-status';
        $data = array_map(function($line) {
            return rtrim($line) . "\r\n";
        }, file(__DIR__ . '/data/circuit-status-1'));

        $tc       = $this->getMockControlClient($data);
        $circuits = $tc->getInfoCircuitStatus();

        $this->assertCount(38, $circuits);

        $this->assertInstanceOf(\Dapphp\TorUtils\Event\CircuitStatus::class, $circuits[0]);
        $this->assertInstanceOf(\Dapphp\TorUtils\Event\CircuitStatus::class, $circuits[37]);

        $c = $circuits[0]; //185 BUILT $CBB5AE37E2927A915D70FA71572D2EA203F03E83~dthpulse,$5A9B2EC4C652EC4FF72C8C673937BE27B3486666~CryingOnion,$AEDE403BD0B7CE114F5B3BF5D33B15C6B9001BC2~VSIFsalyut4 BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2020-12-25T18:59:24.377094
        $this->assertEquals(185, $c->id);
        $this->assertEquals('BUILT', $c->status);
        $this->assertCount(3, $c->path);
        $this->assertEquals('dthpulse', $c->path[0]['nickname']);
        $this->assertEquals('$CBB5AE37E2927A915D70FA71572D2EA203F03E83', $c->path[0]['fingerprint']);
        $this->assertEquals('CryingOnion', $c->path[1]['nickname']);
        $this->assertEquals('$5A9B2EC4C652EC4FF72C8C673937BE27B3486666', $c->path[1]['fingerprint']);
        $this->assertEquals('VSIFsalyut4', $c->path[2]['nickname']);
        $this->assertEquals('$AEDE403BD0B7CE114F5B3BF5D33B15C6B9001BC2', $c->path[2]['fingerprint']);
        $this->assertContains('NEED_CAPACITY', $c->buildFlags);
        $this->assertEquals('GENERAL', $c->purpose);
        $this->assertEquals('2020-12-25T18:59:24.377094', $c->timeCreated);

        $c = $circuits[33]; // 254 GUARD_WAIT $B7EF647EF659726C716243A82877D20AA7978EBC~piersic,$459310E0C3A72CAACAE10BEEBB7484D724C9C8C0~StoNet08,$C0192FF43E777250084175F4E59AC1BA2290CE38~manipogo BUILD_FLAGS=NEED_CAPACITY PURPOSE=MEASURE_TIMEOUT TIME_CREATED=2020-12-25T19:03:08.275804
        $this->assertEquals(254, $c->id);
        $this->assertEquals('GUARD_WAIT', $c->status);
        $this->assertCount(3, $c->path);
        $this->assertEquals('piersic', $c->path[0]['nickname']);
        $this->assertEquals('$B7EF647EF659726C716243A82877D20AA7978EBC', $c->path[0]['fingerprint']);
        $this->assertEquals('StoNet08', $c->path[1]['nickname']);
        $this->assertEquals('$459310E0C3A72CAACAE10BEEBB7484D724C9C8C0', $c->path[1]['fingerprint']);
        $this->assertEquals('manipogo', $c->path[2]['nickname']);
        $this->assertEquals('$C0192FF43E777250084175F4E59AC1BA2290CE38', $c->path[2]['fingerprint']);
        $this->assertEquals('MEASURE_TIMEOUT', $c->purpose);
        $this->assertEquals('2020-12-25T19:03:08.275804', $c->timeCreated);

        $c = $circuits[37]; // 259 EXTENDED BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2020-12-25T19:03:45.423132
        $this->assertEquals(259, $c->id);
        $this->assertEquals('EXTENDED', $c->status);
        $this->assertContains('NEED_CAPACITY', $c->buildFlags);
        $this->assertEquals('GENERAL', $c->purpose);
        $this->assertEquals('2020-12-25T19:03:45.423132', $c->timeCreated);
    }

}

/**
 * Weak way to mock a ControlClient such that when a test invokes readReply to
 * read from the control socket, we can override _recvData to return lines of
 * test data rather than reading from a socket.
 *
 * To mock reads, set recvData to a numerically keyed array where each index
 * is a line of data from the controller.
 */
class ControlClientMock extends ControlClient
{
    public $recvData = [];

    public function _recvData()
    {
        $v = array_shift($this->recvData);

        if (is_null($v)) {
            return false;
        } else {
            return $v;
        }
    }

    public function sendData($data)
    {
        $data = $data . "\r\n";
        return strlen($data);
    }

    public function waitForEvent(?int $tv_sec = NULL, ?int $tv_usec = 0): void
    {
        $changed = count($this->recvData) ?? false;

        if ($changed === false) {
            return;
        } elseif ($changed > 0) {
            $this->readReply(null, true); // invokes event handler
        }
    }
}
