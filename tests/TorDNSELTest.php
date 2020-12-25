<?php

use Dapphp\TorUtils\TorDNSEL;
use PHPUnit\Framework\TestCase;

final class TorDNSELTest extends TestCase
{
    public function testGetDnsName()
    {
        $dnsel = new TorDNSEL();

        $remoteaddr = '2001:0db8::0001';
        $name       = $dnsel->getTorDNSELName($remoteaddr);

        $this->assertEquals('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.dnsel.torproject.org', $name);

        $remoteaddr = '[2001:db8:85a3:8d3:1319:8a2e:370:7348]';
        $name       = $dnsel->getTorDNSELName($remoteaddr);

        $this->assertEquals('8.4.3.7.0.7.3.0.e.2.a.8.9.1.3.1.3.d.8.0.3.a.5.8.8.b.d.0.1.0.0.2.dnsel.torproject.org', $name);

        $remoteaddr = '1.2.3.4';
        $name       = $dnsel->getTorDNSELName($remoteaddr);

        $this->assertEquals('4.3.2.1.dnsel.torproject.org', $name);

        $remoteaddr = '29.58.116.203';
        $name       = $dnsel->getTorDNSELName($remoteaddr);

        $this->assertEquals('203.116.58.29.dnsel.torproject.org', $name);
    }

    /**
     * @dataProvider expandIPv6AddressDataProvider
     */
    public function testExpandIPv6Address($address, $expected)
    {
        $dnsel  = new TorDNSEL();
        $result = $dnsel->expandIPv6Address($address);

        $this->assertEquals($expected, $result);
    }

    public function expandIPv6AddressDataProvider()
    {
        return [
            [ '::',                        '0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0', ],
            [ '::1',                       '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0', ],

            [ '2001:db8::1',               '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2', ],
            [ '2001:0db8::0001',           '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2', ],
            [ '2001:db8:0:0:0:0:2:1',      '1.0.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2', ],
            [ '2001:db8::2:1',             '1.0.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2', ],
            [ '2001:db8::1:0:0:1',         '1.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2', ],
            [ '2001:0db8:0000:0000:0001:0000:0000:0001',
                                           '1.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2', ],

            [ '[2001:db8:85a3:8d3:1319:8a2e:370:7348]',
                                           '8.4.3.7.0.7.3.0.e.2.a.8.9.1.3.1.3.d.8.0.3.a.5.8.8.b.d.0.1.0.0.2', ],

            [ 'fe80::1ff:fe23:4567:890a',  'a.0.9.8.7.6.5.4.3.2.e.f.f.f.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f', ],
            [ 'fdda:5cc1:23:4::1f',        'f.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.0.0.3.2.0.0.1.c.c.5.a.d.d.f', ],
            [ '2001:b011:4006:170c::11',   '1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.0.7.1.6.0.0.4.1.1.0.b.1.0.0.2', ],
            [ '2620:6e:a001:705:face:b00c:15:bad',
                                           'd.a.b.0.5.1.0.0.c.0.0.b.e.c.a.f.5.0.7.0.1.0.0.a.e.6.0.0.0.2.6.2', ],
            [ '2620:7:6001::101',          '1.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.6.7.0.0.0.0.2.6.2', ],
            [ '[2a0a:3840:1337:125:0:b9c1:7d9b:1337]',
                                           '7.3.3.1.b.9.d.7.1.c.9.b.0.0.0.0.5.2.1.0.7.3.3.1.0.4.8.3.a.0.a.2', ],
        ];
    }

    /**
     * @dataProvider invalidIPv6AddressesDataProvider
     */
    public function testInvalidIPv6Addresses($address)
    {
        $dnsel = new TorDNSEL();

        $this->expectException(\InvalidArgumentException::class);

        $dnsel->expandIPv6Address($address);
    }

    public function invalidIPv6AddressesDataProvider()
    {
        return [
            [ '', ],
            [ ':', ],
            [ '[:]', ],
            [ '1.2.3.4', ],
            [ '2620:7:6001::101z', ],
        ];
    }
}
