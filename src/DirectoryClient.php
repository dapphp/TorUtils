<?php

/**
 * Project:  TorUtils: PHP classes for interacting with Tor
 * File:     DirectoryClient.php
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
 * @copyright 2015 Drew Phillips
 * @author Drew Phillips <drew@drew-phillips.com>
 *
 */

namespace Dapphp\TorUtils;

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

/**
 * Class for getting router info from Tor directory authorities
 *
 */
class DirectoryClient
{
    /**
     * @var array $directoryAuthorities List of directory authorities https://gitweb.torproject.org/tor.git/tree/src/app/config/auth_dirs.inc
     */
    protected $directoryAuthorities = array(
        '9695DFC35FFEB861329B9F1AB04C46397020CE31' => '128.31.0.39:9131', // moria1
        '847B1F850344D7876491A54892F904934E4EB85D' => '86.59.21.38:80', // tor26
        '7EA6EAD6FD83083C538F44038BBFA077587DD755' => '45.66.33.45:80', // dizum
        'BA44A889E64B93FAA2B114E02C2A279A8555C533' => '66.111.2.131:9030', // Serge
        'F2044413DAC2E02E3D6BCF4735A19BCA1DE97281' => '131.188.40.189:80', // gabelmoo
        '7BE683E65D48141321C5ED92F075C55364AC7123' => '193.23.244.244:80', // dannenberg
        'BD6A829255CB08E66FBE7D3748363586E46B3810' => '171.25.193.9:443', // maatuska
        'CF6D0AAFB385BE71B8E111FC5CFF4B47923733BC' => '154.35.175.225:80', // Faravahar
        '74A910646BCEEFBCD2E874FC1DC997430F968145' => '199.58.81.140:80', // longclaw
        '24E2F139121D4394C54B5BCC368B3B411857C413' => '204.13.164.118:80', // bastet
    );

    /**
     * @var array Array of directory fallbacks from https://gitweb.torproject.org/tor.git/tree/src/app/config/fallback_dirs.inc
     */
    protected $directoryFallbacks = array(
        // List updated 2020/12/02 (commit blob a7ef39bb96a54993123fa307d2ee2330e57e0c39)
        // version=3.0.0, timestamp=20200723133610
        // NF = Not found in Tor Metrics (metrics.torproject.org) - The fingerprint was not found in Tor Metrics on the date given
        // TO = Timing out repeatedly on given date
        // RF = Read failed when trying to query for directory info on the date given.
        // Exit Relay = This is a busy exit relay so we should not bug it for directory info.
        '0338F9F55111FE8E3570E7DE117EF3AF999CC1D7' => '185.225.17.3:80', // Nebuchadnezzar
        '03C3069E814E296EB18776EB61B1ECB754ED89FE' => '81.7.10.193:9002', // Ichotolot61
        //'0B85617241252517E8ECF2CFC7F4C1A32DCD153F' => '163.172.149.155:80', // niij02 (NF 2020/12/02)
        '0C039F35C2E40DCB71CD8A07E97C7FD7787D42D6' => '5.200.21.144:80', // libel
        '0C475BA4D3AA3C289B716F95954CAD616E50C4E5' => '81.7.18.7:9030', // Freebird32
        '0F6E5CA4BF5565D9AA9FDDCA165AFC6A5305763D' => '193.234.15.60:80', // jaures3
        '113143469021882C3A4B82F084F8125B08EE471E' => '93.177.67.71:9030', // parasol
        '11DF0017A43AF1F08825CD5D973297F81AB00FF3' => '37.120.174.249:80', // gGDHjdcC6zAlM8k08lX
        '12AD30E5D25AA67F519780E2111E611A455FDC89' => '193.11.114.43:9030', // mdfnet1
        '12FD624EE73CEF37137C90D38B2406A66F68FAA2' => '37.157.195.87:8030', // thanatosCZ
        '158581827034DEF1BAB1FC248D180165452E53D3' => '193.234.15.61:80', // bakunin3
        '15BE17C99FACE24470D40AF782D6A9C692AB36D6' => '51.15.78.0:9030', // rofltor07
        '185F2A57B0C4620582602761097D17DB81654F70' => '204.11.50.131:9030', // BoingBoing
        '1CD17CB202063C51C7DAD3BACEF87ECE81C2350F' => '50.7.74.171:9030', // theia1
        '1F6ABD086F40B890A33C93CC4606EE68B31C9556' => '199.184.246.250:80', // dao
        '20462CBA5DA4C2D963567D17D0B7249718114A68' => '212.47.229.2:9030', // scaletor
        '204DFD2A2C6A0DC1FA0EACB495218E0B661704FD' => '77.247.181.164:80', // HaveHeart
        //'230A8B2A8BA861210D9B4BA97745AEC217A94207' => '163.172.176.167:80', // niij01 (NF 2020/12/02)
        '24D0491A2ADAAB52C17625FBC926D84477AEA322' => '193.234.15.57:80', // bakunin
        '28F4F392F8F19E3FBDE09616D9DB8143A1E2DDD3' => '185.220.101.137:20137', // niftycottonmouse
        '2BA2C8E96B2590E1072AECE2BDB5C48921BF8510' => '138.201.250.33:9012', // storm
        '2BB85DC5BD3C6F0D81A4F2B5882176C6BF7ECF5A' => '5.181.50.99:80', // AlanTuring
        '2F0F32AB1E5B943CA7D062C03F18960C86E70D94' => '97.74.237.196:9030', // Minotaur
        '311A4533F7A2415F42346A6C8FA77E6FD279594C' => '94.230.208.147:8080', // DigiGesTor3e2
        '32EE911D968BE3E016ECA572BB1ED0A9EE43FC2F' => '109.105.109.162:52860', // ndnr1
        '330CD3DB6AD266DC70CDB512B036957D03D9BC59' => '185.100.84.212:80', // TeamTardis
        '375DCBB2DBD94E5263BC0C015F0C9E756669617E' => '64.79.152.132:80', // ebola
        '39F096961ED2576975C866D450373A9913AFDC92' => '198.50.191.95:80', // shhovh
        '3AFDAAD91A15B4C6A7686A53AA8627CA871FF491' => '50.7.74.174:9030', // theia7
        '3C79699D4FBC37DE1A212D5033B56DAE079AC0EF' => '212.83.154.33:8888', // bauruine203
        '3CB4193EF4E239FCEDC4DC43468E0B0D6B67ACC3' => '51.38.65.160:9030', // rofltor10
        '3CCF9573F59137E52787D9C322AC19D2BD090B70' => '95.216.211.81:80', // BurningMan
        '3E53D3979DB07EFD736661C934A1DED14127B684' => '217.79.179.177:9030', // Unnamed
        //'3F092986E9B87D3FDA09B71FA3A602378285C77A' => '66.111.2.16:9030', // NYCBUG1 (NF 2020/09/17)
        '4061C553CA88021B8302F0814365070AAE617270' => '185.100.85.101:9030', // TorExitRomania
        '4623A9EC53BFD83155929E56D6F7B55B5E718C24' => '163.172.157.213:8080', // Cotopaxi
        '484A10BA2B8D48A5F0216674C8DD50EF27BC32F3' => '193.70.43.76:9030', // Aerodynamik03
        '4BFC9C631A93FF4BA3AA84BC6931B4310C38A263' => '109.70.100.4:80', // karotte
        //'4EB55679FA91363B97372554F8DC7C63F4E5B101' => '81.7.13.84:80', // torpidsDEisppro (NF 2020/12/02)
        '4F0DB7E687FC7C0AE55C8F243DA8B0EB27FBF1F2' => '108.53.208.157:80', // Binnacle
        '509EAB4C5D10C9A9A24B4EA0CE402C047A2D64E6' => '5.9.158.75:9030', // zwiebeltoralf2
        '510176C07005D47B23E6796F02C93241A29AA0E9' => '69.30.215.42:80', // torpidsUSwholesale
        '5262556D44A7F2434990FDE1AE7973C67DF49E58' => '176.223.141.106:80', // Theoden
        '52BFADA8BEAA01BA46C8F767F83C18E2FE50C1B9' => '85.25.159.65:995', // BeastieJoy63
        '562434D987CF49D45649B76ADCA993BEA8F78471' => '193.234.15.59:80', // bakunin2
        '578E007E5E4535FBFEF7758D8587B07B4C8C5D06' => '89.234.157.254:80', // marylou1
        '5E56738E7F97AA81DEEF59AF28494293DFBFCCDF' => '172.98.193.43:80', // Backplane
        '68F175CCABE727AA2D2309BCD8789499CEE36ED7' => '163.172.139.104:8080', // Pichincha
        '6A7551EEE18F78A9813096E82BF84F740D32B911' => '95.217.16.212:80', // TorMachine
        //'7262B9D2EDE0B6A266C4B43D6202209BF6BBA888' => '78.156.110.135:9093', // SkynetRenegade (NF 2020/12/02)
        '72B2B12A3F60408BDBC98C6DF53988D3A0B3F0EE' => '85.235.250.88:80', // TykRelay01
        '742C45F2D9004AADE0077E528A4418A6A81BC2BA' => '178.17.170.23:9030', // TorExitMoldova2
        '7600680249A22080ECC6173FBBF64D6FCF330A61' => '81.7.14.31:9001', // Ichotolot62
        '7614EF326635DA810638E2F5D449D10AE2BB7158' => '62.171.144.155:80', // Nicenstein
        '77131D7E2EC1CA9B8D737502256DA9103599CE51' => '77.247.181.166:80', // CriticalMass
        '775B0FAFDE71AADC23FFC8782B7BEB1D5A92733E' => '5.196.23.64:9030', // Aerodynamik01
        '79509683AB4C8DDAF90A120C69A4179C6CD5A387' => '185.244.193.141:9030', // DerDickeReloaded
        //'7A32C9519D80CA458FC8B034A28F5F6815649A98' => '82.223.21.74:9030', // silentrocket (NF 2020/09/17)
        '7BB70F8585DFC27E75D692970C0EEB0F22983A63' => '51.254.136.195:80', // torproxy02
        '7BFB908A3AA5B491DA4CA72CCBEE0E1F2A939B55' => '77.247.181.162:80', // sofia
        '80AAF8D5956A43C197104CEF2550CD42D165C6FB' => '193.11.114.45:9031', // mdfnet2
        '8101421BEFCCF4C271D5483C5AABCAAD245BBB9D' => '51.254.96.208:9030', // rofltor01
        '8111FEB45EF2950EB8F84BFD8FF070AB07AEE9DD' => '152.89.106.147:9030', // TugaOnionMR3
        '81B75D534F91BFB7C57AB67DA10BCEF622582AE8' => '192.42.116.16:80', // hviv104
        '844AE9CAD04325E955E2BE1521563B79FE7094B7' => '192.87.28.82:9030', // Smeerboel
        '855BC2DABE24C861CD887DB9B2E950424B49FC34' => '85.228.136.92:9030', // Logforme
        '85A885433E50B1874F11CEC9BE98451E24660976' => '178.254.7.88:8080', // wr3ck3d0ni0n01
        '8C00FA7369A7A308F6A137600F0FA07990D9D451' => '163.172.194.53:9030', // GrmmlLitavis
        '8CAA470B905758742203E3EB45941719FCA9FEEC' => '188.138.102.98:465', // BeastieJoy64
        '8CF987FF43FB7F3D9AA4C4F3D96FFDF247A9A6C2' => '109.70.100.6:80', // zucchini
        '8D79F73DCD91FC4F5017422FAC70074D6DB8DD81' => '5.189.169.190:8030', // thanatosDE
        '8E6EDA78D8E3ABA88D877C3E37D6D4F0938C7B9F' => '80.67.172.162:80', // AlGrothendieck
        '90A5D1355C4B5840E950EB61E673863A6AE3ACA1' => '54.37.139.118:9030', // rofltor09
        '924B24AFA7F075D059E8EEB284CC400B33D3D036' => '96.253.78.108:80', // NSDFreedom
        '9661AC95717798884F3E3727D360DD98D66727CC' => '109.70.100.5:80', // erdapfel
        '99E246DB480B313A3012BC3363093CC26CD209C7' => '173.212.254.192:31336', // ViDiSrv
        '9B2BC7EFD661072AFADC533BE8DCF1C19D8C2DCC' => '188.127.69.60:80', // MIGHTYWANG
        '9B31F1F1C1554F9FFB3455911F82E818EF7C7883' => '185.100.86.128:9030', // TorExitFinland
        '9BA84E8C90083676F86C7427C8D105925F13716C' => '95.142.161.63:80', // ekumen
        '9C900A7F6F5DD034CFFD192DAEC9CCAA813DB022' => '86.105.212.130:9030', // firstor2
        '9F7D6E6420183C2B76D3CE99624EBC98A21A967E' => '46.28.110.244:80', // Nivrim
        'A0F06C2FADF88D3A39AA3072B406F09D7095AC9E' => '46.165.230.5:80', // Dhalgren
        'A1B28D636A56AAFFE92ADCCA937AA4BD5333BB4C' => '193.234.15.55:80', // bakunin4
        'A53C46F5B157DD83366D45A8E99A244934A14C46' => '128.31.0.13:80', // csailmitexit
        //'A68097FE97D3065B1A6F4CE7187D753F8B8513F5' => '212.47.233.86:9130', // olabobamanmu (NF 2020/09/17)
        //'A9406A006D6E7B5DA30F2C6D4E42A338B5E340B2' => '163.172.149.122:80', // niij03 (NF 2020/12/02)
        'AC2BEDD0BAC72838EA7E6F113F856C4E8018ACDB' => '176.10.107.180:9030', // schokomilch
        'AC66FFA4AB35A59EBBF5BF4C70008BF24D8A7A5C' => '195.154.164.243:80', // torpidsFRonline3
        'ACDD9E85A05B127BA010466C13C8C47212E8A38F' => '185.129.62.62:9030', // kramse
        'AD19490C7DBB26D3A68EFC824F67E69B0A96E601' => '188.40.128.246:9030', // sputnik
        'AD86CD1A49573D52A7B6F4A35750F161AAD89C88' => '176.10.104.240:8080', // DigiGesTor1e2
        'B06F093A3D4DFAD3E923F4F28A74901BD4F74EB1' => '178.17.174.14:9030', // TorExitMoldova
        'B143D439B72D239A419F8DCE07B8A8EB1B486FA7' => '212.129.62.232:80', // wardsback
        'B27CF1DCEECD50F7992B07D720D7F6BF0EDF9D40' => '109.70.100.2:80', // radieschen
        //'B291D30517D23299AD7CEE3E60DFE60D0E3A4664' => '136.243.214.137:80', // TorKIT (NF 2020/12/02)
        'B5212DB685A2A0FCFBAE425738E478D12361710D' => '93.115.97.242:9030', // firstor
        'B83DC1558F0D34353BB992EF93AFEAFDB226A73E' => '193.11.114.46:9032', // mdfnet3
        'B84F248233FEA90CAD439F292556A3139F6E1B82' => '85.248.227.164:444', // tollana
        //'BB60F5BA113A0B8B44B7B37DE3567FE561E92F78' => '51.15.179.153:110', // Casper04 (NF 2020/12/02)
        'BCEDF6C193AA687AE471B8A22EBF6BC57C2D285E' => '198.96.155.3:8080', // gurgle
        'BCEF908195805E03E92CCFE669C48738E556B9C5' => '128.199.55.207:9030', // EldritchReaper
        'BD552C165E2ED2887D3F1CCE9CFF155DDA2D86E6' => '213.141.138.174:9030', // Schakalium
        'BF0FB582E37F738CD33C3651125F2772705BB8E8' => '148.251.190.229:9030', // quadhead
        'BF735F669481EE1CCC348F0731551C933D1E2278' => '212.47.233.250:9030', // freeway
        'C0C4F339046EB824999F711D178472FDF53BE7F5' => '132.248.241.5:9130', // toritounam2
        'C282248597D1C8522A2A7525E61C8B77BBC37614' => '109.70.100.3:80', // erbse
        'C36A434DB54C66E1A97A5653858CE36024352C4D' => '50.7.74.170:9030', // theia9
        'C414F28FD2BEC1553024299B31D4E726BEB8E788' => '188.138.112.60:1433', // zebra620
        'C656B41AEFB40A141967EBF49D6E69603C9B4A11' => '178.20.55.18:80', // marcuse2
        'C793AB88565DDD3C9E4C6F15CCB9D8C7EF964CE9' => '85.248.227.163:443', // ori
        'C87A4D8B534F78FDF0F4639B55F121401FEF259C' => '50.7.74.173:80', // theia4
        'CBD0D1BD110EC52963082D839AC6A89D0AE243E7' => '176.31.103.150:9030', // UV74S7mjxRcYVrGsAMw
        'CD0F9AA1A5064430B1DE8E645CBA7A502B27ED5F' => '193.234.15.62:80', // jaures4
        'CE47F0356D86CF0A1A2008D97623216D560FB0A8' => '85.25.213.211:465', // BeastieJoy61
        'D1AFBF3117B308B6D1A7AA762B1315FD86A6B8AF' => '50.7.74.172:80', // theia2
        'D317C7889162E9EC4A1DA1A1095C2A0F377536D9' => '66.111.2.20:9030', // NYCBUG0
        'D405FCCF06ADEDF898DF2F29C9348DCB623031BA' => '5.45.111.149:80', // gGDHjdcC6zAlM8k08lY
        'D5C33F3E203728EDF8361EA868B2939CCC43FAFB' => '12.235.151.200:9030', // nx1tor
        'D7082DB97E7F0481CBF4B88CA5F5683399E196A3' => '212.83.166.62:80', // shhop
        'DB2682153AC0CCAECD2BD1E9EBE99C6815807A1E' => '54.36.237.163:80', // GermanCraft2
        'DD8BD7307017407FCC36F8D04A688F74A0774C02' => '171.25.193.20:80', // DFRI0
        'DDBB2A38252ADDA53E4492DDF982CA6CC6E10EC0' => '83.212.99.68:80', // zouzounella
        'E41B16F7DDF52EBB1DB4268AB2FE340B37AD8904' => '166.70.207.2:9130', // xmission1
        'E51620B90DCB310138ED89EDEDD0A5C361AAE24E' => '185.100.86.182:9030', // NormalCitizen
        'E81EF60A73B3809F8964F73766B01BAA0A171E20' => '212.47.244.38:8080', // Chimborazo
        'E8D114B3C78D8E6E7FEB1004650DD632C2143C9E' => '185.4.132.148:80', // libreonion1
        'E947C029087FA1C3499BEF5D4372947C51223D8F' => '195.154.105.170:9030', // dgplug
        'EBE718E1A49EE229071702964F8DB1F318075FF8' => '131.188.40.188:1443', // fluxe4
        //'ED2338CAC2711B3E331392E1ED2831219B794024' => '192.87.28.28:9030', // SEC6xFreeBSD64 (NF 2020/09/17)
        'EFAE44728264982224445E96214C15F9075DEE1D' => '178.20.55.16:80', // marcuse1
        'EFEACD781604EB80FBC025EDEDEA2D523AEAAA2F' => '217.182.75.181:9030', // Aerodynamik02
        'F24F8BEA2779A79111F33F6832B062BED306B9CB' => '193.234.15.58:80', // jaures2
        //'F2DFE5FA1E4CF54F8E761A6D304B9B4EC69BDAE8' => '129.13.131.140:80', // AlleKochenKaffee (NF 2020/09/17)
        'F4263275CF54A6836EE7BD527B1328836A6F06E1' => '37.187.102.108:80', // EvilMoe
        'F4C0EDAA0BF0F7EC138746F8FEF1CE26C7860265' => '5.199.142.236:9030', // tornodenumber9004
        'F741E5124CB12700DA946B78C9B2DD175D6CD2A1' => '163.172.154.162:9030', // rofltor06
        'F8D27B163B9247B232A2EEE68DD8B698695C28DE' => '78.47.18.110:443', // fluxe3
        'F9246DEF2B653807236DA134F2AEAB103D58ABFE' => '91.143.88.62:80', // Freebird31
        'FE296180018833AF03A8EACD5894A614623D3F76' => '149.56.45.200:9030', // PyotrTorpotkinOne
        'FF9FC6D130FA26AE3AE8B23688691DC419F0F22E' => '62.141.38.69:80', // rinderwahnRelay3L
        'FFA72BD683BC2FCF988356E6BEC1E490F313FB07' => '193.11.164.243:9030', // Lule
    );

    protected $preferredServer;

    protected $connectTimeout = 5;
    protected $readTimeout = 30;
    protected $userAgent = 'dapphp/TorUtils 1.1.13';

    protected $parser;
    protected $serverList;

    /**
     * DirectoryClient constructor
     */
    public function __construct()
    {
        $this->serverList = array_merge($this->directoryAuthorities, $this->directoryFallbacks);
        shuffle($this->serverList);

        $this->parser = new Parser();
    }

    /**
     * Set the preferred directory server to use for lookups.  This server will always be used
     * first.  If the preferred server times out or fails, the lookup will proceed using a random
     * server from the list of directory authorities and fallbacks.
     *
     * @param string $server The directory server to connect to (e.g. 1.2.3.4:80)
     * @return \Dapphp\TorUtils\DirectoryClient
     */
    public function setPreferredServer($server)
    {
        $this->preferredServer = $server;

        return $this;
    }

    public function setServerList($list)
    {
        $this->serverList = $list;

        return $this;
    }

    /**
     * Set the connection timeout period (in seconds).  Attempts to connect to
     * directories that take longer than this will time out and try the next host.
     *
     * @param number $timeout  The connection timeout in seconds
     * @throws \InvalidArgumentException If timeout is non-numeric or less than 1
     * @return \Dapphp\TorUtils\DirectoryClient
     */
    public function setConnectTimeout($timeout)
    {
        if (!preg_match('/^\d+$/', $timeout) || (int)$timeout < 1) {
            throw new \InvalidArgumentException('Timeout must be a positive integer');
        }

        $this->connectTimeout = (int)$timeout;

        return $this;
    }

    /**
     * Set the read timeout in seconds (default = 30).  Directory requests
     * that fail to receive any data after this many seconds will time out
     * and try the next host.
     *
     * @param number $timeout  The read timeout in seconds
     * @throws \InvalidArgumentException If timeout is non-numeric or less than 1
     * @return \Dapphp\TorUtils\DirectoryClient
     */
    public function setReadTimeout($timeout)
    {
        if (!preg_match('/^\d+$/', $timeout) || (int)$timeout < 1) {
            throw new \InvalidArgumentException('Timeout must be a positive integer');
        }

        $this->readTimeout = (int)$timeout;

        return $this;
    }

    public function getReadTimeout()
    {
        return $this->readTimeout;
    }

    /**
     * Get the list of Tor directory authority servers
     *
     * @return array Array of directory authorities, keyed by fingerprint (value may be a string [ip address] or array of IP addresses)
     */
    public function getDirectoryAuthorities()
    {
        return $this->directoryAuthorities;
    }

    /**
     * Get the list of Tor directory authority servers
     *
     * @return array Array of directory fallbacks, keyed by fingerprint (value may be a string [ip address] or array of IP addresses)
     */
    public function getDirectoryFallbacks()
    {
        return $this->directoryFallbacks;
    }

    /**
     * Fetch a list of all known router descriptors on the Tor network
     *
     * @return array Array of RouterDescriptor objects
     */
    public function getAllServerDescriptors()
    {
        $reply = $this->_request(
            sprintf('/tor/server/all%s', (function_exists('gzuncompress') ? '.z' : ''))
        );

        $descriptors = $this->parser->parseDirectoryStatus($reply);

        return $descriptors;
    }

    /**
     * Fetch directory information about a router
     * @param string|array $fingerprint router fingerprint or array of fingerprints to get information about
     * @return mixed Array of RouterDescriptor objects, or a single RouterDescriptor object
     */
    public function getServerDescriptor($fingerprint)
    {
        if (is_array($fingerprint)) {
            $fp = implode('+', $fingerprint);
        } else {
            $fp = $fingerprint;
        }

        $uri = sprintf('/tor/server/fp/%s%s', $fp, (function_exists('gzuncompress') ? '.z' : ''));

        $reply = $this->_request($uri);

        $descriptors = $this->parser->parseDirectoryStatus($reply);

        if (sizeof($descriptors) == 1) {
            return array_shift($descriptors);
        } else {
            return $descriptors;
        }
    }

    /**
     * Pick a random dir authority to query and perform the HTTP request for directory info
     *
     * @param string $uri Uri to request
     * @param string $directoryServer IP and port of the directory to query
     * @throws \Exception No authorities responded
     * @return \Dapphp\TorUtils\ProtocolReply The reply from the directory authority
     */
    private function _request($uri, $directoryServer = null)
    {
        reset($this->serverList);
        $used = false;

        do {
            // pick a server from the list, it is randomized in __construct
            if ($this->preferredServer && !$used) {
                $server = $this->preferredServer;
                $used   = true;
            } else {
                $server = $this->getNextServer();
            }

            if ($server === false) {
                throw new \Exception('No more directory servers available to query');
            }

            list($host, $port) = @explode(':', $server);
            if (!$port) $port = 80;

            $fp = fsockopen($host, $port, $errno, $errstr, $this->connectTimeout);
            if (!$fp) continue;

            $request = $this->_getHttpRequest('GET', $host, $uri);

            $written = fwrite($fp, $request);

            if ($written === false) {
                trigger_error("Failed to write directory request to $server", E_USER_NOTICE);
                continue;
            } elseif (strlen($request) != $written) {
                trigger_error("Request to $server failed; could not write all data", E_USER_NOTICE);
                continue;
            }

            $response = '';

            stream_set_blocking($fp, 0);

            $read   = array($fp);
            $write  = null;
            $except = null;
            $err    = false;

            while (!feof($fp)) {
                $changed = stream_select($read, $write, $except, $this->readTimeout);

                if ($changed === false) {
                    trigger_error("stream_select() returned error while reading data from $server", E_USER_NOTICE);
                    $err = true;
                    break;
                } elseif ($changed < 1) {
                    trigger_error("Failed to read all data from $server within timeout", E_USER_NOTICE);
                    $err = true;
                    break;
                } else {
                    $data = fgets($fp);

                    if ($data === false) {
                        trigger_error("Directory read failed while talking to $server", E_USER_NOTICE);
                        $err = true;
                        break;
                    } else {
                        $response .= $data;
                    }
                }
            }

            fclose($fp);

            if ($err) {
                continue;
            }

            list($headers, $body) = explode("\r\n\r\n", $response, 2);
            $headers = $this->_parseHttpResponseHeaders($headers);

            if ($headers['status_code'] == '503') {
                trigger_error("Directory $server returned 503 {$headers['message']}", E_USER_NOTICE);
                continue;
            } elseif ($headers['status_code'] == '504') {
                // observed this from various fallback dirs. This code is not defined in dir-spec.txt
                trigger_error("Directory $server returned 504 {$headers['message']}", E_USER_NOTICE);
                continue;
            }

            if ($headers['status_code'] !== '200') {
                throw new \Exception(
                    sprintf(
                        'Directory %s returned a negative response code to request.  %s %s',
                        $server,
                        $headers['status_code'],
                        $headers['message']
                    )
                );
            }

            $encoding = (isset($headers['headers']['content-encoding'])) ? $headers['headers']['content-encoding'] : null;

            if ($encoding == 'deflate') {
                if (!function_exists('gzuncompress')) {
                    throw new \Exception('Directory response was gzip compressed but PHP does not have zlib support enabled');
                }

                $body = gzuncompress($body);
                if ($body === false) {
                    throw new \Exception('Failed to inflate response data');
                }
            } else if ($encoding == 'identity') {
                // nothing to do
            } else {
                throw new \Exception('Directory sent response in an unknown encoding: ' . $encoding);
            }

            break;
        } while (true);

        $reply = new ProtocolReply();
        $reply->appendReplyLine(
            sprintf('%s %s', $headers['status_code'], $headers['message'])
        );
        $reply->appendReplyLines(explode("\n", $body));

        return $reply;
    }

    /**
     * Construct an http request for talking to a directory server
     *
     * @param string $method GET|POST
     * @param string $host IP/hostname to query
     * @param string $uri The request URI
     * @return string Completed HTTP request
     */
    private function _getHttpRequest($method, $host, $uri)
    {
        $request = sprintf(
            "%s %s HTTP/1.0\r\n" .
            "Host: $host\r\n" .
            "Connection: close\r\n" .
            "User-Agent: %s\r\n" .
            "\r\n",
            $method, $uri, $host, $this->userAgent
        );

        return $request;
    }

    /**
     * Parse HTTP response headers from the directory reply
     *
     * @param string $headers String of http response headers
     * @throws \Exception Response was not a valid http response
     * @return array Array with http status_code, message, and lines of headers
     */
    private function _parseHttpResponseHeaders($headers)
    {
        $lines    = explode("\r\n", $headers);
        $response = array_shift($lines);
        $header   = array();

        if (!preg_match('/^HTTP\/\d\.\d (\d{3}) (.*)$/i', $response, $match)) {
            throw new \Exception('Directory server sent a malformed HTTP response');
        }

        $code    = $match[1];
        $message = $match[2];

        foreach($lines as $line) {
            if (strpos($line, ':') === false) {
                throw new \Exception('Directory server sent an HTTP response line missing the ":" separator');
            }
            list($name, $value) = explode(':', $line, 2);
            $header[strtolower($name)] = trim($value);
        }

        return array(
            'status_code' => $code,
            'message'     => $message,
            'headers'     => $header,
        );
    }

    /**
     * Get the next directory authority from the list to query
     *
     * @return string IP:Port of directory
     */
    private function getNextServer()
    {
        $server = current($this->serverList);
        next($this->serverList);
        return $server;
    }
}
