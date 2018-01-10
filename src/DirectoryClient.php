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

require_once 'Parser.php';
require_once 'ProtocolReply.php';

use Dapphp\TorUtils\Parser;
use Dapphp\TorUtils\ProtocolReply;

/**
 * Class for getting router info from Tor directory authorities
 *
 */
class DirectoryClient
{
    /**
     * @var $directoryAuthorities List of directory authorities https://gitweb.torproject.org/tor.git/tree/src/or/config.c#n1052
     */
    protected $directoryAuthorities = array(
        '7BE683E65D48141321C5ED92F075C55364AC7123' => '193.23.244.244:80', // dannenberg
        '7EA6EAD6FD83083C538F44038BBFA077587DD755' => '194.109.206.212:80', // dizum
        'CF6D0AAFB385BE71B8E111FC5CFF4B47923733BC' => '154.35.175.225:80', // Faravahar
        'F2044413DAC2E02E3D6BCF4735A19BCA1DE97281' => '131.188.40.189:80', // gabelmoo
        '74A910646BCEEFBCD2E874FC1DC997430F968145' => '199.58.81.140:80', // longclaw
        'BD6A829255CB08E66FBE7D3748363586E46B3810' => '171.25.193.9:443', // maatuska
        '9695DFC35FFEB861329B9F1AB04C46397020CE31' => '128.31.0.39:9131', // moria1
        '1D8F3A91C37C5D1C4C19B1AD1D0CFBE8BF72D8E1' => '37.218.247.217:80', // Bifroest
        '847B1F850344D7876491A54892F904934E4EB85D' => '86.59.21.38:80', // tor26
        '24E2F139121D4394C54B5BCC368B3B411857C413' => '204.13.164.118:80', // bastet
    );

    /**
     * @var array Array of directory fallbacks from https://gitweb.torproject.org/tor.git/tree/src/or/fallback_dirs.inc
     */
    protected $directoryFallbacks = array(
        // List updated 2018/01/09 (commit blob c446152e6a717cd7f754b4e006051bb0c377ebd9)
        // NIA = Not In Atlas (atlas.torproject.org) - The fingerprint was not found in Atlas on the date given
        '001524DD403D729F08F7E5D77813EF12756CFA8D' => '185.13.39.197:80', // Neldoreth
        '0111BA9B604669E636FFD5B503F382A4B7AD6E80' => '176.10.104.240:80', // DigiGesTor1e1
        '025B66CEBC070FCB0519D206CF0CF4965C20C96E' => '185.100.85.61:80', // nibbana
        '0756B7CD4DFC8182BE23143FAC0642F515182CEB' => '5.9.110.236:9030', // rueckgrat
        '0B85617241252517E8ECF2CFC7F4C1A32DCD153F' => '163.172.149.155:80', // niij02
        '0BEA4A88D069753218EAAAD6D22EA87B9A1319D6' => '5.39.92.199:80', // BaelorTornodePw
        '0CF8F3E6590F45D50B70F2F7DA6605ECA6CD408F' => '163.172.25.118:80', // torpidsFRonline4
        '0D3EBA17E1C78F1E9900BABDB23861D46FCAF163' => '178.62.197.82:80', // HY100
        '0E8C0C8315B66DB5F703804B3889A1DD66C67CE0' => '185.100.86.100:80', // saveyourprivacyex1
        '11DF0017A43AF1F08825CD5D973297F81AB00FF3' => '37.120.174.249:80', // gGDHjdcC6zAlM8k08lX
        '12AD30E5D25AA67F519780E2111E611A455FDC89' => '193.11.114.43:9030', // mdfnet1
        '12FD624EE73CEF37137C90D38B2406A66F68FAA2' => '37.157.195.87:8030', // thanatosCZ
        '136F9299A5009A4E0E96494E723BDB556FB0A26B' => '178.16.208.59:80', // bakunin2
        '16102E458460349EE45C0901DAA6C30094A9BBEA' => '163.172.138.22:80', // mkultra
        '175921396C7C426309AB03775A9930B6F611F794' => '178.62.60.37:80', // lovejoy
        '185663B7C12777F052B2C2D23D7A239D8DA88A0F' => '171.25.193.25:80', // DFRI5
        '1938EBACBB1A7BFA888D9623C90061130E63BB3F' => '149.56.141.138:9030', // Aerodynamik04
        '1AE039EE0B11DB79E4B4B29CBA9F752864A0259E' => '81.7.14.253:9001', // Ichotolot60
        '1C90D3AEADFF3BCD079810632C8B85637924A58E' => '163.172.53.84:143', // Multivac
        '1DBAED235E3957DE1ABD25B4206BE71406FB61F8' => '46.101.151.222:80', // flanders
        '1ECD73B936CB6E6B3CD647CC204F108D9DF2C9F7' => '91.219.237.229:80', // JakeDidNothingWrong
        '1F6ABD086F40B890A33C93CC4606EE68B31C9556' => '199.184.246.250:80', // dao
        '1FA8F638298645BE58AC905276680889CB795A94' => '185.129.249.124:9030', // treadstone
        '20462CBA5DA4C2D963567D17D0B7249718114A68' => '212.47.229.2:9030', // scaletor
        '204DFD2A2C6A0DC1FA0EACB495218E0B661704FD' => '77.247.181.164:80', // HaveHeart
        '230A8B2A8BA861210D9B4BA97745AEC217A94207' => '163.172.176.167:80', // niij01
        '231C2B9C8C31C295C472D031E06964834B745996' => '37.200.98.5:80', // torpidsDEdomainf
        '2BA2C8E96B2590E1072AECE2BDB5C48921BF8510' => '138.201.250.33:9012', // storm
        '2CDCFED0142B28B002E89D305CBA2E26063FADE2' => '178.16.208.56:80', // jaures
        '2F0F32AB1E5B943CA7D062C03F18960C86E70D94' => '97.74.237.196:9030', // Minotaur
        '30C19B81981F450C402306E2E7CFB6C3F79CB6B2' => '64.113.32.29:9030', // Libero
        '328E54981C6DDD7D89B89E418724A4A7881E3192' => '80.127.117.180:80', // sjc01
        '330CD3DB6AD266DC70CDB512B036957D03D9BC59' => '185.100.84.212:80', // TeamTardis
        '33DA0CAB7C27812EFF2E22C9705630A54D101FEB' => '163.172.13.165:9030', // mullbinde9
        '3711E80B5B04494C971FB0459D4209AB7F2EA799' => '91.121.23.100:9030', // 0x3d002
        '379FB450010D17078B3766C2273303C358C3A442' => '176.126.252.12:21', // aurora
        '387B065A38E4DAA16D9D41C2964ECBC4B31D30FF' => '62.210.92.11:9130', // redjohn1
        '39F096961ED2576975C866D450373A9913AFDC92' => '198.50.191.95:80', // thomas
        '3B33F6FCA645AD4E91428A3AF7DC736AD9FB727B' => '164.132.77.175:9030', // rofltor1
        '3C79699D4FBC37DE1A212D5033B56DAE079AC0EF' => '212.83.154.33:8888', // bauruine203
        '3D7E274A87D9A89AF064C13D1EE4CA1F184F2600' => '176.10.107.180:9030', // schokomilch
        '3E53D3979DB07EFD736661C934A1DED14127B684' => '217.79.179.177:9030', // Unnamed
        '4061C553CA88021B8302F0814365070AAE617270' => '185.100.85.101:9030', // TorExitRomania
        '40E7D6CE5085E4CDDA31D51A29D1457EB53F12AD' => '199.249.223.61:80', // Quintex12
        '41C59606AFE1D1AA6EC6EF6719690B856F0B6587' => '178.17.170.156:9030', // TorExitMoldova2
        '439D0447772CB107B886F7782DBC201FA26B92D1' => '178.62.86.96:9030', // pablobm001
        '4623A9EC53BFD83155929E56D6F7B55B5E718C24' => '163.172.157.213:8080', // Cotopaxi
        '46791D156C9B6C255C2665D4D8393EC7DBAA7798' => '31.31.78.49:80', // KrigHaBandolo
        '484A10BA2B8D48A5F0216674C8DD50EF27BC32F3' => '193.70.43.76:9030', // Aerodynamik03
        '489D94333DF66D57FFE34D9D59CC2D97E2CB0053' => '37.187.102.186:9030', // txtfileTorNode65536
        '4CC9CC9195EC38645B699A33307058624F660CCF' => '51.254.101.242:9002', // devsum
        '4F0DB7E687FC7C0AE55C8F243DA8B0EB27FBF1F2' => '108.53.208.157:80', // Binnacle
        '50586E25BE067FD1F739998550EDDCB1A14CA5B2' => '212.51.134.123:9030', // Jans
        '51E1CF613FD6F9F11FE24743C91D6F9981807D82' => '81.7.16.182:80', // torpidsDEisppro3
        '52BFADA8BEAA01BA46C8F767F83C18E2FE50C1B9' => '85.25.159.65:995', // BeastieJoy63
        '587E0A9552E4274B251F29B5B2673D38442EE4BF' => '95.130.12.119:80', // Nuath
        '58ED9C9C35E433EE58764D62892B4FFD518A3CD0' => '185.21.100.50:9030', // SamAAdams2
        '5E56738E7F97AA81DEEF59AF28494293DFBFCCDF' => '172.98.193.43:80', // Backplane
        '5F4CD12099AF20FAF9ADFDCEC65316A376D0201C' => '199.249.223.74:80', // QuintexAirVPN7
        '616081EC829593AF4232550DE6FFAA1D75B37A90' => '95.128.43.164:80', // AquaRayTerminus
        '68F175CCABE727AA2D2309BCD8789499CEE36ED7' => '163.172.139.104:8080', // Pichincha
        '6A7551EEE18F78A9813096E82BF84F740D32B911' => '85.214.62.48:80', // TorMachine
        '6EF897645B79B6CB35E853B32506375014DE3621' => '80.127.137.19:80', // d6relay
        '72B2B12A3F60408BDBC98C6DF53988D3A0B3F0EE' => '85.235.250.88:80', // TykRelay01
        '7600680249A22080ECC6173FBBF64D6FCF330A61' => '81.7.14.31:9001', // Ichotolot62
        '763C9556602BD6207771A7A3D958091D44C43228' => '134.119.36.135:80', // torpidsDEdomainf2
        '774555642FDC1E1D4FDF2E0C31B7CA9501C5C9C7' => '188.166.133.133:9030', // dropsy
        '775B0FAFDE71AADC23FFC8782B7BEB1D5A92733E' => '5.196.23.64:9030', // Aerodynamik01
        '789EA6C9AE9ADDD8760903171CFA9AC5741B0C70' => '81.30.158.213:9030', // dumpster
        '78E2BE744A53631B4AAB781468E94C52AB73968B' => '104.200.20.46:80', // bynumlawtor
        '79E169B25E4C7CE99584F6ED06F379478F23E2B8' => '62.210.129.246:80', // MilesPrower
        '7A32C9519D80CA458FC8B034A28F5F6815649A98' => '82.223.21.74:9030', // silentrocket
        '7BB70F8585DFC27E75D692970C0EEB0F22983A63' => '51.254.136.195:80', // torproxy02
        '7BFB908A3AA5B491DA4CA72CCBEE0E1F2A939B55' => '77.247.181.162:80', // sofia
        '7D05A38E39FC5D29AFE6BE487B9B4DC9E635D09E' => '185.100.84.82:80', // saveyourprivacyexit
        '7FA8E7E44F1392A4E40FFC3B69DB3B00091B7FD3' => '199.249.223.69:80', // Quintex20
        '80AAF8D5956A43C197104CEF2550CD42D165C6FB' => '193.11.114.45:9031', // mdfnet2
        '8456DFA94161CDD99E480C2A2992C366C6564410' => '62.210.254.132:80', // turingmachine
        '855BC2DABE24C861CD887DB9B2E950424B49FC34' => '85.230.184.93:9030', // Logforme
        '8567AD0A6369ED08527A8A8533A5162AC00F7678' => '72.52.75.27:9030', // piecoopdotnet
        '86C281AD135058238D7A337D546C902BE8505DDE' => '185.96.88.29:80', // TykRelay05
        '88487BDD980BF6E72092EE690E8C51C0AA4A538C' => '176.10.104.243:80', // DigiGesTor2e1
        '8C00FA7369A7A308F6A137600F0FA07990D9D451' => '163.172.194.53:9030', // GrmmlLitavis
        '8D79F73DCD91FC4F5017422FAC70074D6DB8DD81' => '5.189.169.190:8030', // thanatosDE
        '9007C1D8E4F03D506A4A011B907A9E8D04E3C605' => '151.80.42.103:9030', // matlink
        '91D23D8A539B83D2FB56AA67ECD4D75CC093AC55' => '37.187.20.59:80', // torpidsFRovh
        '9285B22F7953D7874604EEE2B470609AD81C74E9' => '62.138.7.171:8030', // 0x3d005
        '92CFD9565B24646CAC2D172D3DB503D69E777B8A' => '178.16.208.57:80', // bakunin
        '92ECC9E0E2AF81BB954719B189AC362E254AD4A5' => '91.219.237.244:80', // lewwerDuarUesSlaav
        '9772EFB535397C942C3AB8804FB35CFFAD012438' => '37.153.1.10:9030', // smallsweatnode
        '998BF3ED7F70E33D1C307247B9626D9E7573C438' => '163.172.223.200:80', // Outfall2
        '9A0D54D3A6D2E0767596BF1515E6162A75B3293F' => '91.229.20.27:9030', // gordonkeybag
        '9A68B85A02318F4E7E87F2828039FBD5D75B0142' => '66.111.2.20:9030', // NYCBUG0
        '9B31F1F1C1554F9FFB3455911F82E818EF7C7883' => '185.100.86.128:9030', // TorExitFinland
        '9EC5E097663862DF861A18C32B37C5F82284B27D' => '146.185.177.103:80', // Winter
        '9F2856F6D2B89AD4EF6D5723FAB167DB5A53519A' => '199.249.223.64:80', // Quintex15
        '9F7D6E6420183C2B76D3CE99624EBC98A21A967E' => '46.28.110.244:80', // Nivrim
        '9FBEB75E8BC142565F12CBBE078D63310236A334' => '91.121.84.137:4952', // lindon
        'A0F06C2FADF88D3A39AA3072B406F09D7095AC9E' => '46.165.230.5:80', // Dhalgren
        'A10C4F666D27364036B562823E5830BC448E046A' => '171.25.193.77:80', // DFRI1
        'A2E6BB5C391CD46B38C55B4329C35304540771F1' => '81.7.3.67:993', // BeastieJoy62
        'A478E421F83194C114F41E94F95999672AED51FE' => '171.25.193.78:80', // DFRI4
        'A4C98CEA3F34E05299417E9F885A642C88EF6029' => '178.16.208.58:80', // jaures2
        'A9406A006D6E7B5DA30F2C6D4E42A338B5E340B2' => '163.172.149.122:80', // niij03
        'AC66FFA4AB35A59EBBF5BF4C70008BF24D8A7A5C' => '195.154.164.243:80', // torpidsFRonline3
        'ACD889D86E02EDDAB1AFD81F598C0936238DC6D0' => '86.59.119.88:80', // ph3x
        'ACDD9E85A05B127BA010466C13C8C47212E8A38F' => '185.129.62.62:9030', // kramse
        'AD19490C7DBB26D3A68EFC824F67E69B0A96E601' => '188.40.128.246:9030', // sputnik
        'B0279A521375F3CB2AE210BDBFC645FDD2E1973A' => '176.126.252.11:443', // chulak
        'B0553175AADB0501E5A61FC61CEA3970BE130FF2' => '5.9.147.226:9030', // zwiubel
        'B06F093A3D4DFAD3E923F4F28A74901BD4F74EB1' => '178.17.174.14:9030', // TorExitMoldova
        'B0CD9F9B5B60651ADC5919C0F1EAA87DBA1D9249' => '199.249.223.40:80', // Quintex31
        'B143D439B72D239A419F8DCE07B8A8EB1B486FA7' => '212.129.62.232:80', // wardsback
        'B291D30517D23299AD7CEE3E60DFE60D0E3A4664' => '136.243.214.137:80', // TorKIT
        'B4CAFD9CBFB34EC5DAAC146920DC7DFAFE91EA20' => '212.47.233.86:9030', // netimanmu
        'B5212DB685A2A0FCFBAE425738E478D12361710D' => '93.115.97.242:9030', // firstor
        'B6904ADD4C0D10CDA7179E051962350A69A63243' => '81.2.209.10:443', // torzabehlice
        'B83DC1558F0D34353BB992EF93AFEAFDB226A73E' => '193.11.114.46:9032', // mdfnet3
        'B86137AE9681701901C6720E55C16805B46BD8E3' => '81.7.11.186:1080', // BeastieJoy60
        'BC630CBBB518BE7E9F4E09712AB0269E9DC7D626' => '197.231.221.211:9030', // IPredator
        'BCEDF6C193AA687AE471B8A22EBF6BC57C2D285E' => '198.96.155.3:8080', // gurgle
        'BCEF908195805E03E92CCFE669C48738E556B9C5' => '128.199.55.207:9030', // EldritchReaper
        'BD552C165E2ED2887D3F1CCE9CFF155DDA2D86E6' => '213.141.138.174:9030', // Schakalium
        'BF735F669481EE1CCC348F0731551C933D1E2278' => '104.192.5.248:9030', // Freeway11
        'C2AAB088555850FC434E68943F551072042B85F1' => '31.185.104.21:80', // Digitalcourage3ip3
        'C37BC191AC389179674578C3E6944E925FE186C2' => '213.239.217.18:1338', // xzdsb
        'C414F28FD2BEC1553024299B31D4E726BEB8E788' => '188.138.112.60:1433', // zebra620
        'C5A53BCC174EF8FD0DCB223E4AA929FA557DEDB2' => '199.249.223.66:80', // Quintex17
        'CE47F0356D86CF0A1A2008D97623216D560FB0A8' => '85.25.213.211:465', // BeastieJoy61
        'CED527EAC230E7B56E5B363F839671829C3BA01B' => '51.15.13.245:9030', // 0x3d006
        'D30E9D4D639068611D6D96861C95C2099140B805' => '46.38.237.221:9030', // mine
        'D3E5EDDBE5159388704D6785BE51930AAFACEC6F' => '31.171.155.108:9030', // TorNodeAlbania
        'D64366987CB39F61AD21DBCF8142FA0577B92811' => '37.221.162.226:9030', // kasperskytor01
        'D760C5B436E42F93D77EF2D969157EEA14F9B39C' => '46.101.169.151:9030', // DanWin1210
        'D8B7A3A6542AA54D0946B9DC0257C53B6C376679' => '85.10.201.47:9030', // sif
        'DAA39FC00B196B353C2A271459C305C429AF09E4' => '193.35.52.53:9030', // Arne
        'DD823AFB415380A802DCAEB9461AE637604107FB' => '178.33.183.251:80', // grenouille
        'DD8BD7307017407FCC36F8D04A688F74A0774C02' => '171.25.193.20:80', // DFRI0
        'DED6892FF89DBD737BA689698A171B2392EB3E82' => '92.222.38.67:80', // ThorExit
        'E3DB2E354B883B59E8DC56B3E7A353DDFD457812' => '166.70.207.2:9030', // xmission
        'E480D577F58E782A5BC4FA6F49A6650E9389302F' => '199.249.223.43:80', // Quintex34
        'E589316576A399C511A9781A73DA4545640B479D' => '46.252.26.2:45212', // marlen
        'E781F4EC69671B3F1864AE2753E0890351506329' => '176.31.180.157:143', // armbrust
        'E81EF60A73B3809F8964F73766B01BAA0A171E20' => '212.47.244.38:8080', // Chimborazo
        'EFEACD781604EB80FBC025EDEDEA2D523AEAAA2F' => '217.182.75.181:9030', // Aerodynamik02
        'F4263275CF54A6836EE7BD527B1328836A6F06E1' => '37.187.102.108:80', // EvilMoe
        'F70B7C5CD72D74C7F9F2DC84FA9D20D51BA13610' => '46.28.109.231:9030', // wedostor
        'F93D8F37E35C390BCAD9F9069E13085B745EC216' => '185.96.180.29:80', // TykRelay06
        'FC9AC8EA0160D88BCCFDE066940D7DD9FA45495B' => '86.59.119.83:80', // ph3x
        'FE296180018833AF03A8EACD5894A614623D3F76' => '149.56.45.200:9030', // PiotrTorpotkinOne
    );

    protected $preferredServer;

    protected $connectTimeout = 5;
    protected $readTimeout = 30;
    protected $userAgent = 'dapphp/TorUtils 1.1.10';

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
