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
        // List updated 2020/04/29 (commit blob 793f65ce88803743aa34393c193356bef18cdc63)
        // NF = Not found in Tor Metrics (metrics.torproject.org) - The fingerprint was not found in Tor Metrics on the date given
        // TO = Timing out repeatedly on given date
        // RF = Read failed when trying to query for directory info on the date given.
        // Exit Relay = This is a busy exit relay so we should not bug it for directory info.
        // '001524DD403D729F08F7E5D77813EF12756CFA8D' => '185.13.39.197:80', // Neldoreth - NF 2020/04/29
        '025B66CEBC070FCB0519D206CF0CF4965C20C96E' => '185.100.85.61:80', // nibbana
        '0338F9F55111FE8E3570E7DE117EF3AF999CC1D7' => '185.225.17.3:80', // Nebuchadnezzar
        '0B85617241252517E8ECF2CFC7F4C1A32DCD153F' => '163.172.149.155:80', // niij02
        '0C039F35C2E40DCB71CD8A07E97C7FD7787D42D6' => '5.200.21.144:80', // libel
        //'113143469021882C3A4B82F084F8125B08EE471E' => '37.252.185.182:9030', // parasol - TO 2020/04/29
        '11DF0017A43AF1F08825CD5D973297F81AB00FF3' => '37.120.174.249:80', // gGDHjdcC6zAlM8k08lX
        '1211AC1BBB8A1AF7CBA86BCE8689AA3146B86423' => '95.85.8.226:80', // ccrelaycc
        '12AD30E5D25AA67F519780E2111E611A455FDC89' => '193.11.114.43:9030', // mdfnet1
        '12FD624EE73CEF37137C90D38B2406A66F68FAA2' => '37.157.195.87:8030', // thanatosCZ
        //'183005F78229D94EE51CE7795A42280070A48D0D' => '217.182.51.248:80', // Cosworth02 - NF 2020/04/29
        '185663B7C12777F052B2C2D23D7A239D8DA88A0F' => '171.25.193.25:80', // DFRI5
        '1938EBACBB1A7BFA888D9623C90061130E63BB3F' => '149.56.141.138:9030', // Aerodynamik04
        '1AE039EE0B11DB79E4B4B29CBA9F752864A0259E' => '81.7.14.253:9001', // Ichotolot60
        //'1CD17CB202063C51C7DAD3BACEF87ECE81C2350F' => '50.7.74.171:9030', // theia1 - TO 2020/04/29
        //'1F6ABD086F40B890A33C93CC4606EE68B31C9556' => '199.184.246.250:80', // dao - RF 2020/04/29
        '20462CBA5DA4C2D963567D17D0B7249718114A68' => '212.47.229.2:9030', // scaletor
        '204DFD2A2C6A0DC1FA0EACB495218E0B661704FD' => '77.247.181.164:80', // HaveHeart
        '230A8B2A8BA861210D9B4BA97745AEC217A94207' => '163.172.176.167:80', // niij01
        '2F0F32AB1E5B943CA7D062C03F18960C86E70D94' => '97.74.237.196:9030', // Minotaur
        '322C6E3A973BC10FC36DE3037AD27BC89F14723B' => '212.83.154.33:8080', // bauruine204
        '32EE911D968BE3E016ECA572BB1ED0A9EE43FC2F' => '109.105.109.162:52860', // ndnr1
        '330CD3DB6AD266DC70CDB512B036957D03D9BC59' => '185.100.84.212:80', // TeamTardis
        '361D33C96D0F161275EE67E2C91EE10B276E778B' => '37.157.255.35:9030', // cxx4freedom
        //'375DCBB2DBD94E5263BC0C015F0C9E756669617E' => '64.79.152.132:80', // ebola - RF 2020/04/29
        '39F91959416763AFD34DBEEC05474411B964B2DC' => '213.183.60.21:9030', // angeltest11
        //'3AFDAAD91A15B4C6A7686A53AA8627CA871FF491' => '50.7.74.174:9030', // theia7 - RF 2020/04/29
        //'3CA0D15567024D2E0B557DC0CF3E962B37999A79' => '199.249.230.83:80', // QuintexAirVPN30 - Exit relay
        '3CB4193EF4E239FCEDC4DC43468E0B0D6B67ACC3' => '51.38.65.160:9030', // rofltor10
        '3E53D3979DB07EFD736661C934A1DED14127B684' => '217.79.179.177:9030', // Unnamed
        '3F092986E9B87D3FDA09B71FA3A602378285C77A' => '66.111.2.16:9030', // NYCBUG1
        '4061C553CA88021B8302F0814365070AAE617270' => '185.100.85.101:9030', // TorExitRomania
        '4623A9EC53BFD83155929E56D6F7B55B5E718C24' => '163.172.157.213:8080', // Cotopaxi
        '465D17C6FC297E3857B5C6F152006A1E212944EA' => '195.123.245.141:9030', // angeltest14
        //'46791D156C9B6C255C2665D4D8393EC7DBAA7798' => '31.31.78.49:80', // KrigHaBandolo - NF 2020/04/29
        '484A10BA2B8D48A5F0216674C8DD50EF27BC32F3' => '193.70.43.76:9030', // Aerodynamik03
        //'489D94333DF66D57FFE34D9D59CC2D97E2CB0053' => '37.187.102.186:9030', // txtfileTorNode65536 - NF 2020/04/29
        '4EB55679FA91363B97372554F8DC7C63F4E5B101' => '81.7.13.84:80', // torpidsDEisppro
        //'4F0DB7E687FC7C0AE55C8F243DA8B0EB27FBF1F2' => '108.53.208.157:80', // Binnacle - RF 2020/04/29
        '509EAB4C5D10C9A9A24B4EA0CE402C047A2D64E6' => '5.9.158.75:9030', // zwiebeltoralf2
        '51E1CF613FD6F9F11FE24743C91D6F9981807D82' => '81.7.16.182:80', // torpidsDEisppro3
        //'547DA56F6B88B6C596B3E3086803CDA4F0EF8F21' => '192.160.102.166:80', // chaucer - RF 2020/04/29
        '557ACEC850F54EEE65839F83CACE2B0825BE811E' => '192.160.102.170:80', // ogopogo
        //'5BF17163CBE73D8CD9FDBE030C944EA05707DA93' => '50.7.74.170:80', // theia8 - RF 2020/04/29
        '5E56738E7F97AA81DEEF59AF28494293DFBFCCDF' => '172.98.193.43:80', // Backplane
        '616081EC829593AF4232550DE6FFAA1D75B37A90' => '95.128.43.164:80', // AquaRayTerminus
        '68F175CCABE727AA2D2309BCD8789499CEE36ED7' => '163.172.139.104:8080', // Pichincha
        '6A7551EEE18F78A9813096E82BF84F740D32B911' => '94.130.186.5:80', // TorMachine
        '6EF897645B79B6CB35E853B32506375014DE3621' => '80.127.137.19:80', // d6relay
        '7088D485934E8A403B81531F8C90BDC75FA43C98' => '37.139.8.104:9030', // Basil
        '70C55A114C0EF3DC5784A4FAEE64388434A3398F' => '188.138.88.42:80', // torpidsFRplusserver
        '72B2B12A3F60408BDBC98C6DF53988D3A0B3F0EE' => '85.235.250.88:80', // TykRelay01
        '742C45F2D9004AADE0077E528A4418A6A81BC2BA' => '178.17.170.23:9030', // TorExitMoldova2
        //'745369332749021C6FAF100D327BC3BF1DF4707B' => '50.7.74.173:9030', // theia5 - RF 2020/04/29
        '77131D7E2EC1CA9B8D737502256DA9103599CE51' => '77.247.181.166:80', // CriticalMass
        '775B0FAFDE71AADC23FFC8782B7BEB1D5A92733E' => '5.196.23.64:9030', // Aerodynamik01
        //'79509683AB4C8DDAF90A120C69A4179C6CD5A387' => '185.244.193.141:9030', // DerDickeReloaded - RF 2020/04/29
        '7BB70F8585DFC27E75D692970C0EEB0F22983A63' => '51.254.136.195:80', // torproxy02
        '7BFB908A3AA5B491DA4CA72CCBEE0E1F2A939B55' => '77.247.181.162:80', // sofia
        //'7E281CD2C315C4F7A84BC7C8721C3BC974DDBFA3' => '185.220.101.48:10048', // niftyporcupine - RF 2020/04/29
        '80AAF8D5956A43C197104CEF2550CD42D165C6FB' => '193.11.114.45:9031', // mdfnet2
        '8101421BEFCCF4C271D5483C5AABCAAD245BBB9D' => '51.254.96.208:9030', // rofltor01
        '81B75D534F91BFB7C57AB67DA10BCEF622582AE8' => '192.42.116.16:80', // hviv104
        //'823AA81E277F366505545522CEDC2F529CE4DC3F' => '192.160.102.164:80', // snowfall - RF 2020/04/29
        '844AE9CAD04325E955E2BE1521563B79FE7094B7' => '192.87.28.82:9030', // Smeerboel
        //'8456DFA94161CDD99E480C2A2992C366C6564410' => '62.210.254.132:80', // turingmachine - NF 2020/04/29
        //'855BC2DABE24C861CD887DB9B2E950424B49FC34' => '85.230.178.139:9030', // Logforme  - TO 2020/04/29
        '85A885433E50B1874F11CEC9BE98451E24660976' => '178.254.7.88:8080', // wr3ck3d0ni0n01
        '86C281AD135058238D7A337D546C902BE8505DDE' => '185.96.88.29:80', // TykRelay05
        '8C00FA7369A7A308F6A137600F0FA07990D9D451' => '163.172.194.53:9030', // GrmmlLitavis
        '8D79F73DCD91FC4F5017422FAC70074D6DB8DD81' => '5.189.169.190:8030', // thanatosDE
        //'8FA37B93397015B2BC5A525C908485260BE9F422' => '81.7.11.96:9030', // Doedel22 - TO 2020/04/29
        '90A5D1355C4B5840E950EB61E673863A6AE3ACA1' => '54.37.139.118:9030', // rofltor09
        //'91D23D8A539B83D2FB56AA67ECD4D75CC093AC55' => '37.187.20.59:80', // torpidsFRovh - NF 2020/04/29
        //'91E4015E1F82DAF0121D62267E54A1F661AB6DC7' => '173.255.245.116:9030', // IWorshipHisShadow - RF 2020/04/29
        '924B24AFA7F075D059E8EEB284CC400B33D3D036' => '96.253.78.108:80', // NSDFreedom
        '9288B75B5FF8861EFF32A6BE8825CC38A4F9F8C2' => '92.38.163.21:9030', // angeltest9
        //'935F589545B8A271A722E330445BB99F67DBB058' => '163.172.53.84:80', // Multivac0 - NF 2020/04/29
        '94C4B7B8C50C86A92B6A20107539EE2678CF9A28' => '204.8.156.142:80', // BostonUCompSci
        '9772EFB535397C942C3AB8804FB35CFFAD012438' => '37.153.1.10:9030', // smallsweatnode
        '99E246DB480B313A3012BC3363093CC26CD209C7' => '173.212.254.192:31336', // ViDiSrv
        //'9B31F1F1C1554F9FFB3455911F82E818EF7C7883' => '185.100.86.128:9030', // TorExitFinland
        '9B816A5B3EB20B8E4E9B9D1FBA299BD3F40F0320' => '185.220.101.16:20016', // niftypygmyjerboa
        '9C900A7F6F5DD034CFFD192DAEC9CCAA813DB022' => '86.105.212.130:9030', // firstor2
        '9EAD5B2D3DBD96DBC80DCE423B0C345E920A758D' => '31.185.104.19:80', // Digitalcourage3ip1
        '9F7D6E6420183C2B76D3CE99624EBC98A21A967E' => '46.28.110.244:80', // Nivrim
        'A0F06C2FADF88D3A39AA3072B406F09D7095AC9E' => '46.165.230.5:80', // Dhalgren
        //'A2E6BB5C391CD46B38C55B4329C35304540771F1' => '81.7.3.67:993', // BeastieJoy62 - Dirport = none
        'A53C46F5B157DD83366D45A8E99A244934A14C46' => '128.31.0.13:80', // csailmitexit
        'A86EC24F5B8B964F67AC7C27CE92842025983274' => '185.246.152.22:9030', // angeltest19
        'A9406A006D6E7B5DA30F2C6D4E42A338B5E340B2' => '163.172.149.122:80', // niij03
        'AC2BEDD0BAC72838EA7E6F113F856C4E8018ACDB' => '176.10.107.180:9030', // schokomilch
        'ACDD9E85A05B127BA010466C13C8C47212E8A38F' => '185.129.62.62:9030', // kramse
        'ADB2C26629643DBB9F8FE0096E7D16F9414B4F8D' => '31.185.104.20:80', // Digitalcourage3ip2
        'AEDAC7081AE14B8D241ECF0FF17A2858AB4383D0' => '45.79.108.130:9030', // linss
        //'B0553175AADB0501E5A61FC61CEA3970BE130FF2' => '5.9.147.226:9030', // zwiubel - RF 2020/04/29
        'B06F093A3D4DFAD3E923F4F28A74901BD4F74EB1' => '178.17.174.14:9030', // TorExitMoldova
        'B143D439B72D239A419F8DCE07B8A8EB1B486FA7' => '212.129.62.232:80', // wardsback
        //'B2197C23A4FF5D1C49EE45BA7688BA8BCCD89A0B' => '199.249.230.64:80', // Quintex41 - RF 2020/04/29
        'B291D30517D23299AD7CEE3E60DFE60D0E3A4664' => '136.243.214.137:80', // TorKIT
        'B4CAFD9CBFB34EC5DAAC146920DC7DFAFE91EA20' => '212.47.233.86:9030', // netimanmu
        'B5212DB685A2A0FCFBAE425738E478D12361710D' => '93.115.97.242:9030', // firstor
        'B57A87009FA838471FB2227DDE68165AB2A2FCC4' => '51.38.134.104:9030', // angeltest5
        'B83DC1558F0D34353BB992EF93AFEAFDB226A73E' => '193.11.114.46:9032', // mdfnet3
        'B84F248233FEA90CAD439F292556A3139F6E1B82' => '85.248.227.164:444', // tollana
        //'B86137AE9681701901C6720E55C16805B46BD8E3' => '81.7.11.186:1080', // BeastieJoy60 - Dirport = none
        'BB60F5BA113A0B8B44B7B37DE3567FE561E92F78' => '51.15.179.153:110', // Casper04
        'BCEDF6C193AA687AE471B8A22EBF6BC57C2D285E' => '198.96.155.3:8080', // gurgle
        //'BCEF908195805E03E92CCFE669C48738E556B9C5' => '128.199.55.207:9030', // EldritchReaper - RF 2020/04/29
        'BD552C165E2ED2887D3F1CCE9CFF155DDA2D86E6' => '213.141.138.174:9030', // Schakalium
        'BF0FB582E37F738CD33C3651125F2772705BB8E8' => '148.251.190.229:9030', // quadhead
        'BF735F669481EE1CCC348F0731551C933D1E2278' => '212.47.233.250:9030', // FreewaySca
        //'C0192FF43E777250084175F4E59AC1BA2290CE38' => '192.160.102.169:80', // manipogo - RF 2020/04/29
        //'C0C4F339046EB824999F711D178472FDF53BE7F5' => '132.248.241.5:9130', // toritounam2 - RF 2020/04/29
        'C2AAB088555850FC434E68943F551072042B85F1' => '31.185.104.21:80', // Digitalcourage3ip3
        //'C36A434DB54C66E1A97A5653858CE36024352C4D' => '50.7.74.170:9030', // theia9 - RF 2020/04/29
        'C793AB88565DDD3C9E4C6F15CCB9D8C7EF964CE9' => '85.248.227.163:443', // ori
        //'C90CA3B7FE01A146B8268D56977DC4A2C024B9EA' => '192.160.102.165:80', // cowcat - RF 2020/04/29
        'CBD0D1BD110EC52963082D839AC6A89D0AE243E7' => '176.31.103.150:9030', // UV74S7mjxRcYVrGsAMw
        //'D15AFF44BE641368B958A32FB6B071AC2136B8B1' => '51.254.147.57:80', // Cosworth01 - NF 2020/04/29
        'D1AFBF3117B308B6D1A7AA762B1315FD86A6B8AF' => '50.7.74.172:80', // theia2
        //'D379A1CB8285748FFF64AE94296CA89878F25B22' => '62.141.38.69:9030', // angeltest3 - NF 2020/04/29
        'D405FCCF06ADEDF898DF2F29C9348DCB623031BA' => '5.45.111.149:80', // gGDHjdcC6zAlM8k08lY
        'D50101A2ABD09DC245F7E96C0818D003CDD62351' => '50.7.74.174:80', // theia6
        'D5039E1EBFD96D9A3F9846BF99EC9F75EDDE902A' => '37.187.115.157:9030', // Janky328891
        //'D8B7A3A6542AA54D0946B9DC0257C53B6C376679' => '85.10.201.47:9030', // sif - NF 2020/04/29
        'DAA39FC00B196B353C2A271459C305C429AF09E4' => '193.35.52.53:9030', // Arne
        'DB2682153AC0CCAECD2BD1E9EBE99C6815807A1E' => '54.36.237.163:80', // GermanCraft2
        'DC163DDEF4B6F0C6BC226F9F6656A5A30C5C5686' => '176.158.236.102:9030', // Underworld
        'DD823AFB415380A802DCAEB9461AE637604107FB' => '178.33.183.251:80', // grenouille
        'DD8BD7307017407FCC36F8D04A688F74A0774C02' => '171.25.193.20:80', // DFRI0
        'DED6892FF89DBD737BA689698A171B2392EB3E82' => '92.222.38.67:80', // ThorExit
        //'E41B16F7DDF52EBB1DB4268AB2FE340B37AD8904' => '166.70.207.2:9130', // xmission1 - RF 2020/04/29
        'E51620B90DCB310138ED89EDEDD0A5C361AAE24E' => '185.100.86.182:9030', // NormalCitizen
        //'E81EF60A73B3809F8964F73766B01BAA0A171E20' => '212.47.244.38:8080', // Chimborazo - NF 2020/04/29
        'E8D114B3C78D8E6E7FEB1004650DD632C2143C9E' => '185.4.132.148:80', // libreonion1
        'EBE718E1A49EE229071702964F8DB1F318075FF8' => '131.188.40.188:1443', // fluxe4
        'ED2338CAC2711B3E331392E1ED2831219B794024' => '192.87.28.28:9030', // SEC6xFreeBSD64
        'EE4AF632058F0734C1426B1AD689F47445CA2056' => '37.252.187.111:9030', // angeltest7
        'EFEACD781604EB80FBC025EDEDEA2D523AEAAA2F' => '217.182.75.181:9030', // Aerodynamik02
        'F10BDE279AE71515DDCCCC61DC19AC8765F8A3CC' => '193.70.112.165:80', // ParkBenchInd001
        'F4263275CF54A6836EE7BD527B1328836A6F06E1' => '37.187.102.108:80', // EvilMoe
        'F4C0EDAA0BF0F7EC138746F8FEF1CE26C7860265' => '5.199.142.236:9030', // tornodenumber9004
        'F6A358DD367B3282D6EF5824C9D45E1A19C7E815' => '192.160.102.168:80', // prawksi
        'F8D27B163B9247B232A2EEE68DD8B698695C28DE' => '78.47.18.110:443', // fluxe3
        'F93D8F37E35C390BCAD9F9069E13085B745EC216' => '185.96.180.29:80', // TykRelay06
        'FE296180018833AF03A8EACD5894A614623D3F76' => '149.56.45.200:9030', // PyotrTorpotkinOne
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
