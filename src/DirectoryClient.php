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
        '7BE683E65D48141321C5ED92F075C55364AC7123' => '193.23.244.244:80', // dannenberg
        '7EA6EAD6FD83083C538F44038BBFA077587DD755' => '194.109.206.212:80', // dizum
        'BA44A889E64B93FAA2B114E02C2A279A8555C533' => '66.111.2.131:9030', // Serge
        'CF6D0AAFB385BE71B8E111FC5CFF4B47923733BC' => '154.35.175.225:80', // Faravahar
        'F2044413DAC2E02E3D6BCF4735A19BCA1DE97281' => '131.188.40.189:80', // gabelmoo
        '74A910646BCEEFBCD2E874FC1DC997430F968145' => '199.58.81.140:80', // longclaw
        'BD6A829255CB08E66FBE7D3748363586E46B3810' => '171.25.193.9:443', // maatuska
        '9695DFC35FFEB861329B9F1AB04C46397020CE31' => '128.31.0.39:9131', // moria1
        '847B1F850344D7876491A54892F904934E4EB85D' => '86.59.21.38:80', // tor26
        '24E2F139121D4394C54B5BCC368B3B411857C413' => '204.13.164.118:80', // bastet
    );

    /**
     * @var array Array of directory fallbacks from https://gitweb.torproject.org/tor.git/tree/src/app/config/fallback_dirs.inc
     */
    protected $directoryFallbacks = array(
        // List updated 2019/05/25 (commit blob 9f60f309f88a7bcfccd3c56b76e583a68fe431c5)
        // NIA = Not In Atlas (atlas.torproject.org) - The fingerprint was not found in Atlas on the date given
        // RF = Read failed when trying to query for directory info on the date given.
        // Exit Relay = This is a busy exit relay so we should not bug it for directory info.
        '0111BA9B604669E636FFD5B503F382A4B7AD6E80' => '176.10.104.240:80', // DigiGesTor1e1
        //'01A9258A46E97FF8B2CAC7910577862C14F2C524' => '193.171.202.146:9030', // ins0 (NIA - 2019/05/25)
        '0B85617241252517E8ECF2CFC7F4C1A32DCD153F' => '163.172.149.155:80', // niij02
        '0C039F35C2E40DCB71CD8A07E97C7FD7787D42D6' => '5.200.21.144:80', // libel
        //'0C2C599AFCB26F5CFC2C7592435924C1D63D9484' => '5.196.88.122:9030', // ATo (NIA - 2019/05/25)
        '0E8C0C8315B66DB5F703804B3889A1DD66C67CE0' => '185.100.86.100:80', // saveyourprivacyex1
        '113143469021882C3A4B82F084F8125B08EE471E' => '37.252.185.182:9030', // parasol
        '11DF0017A43AF1F08825CD5D973297F81AB00FF3' => '37.120.174.249:80', // gGDHjdcC6zAlM8k08lX
        '12AD30E5D25AA67F519780E2111E611A455FDC89' => '193.11.114.43:9030', // mdfnet1
        //'136F9299A5009A4E0E96494E723BDB556FB0A26B' => '193.234.15.59:80', // bakunin2 (NIA - 2019/05/25)
        //'14419131033443AE6E21DA82B0D307F7CAE42BDB' => '144.76.14.145:110', // PedicaboMundi (NIA - 2019/05/25)
        //'14877C6384A9E793F422C8D1DDA447CACA4F7C4B' => '185.220.101.9:10009', // niftywoodmouse (NIA - 2019/05/25)
        //'1576BE143D8727745BB2BCDDF183291B3C3EFEFC' => '54.37.138.138:8080', // anotherone (NIA - 2019/05/25)
        '15BE17C99FACE24470D40AF782D6A9C692AB36D6' => '51.15.78.0:9030', // rofltor07
        '185F2A57B0C4620582602761097D17DB81654F70' => '204.11.50.131:9030', // BoingBoing
        '1938EBACBB1A7BFA888D9623C90061130E63BB3F' => '149.56.141.138:9030', // Aerodynamik04
        '1AE039EE0B11DB79E4B4B29CBA9F752864A0259E' => '81.7.14.253:9001', // Ichotolot60
        '1C90D3AEADFF3BCD079810632C8B85637924A58E' => '163.172.53.84:143', // Multivac
        '1F6ABD086F40B890A33C93CC4606EE68B31C9556' => '199.184.246.250:80', // dao
        '20462CBA5DA4C2D963567D17D0B7249718114A68' => '212.47.229.2:9030', // scaletor
        '230A8B2A8BA861210D9B4BA97745AEC217A94207' => '163.172.176.167:80', // niij01
        //'24E91955D969AEA1D80413C64FE106FAE7FD2EA9' => '185.220.101.8:10008', // niftymouse (NIA - 2019/05/25)
        '2BA2C8E96B2590E1072AECE2BDB5C48921BF8510' => '138.201.250.33:9012', // storm
        //'2CDCFED0142B28B002E89D305CBA2E26063FADE2' => '193.234.15.56:80', // jaures (NIA - 2019/05/25)
        '2F0F32AB1E5B943CA7D062C03F18960C86E70D94' => '97.74.237.196:9030', // Minotaur
        '311A4533F7A2415F42346A6C8FA77E6FD279594C' => '94.230.208.147:8080', // DigiGesTor3e2
        '322C6E3A973BC10FC36DE3037AD27BC89F14723B' => '212.83.154.33:8080', // bauruine204
        '330CD3DB6AD266DC70CDB512B036957D03D9BC59' => '185.100.84.212:80', // TeamTardis
        //'360CBA08D1E24F513162047BDB54A1015E531534' => '54.37.17.235:9030', // Aerodynamik06 (NIA - 2019/05/25)
        '361D33C96D0F161275EE67E2C91EE10B276E778B' => '37.157.255.35:9030', // cxx4freedom
        //'36B9E7AC1E36B62A9D6F330ABEB6012BA7F0D400' => '37.187.22.87:9030', // kimsufi321 (NIA - 2019/05/25)
        '375DCBB2DBD94E5263BC0C015F0C9E756669617E' => '64.79.152.132:80', // ebola
        //'387B065A38E4DAA16D9D41C2964ECBC4B31D30FF' => '62.210.92.11:9130', // redjohn1 (NIA - 2019/05/25)
        //'39F096961ED2576975C866D450373A9913AFDC92' => '198.50.191.95:80', // thomas (NIA - 2019/05/25)
        '3F092986E9B87D3FDA09B71FA3A602378285C77A' => '66.111.2.16:9030', // NYCBUG1
        '4061C553CA88021B8302F0814365070AAE617270' => '185.100.85.101:9030', // TorExitRomania
        '41A3C16269C7B63DB6EB741DBDDB4E1F586B1592' => '195.191.81.7:9030', // rofltor02
        //'41C59606AFE1D1AA6EC6EF6719690B856F0B6587' => '178.17.170.156:9030', // TorExitMoldova2 (NIA - 2019/05/25)
        //'45362E8ECD651CCAC521156FFBD2FF7F27FA8E88' => '81.7.10.251:80', // torpidsDEisppro2 (NIA - 2019/05/25)
        '4623A9EC53BFD83155929E56D6F7B55B5E718C24' => '163.172.157.213:8080', // Cotopaxi
        '4661DE96D3F8E923994B05218F23760C8D7935A4' => '132.248.241.5:9030', // toritounam
        '46791D156C9B6C255C2665D4D8393EC7DBAA7798' => '31.31.78.49:80', // KrigHaBandolo
        '47C42E2094EE482E7C9B586B10BABFB67557030B' => '185.220.101.34:10034', // niftysugarglider
        '484A10BA2B8D48A5F0216674C8DD50EF27BC32F3' => '193.70.43.76:9030', // Aerodynamik03
        //'4CC9CC9195EC38645B699A33307058624F660CCF' => '51.254.101.242:9002', // devsum (NIA - 2019/05/25)
        '4EB55679FA91363B97372554F8DC7C63F4E5B101' => '81.7.13.84:80', // torpidsDEisppro
        '50586E25BE067FD1F739998550EDDCB1A14CA5B2' => '212.51.134.123:9030', // Jans
        '51E1CF613FD6F9F11FE24743C91D6F9981807D82' => '81.7.16.182:80', // torpidsDEisppro3
        '52BFADA8BEAA01BA46C8F767F83C18E2FE50C1B9' => '85.25.159.65:995', // BeastieJoy63
        '547DA56F6B88B6C596B3E3086803CDA4F0EF8F21' => '192.160.102.166:80', // chaucer
        '557ACEC850F54EEE65839F83CACE2B0825BE811E' => '192.160.102.170:80', // ogopogo
        //'587E0A9552E4274B251F29B5B2673D38442EE4BF' => '95.130.12.119:80', // Nuath (NIA - 2019/05/25)
        '58ED9C9C35E433EE58764D62892B4FFD518A3CD0' => '185.21.100.50:9030', // SamAAdams2
        //'5CF8AFA5E4B0BB88942A44A3F3AAE08C3BDFD60B' => '193.234.15.62:80', // jaures4 (NIA - 2019/05/25)
        '5E56738E7F97AA81DEEF59AF28494293DFBFCCDF' => '172.98.193.43:80', // Backplane
        '609E598FB6A00BCF7872906B602B705B64541C50' => '185.220.101.28:10028', // niftychipmunk
        '68F175CCABE727AA2D2309BCD8789499CEE36ED7' => '163.172.139.104:8080', // Pichincha
        '6EF897645B79B6CB35E853B32506375014DE3621' => '80.127.137.19:80', // d6relay
        '7088D485934E8A403B81531F8C90BDC75FA43C98' => '37.139.8.104:9030', // Basil
        '70C55A114C0EF3DC5784A4FAEE64388434A3398F' => '188.138.88.42:80', // torpidsFRplusserver
        '71CFDEB4D9E00CCC3E31EC4E8A29E109BBC1FB36' => '185.220.101.30:10030', // niftypedetidae
        '72B2B12A3F60408BDBC98C6DF53988D3A0B3F0EE' => '85.235.250.88:80', // TykRelay01
        '7600680249A22080ECC6173FBBF64D6FCF330A61' => '81.7.14.31:9001', // Ichotolot62
        '775B0FAFDE71AADC23FFC8782B7BEB1D5A92733E' => '5.196.23.64:9030', // Aerodynamik01
        '7BB70F8585DFC27E75D692970C0EEB0F22983A63' => '51.254.136.195:80', // torproxy02
        //'7D05A38E39FC5D29AFE6BE487B9B4DC9E635D09E' => '185.100.84.82:80', // saveyourprivacyexit (NIA - 2019/05/25)
        '80AAF8D5956A43C197104CEF2550CD42D165C6FB' => '193.11.114.45:9031', // mdfnet2
        '8101421BEFCCF4C271D5483C5AABCAAD245BBB9D' => '51.254.96.208:9030', // rofltor01
        '81AFA888F8F8F4A024AB58ECA0ADDEBB93FF01DA' => '217.12.199.190:80', // torpidsUAitlas
        '81B75D534F91BFB7C57AB67DA10BCEF622582AE8' => '192.42.116.16:80', // hviv104
        '823AA81E277F366505545522CEDC2F529CE4DC3F' => '192.160.102.164:80', // snowfall
        '844AE9CAD04325E955E2BE1521563B79FE7094B7' => '192.87.28.82:9030', // Smeerboel
        '8456DFA94161CDD99E480C2A2992C366C6564410' => '62.210.254.132:80', // turingmachine
        '86C281AD135058238D7A337D546C902BE8505DDE' => '185.96.88.29:80', // TykRelay05
        '8844D87E9B038BE3270938F05AF797E1D3C74C0F' => '93.180.156.84:9030', // BARACUDA
        //'8B6556601612F1E2AFCE2A12FFFAF8482A76DD1F' => '51.15.205.214:9030', // titania1 (NIA - 2019/05/25)
        '8C00FA7369A7A308F6A137600F0FA07990D9D451' => '163.172.194.53:9030', // GrmmlLitavis
        '8FA37B93397015B2BC5A525C908485260BE9F422' => '81.7.11.96:9030', // Doedel22
        '91D23D8A539B83D2FB56AA67ECD4D75CC093AC55' => '37.187.20.59:80', // torpidsFRovh
        '9231DF741915AA1630031A93026D88726877E93A' => '51.255.41.65:9030', // PrisnCellRelayFR1
        //'92412EA1B9AA887D462B51D816777002F4D58907' => '54.37.73.111:9030', // Aerodynamik05 (NIA - 2019/05/25)
        '924B24AFA7F075D059E8EEB284CC400B33D3D036' => '96.253.78.108:80', // NSDFreedom
        //'92CFD9565B24646CAC2D172D3DB503D69E777B8A' => '193.234.15.57:80', // bakunin (NIA - 2019/05/25)
        '94C4B7B8C50C86A92B6A20107539EE2678CF9A28' => '204.8.156.142:80', // BostonUCompSci
        '9772EFB535397C942C3AB8804FB35CFFAD012438' => '37.153.1.10:9030', // smallsweatnode
        '99E246DB480B313A3012BC3363093CC26CD209C7' => '173.212.254.192:31336', // ViDiSrv
        '9A0D54D3A6D2E0767596BF1515E6162A75B3293F' => '91.229.20.27:9030', // gordonkeybag
        '9A68B85A02318F4E7E87F2828039FBD5D75B0142' => '66.111.2.20:9030', // NYCBUG0
        '9B31F1F1C1554F9FFB3455911F82E818EF7C7883' => '185.100.86.128:9030', // TorExitFinland
        '9C900A7F6F5DD034CFFD192DAEC9CCAA813DB022' => '86.105.212.130:9030', // firstor2
        '9EAD5B2D3DBD96DBC80DCE423B0C345E920A758D' => '31.185.104.19:80', // Digitalcourage3ip1
        '9F7D6E6420183C2B76D3CE99624EBC98A21A967E' => '46.28.110.244:80', // Nivrim
        'A0F06C2FADF88D3A39AA3072B406F09D7095AC9E' => '46.165.230.5:80', // Dhalgren
        'A10C4F666D27364036B562823E5830BC448E046A' => '171.25.193.77:80', // DFRI1
        //'A2A6616723B511D8E068BB71705191763191F6B2' => '87.118.122.120:80', // otheontelth (NIA - 2019/05/25)
        'A2E6BB5C391CD46B38C55B4329C35304540771F1' => '81.7.3.67:993', // BeastieJoy62
        'A478E421F83194C114F41E94F95999672AED51FE' => '171.25.193.78:80', // DFRI4
        //'A4C98CEA3F34E05299417E9F885A642C88EF6029' => '193.234.15.58:80', // jaures2 (NIA - 2019/05/25)
        //'A53C46F5B157DD83366D45A8E99A244934A14C46' => '128.31.0.13:80', // csailmitexit (NIA - 2019/05/25)
        //'AA0D167E03E298F9A8CD50F448B81FBD7FA80D56' => '94.142.242.84:80', // rejozenger (NIA - 2019/05/25)
        'AC66FFA4AB35A59EBBF5BF4C70008BF24D8A7A5C' => '195.154.164.243:80', // torpidsFRonline3
        'ACD889D86E02EDDAB1AFD81F598C0936238DC6D0' => '86.59.119.88:80', // ph3x
        'ACDD9E85A05B127BA010466C13C8C47212E8A38F' => '185.129.62.62:9030', // kramse
        'AD19490C7DBB26D3A68EFC824F67E69B0A96E601' => '188.40.128.246:9030', // sputnik
        'ADB2C26629643DBB9F8FE0096E7D16F9414B4F8D' => '31.185.104.20:80', // Digitalcourage3ip2
        'AEDAC7081AE14B8D241ECF0FF17A2858AB4383D0' => '45.79.108.130:9030', // linss
        'B0553175AADB0501E5A61FC61CEA3970BE130FF2' => '5.9.147.226:9030', // zwiubel
        'B06F093A3D4DFAD3E923F4F28A74901BD4F74EB1' => '178.17.174.14:9030', // TorExitMoldova
        'B143D439B72D239A419F8DCE07B8A8EB1B486FA7' => '212.129.62.232:80', // wardsback
        'B291D30517D23299AD7CEE3E60DFE60D0E3A4664' => '136.243.214.137:80', // TorKIT
        //'B44FBE5366AD98B46D829754FA4AC599BAE41A6A' => '193.234.15.60:80', // jaures3 (NIA - 2019/05/25)
        'B5212DB685A2A0FCFBAE425738E478D12361710D' => '93.115.97.242:9030', // firstor
        //'B6904ADD4C0D10CDA7179E051962350A69A63243' => '81.2.209.10:443', // torzabehlice (NIA - 2019/05/25)
        'B771AA877687F88E6F1CA5354756DF6C8A7B6B24' => '185.220.101.32:10032', // niftypika
        'B83DC1558F0D34353BB992EF93AFEAFDB226A73E' => '193.11.114.46:9032', // mdfnet3
        'B84F248233FEA90CAD439F292556A3139F6E1B82' => '85.248.227.164:444', // tollana
        'B86137AE9681701901C6720E55C16805B46BD8E3' => '81.7.11.186:1080', // BeastieJoy60
        'BD552C165E2ED2887D3F1CCE9CFF155DDA2D86E6' => '213.141.138.174:9030', // Schakalium
        'BF0FB582E37F738CD33C3651125F2772705BB8E8' => '148.251.190.229:9030', // quadhead
        //'BF735F669481EE1CCC348F0731551C933D1E2278' => '104.192.5.248:9030', // Freeway1a1 (NIA - 2019/05/25)
        'C0192FF43E777250084175F4E59AC1BA2290CE38' => '192.160.102.169:80', // manipogo
        'C08DE49658E5B3CFC6F2A952B453C4B608C9A16A' => '185.220.101.6:10006', // niftyvolcanorabbit
        'C2AAB088555850FC434E68943F551072042B85F1' => '31.185.104.21:80', // Digitalcourage3ip3
        //'C37BC191AC389179674578C3E6944E925FE186C2' => '213.239.217.18:1338', // xzdsb (NIA - 2019/05/25)
        'C414F28FD2BEC1553024299B31D4E726BEB8E788' => '188.138.112.60:1433', // zebra620
        //'C4AEA05CF380BAD2230F193E083B8869B4A29937' => '193.234.15.55:80', // bakunin4 (NIA - 2019/05/25)
        'C793AB88565DDD3C9E4C6F15CCB9D8C7EF964CE9' => '85.248.227.163:443', // ori
        'C90CA3B7FE01A146B8268D56977DC4A2C024B9EA' => '192.160.102.165:80', // cowcat
        'CBD0D1BD110EC52963082D839AC6A89D0AE243E7' => '176.31.103.150:9030', // UV74S7mjxRcYVrGsAMw
        'CE47F0356D86CF0A1A2008D97623216D560FB0A8' => '85.25.213.211:465', // BeastieJoy61
        'D30E9D4D639068611D6D96861C95C2099140B805' => '46.38.237.221:9030', // mine
        'D405FCCF06ADEDF898DF2F29C9348DCB623031BA' => '5.45.111.149:80', // gGDHjdcC6zAlM8k08lY
        'D5039E1EBFD96D9A3F9846BF99EC9F75EDDE902A' => '37.187.115.157:9030', // Janky328891
        'D6BA940D3255AB40DC5EE5B0B285FA143E1F9865' => '217.182.51.248:80', // Cosworth02
        //'D71B1CA1C9DC7E8CA64158E106AD770A21160FEE' => '185.34.33.2:9265', // lqdn (NIA - 2019/05/25)
        'D8B7A3A6542AA54D0946B9DC0257C53B6C376679' => '85.10.201.47:9030', // sif
        'DAA39FC00B196B353C2A271459C305C429AF09E4' => '193.35.52.53:9030', // Arne
        'DB2682153AC0CCAECD2BD1E9EBE99C6815807A1E' => '54.36.237.163:80', // GermanCraft2
        'DD823AFB415380A802DCAEB9461AE637604107FB' => '178.33.183.251:80', // grenouille
        'DD8BD7307017407FCC36F8D04A688F74A0774C02' => '171.25.193.20:80', // DFRI0
        //'DDBB2A38252ADDA53E4492DDF982CA6CC6E10EC0' => '83.212.99.68:80', // zouzounella (NIA - 2019/05/25)
        'DED6892FF89DBD737BA689698A171B2392EB3E82' => '92.222.38.67:80', // ThorExit
        'E51620B90DCB310138ED89EDEDD0A5C361AAE24E' => '185.100.86.182:9030', // NormalCitizen
        'E81EF60A73B3809F8964F73766B01BAA0A171E20' => '212.47.244.38:8080', // Chimborazo
        'EB80A8D52F07238B576C42CEAB98ADD084EE075E' => '51.254.147.57:80', // Cosworth01
        'ED2338CAC2711B3E331392E1ED2831219B794024' => '192.87.28.28:9030', // SEC6xFreeBSD64
        'EFEACD781604EB80FBC025EDEDEA2D523AEAAA2F' => '217.182.75.181:9030', // Aerodynamik02
        'F10BDE279AE71515DDCCCC61DC19AC8765F8A3CC' => '193.70.112.165:80', // ParkBenchInd001
        'F2DFE5FA1E4CF54F8E761A6D304B9B4EC69BDAE8' => '129.13.131.140:80', // AlleKochenKaffee
        'F4263275CF54A6836EE7BD527B1328836A6F06E1' => '37.187.102.108:80', // EvilMoe
        'F6A358DD367B3282D6EF5824C9D45E1A19C7E815' => '192.160.102.168:80', // prawksi
        'F741E5124CB12700DA946B78C9B2DD175D6CD2A1' => '163.172.154.162:9030', // rofltor06
        'F8D27B163B9247B232A2EEE68DD8B698695C28DE' => '78.47.18.110:443', // fluxe3
        //'F9246DEF2B653807236DA134F2AEAB103D58ABFE' => '178.254.19.101:80', // Freebird31 (NIA - 2019/05/25)
        'F93D8F37E35C390BCAD9F9069E13085B745EC216' => '185.96.180.29:80', // TykRelay06
        //'FC9AC8EA0160D88BCCFDE066940D7DD9FA45495B' => '86.59.119.83:80', // ph3x (NIA - 2019/05/25)
        'FE296180018833AF03A8EACD5894A614623D3F76' => '149.56.45.200:9030', // PyotrTorpotkinOne
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
