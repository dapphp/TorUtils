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
     * https://gitweb.torproject.org/tor.git/tree/src/or/config.c#n854
     *
     * @var $DirectoryAuthorities List of directory authorities
     */
    private $DirectoryAuthorities = array(
        '7BE683E65D48141321C5ED92F075C55364AC7123' => '193.23.244.244:80', // dannenberg
        '7EA6EAD6FD83083C538F44038BBFA077587DD755' => '194.109.206.212:80', // dizum
        'CF6D0AAFB385BE71B8E111FC5CFF4B47923733BC' => '154.35.175.225:80', // Faravahar
        'F2044413DAC2E02E3D6BCF4735A19BCA1DE97281' => '131.188.40.189:80', // gabelmoo
        '74A910646BCEEFBCD2E874FC1DC997430F968145' => '199.254.238.52:80', // longclaw
        'BD6A829255CB08E66FBE7D3748363586E46B3810' => '171.25.193.9:443', // maatuska
        '9695DFC35FFEB861329B9F1AB04C46397020CE31' => '128.31.0.39:9131', // moria1
        '1D8F3A91C37C5D1C4C19B1AD1D0CFBE8BF72D8E1' => '37.218.247.217:80', // Bifroest
        '847B1F850344D7876491A54892F904934E4EB85D' => '86.59.21.38:80', // tor26
    );

    // last update 2017/06/04 (commit blob cc37e5f9aff6bedfa7752c2e9966de58ad68b2fb)
    private $directoryFallbacks = array(
        '0111BA9B604669E636FFD5B503F382A4B7AD6E80' => '176.10.104.240:80',
        '01A9258A46E97FF8B2CAC7910577862C14F2C524' => '193.171.202.146:9030',
        '025B66CEBC070FCB0519D206CF0CF4965C20C96E' => '185.100.85.61:80',
        '04250C3835019B26AA6764E85D836088BE441088' => '185.97.32.18:9030',
        '0756B7CD4DFC8182BE23143FAC0642F515182CEB' => '5.9.110.236:9030',
        '0818DAE0E2DDF795AEDEAC60B15E71901084F281' => '109.163.234.8:80',
        '0B85617241252517E8ECF2CFC7F4C1A32DCD153F' => '163.172.149.155:80',
        '0BEA4A88D069753218EAAAD6D22EA87B9A1319D6' => '5.39.92.199:80',
        '0D3EBA17E1C78F1E9900BABDB23861D46FCAF163' => '178.62.197.82:80',
        '0E8C0C8315B66DB5F703804B3889A1DD66C67CE0' => '185.100.86.100:80',
        '1211AC1BBB8A1AF7CBA86BCE8689AA3146B86423' => '95.85.8.226:80',
        '12AD30E5D25AA67F519780E2111E611A455FDC89' => '193.11.114.43:9030',
        '12FD624EE73CEF37137C90D38B2406A66F68FAA2' => '37.157.195.87:8030',
        '136F9299A5009A4E0E96494E723BDB556FB0A26B' => '178.16.208.59:80',
        '14419131033443AE6E21DA82B0D307F7CAE42BDB' => '144.76.14.145:110',
        '175921396C7C426309AB03775A9930B6F611F794' => '178.62.60.37:80',
        '185F2A57B0C4620582602761097D17DB81654F70' => '204.11.50.131:9030',
        '1AF72E8906E6C49481A791A6F8F84F8DFEBBB2BA' => '5.9.158.75:80',
        '1DBAED235E3957DE1ABD25B4206BE71406FB61F8' => '46.101.151.222:80',
        '1ECD73B936CB6E6B3CD647CC204F108D9DF2C9F7' => '91.219.237.229:80',
        '20462CBA5DA4C2D963567D17D0B7249718114A68' => '212.47.229.2:9030',
        '22F08CF09764C4E8982640D77F71ED72FF26A9AC' => '144.76.163.93:9030',
        '230A8B2A8BA861210D9B4BA97745AEC217A94207' => '163.172.176.167:80',
        '231C2B9C8C31C295C472D031E06964834B745996' => '37.200.98.5:80',
        '2A4C448784F5A83AFE6C78DA357D5E31F7989DEB' => '212.47.240.10:82',
        '2BA2C8E96B2590E1072AECE2BDB5C48921BF8510' => '144.76.26.175:9012',
        '2F0F32AB1E5B943CA7D062C03F18960C86E70D94' => '97.74.237.196:9030',
        '30973217E70AF00EBE51797FF6D9AA720A902EAA' => '107.170.101.39:9030',
        '30C19B81981F450C402306E2E7CFB6C3F79CB6B2' => '64.113.32.29:9030',
        '322C6E3A973BC10FC36DE3037AD27BC89F14723B' => '212.83.154.33:8080',
        '32EE911D968BE3E016ECA572BB1ED0A9EE43FC2F' => '109.105.109.162:52860',
        '33DA0CAB7C27812EFF2E22C9705630A54D101FEB' => '163.172.13.165:9030',
        '361D33C96D0F161275EE67E2C91EE10B276E778B' => '217.79.190.25:9030',
        '36B9E7AC1E36B62A9D6F330ABEB6012BA7F0D400' => '37.187.22.87:9030',
        '387B065A38E4DAA16D9D41C2964ECBC4B31D30FF' => '62.210.92.11:9130',
        '39F096961ED2576975C866D450373A9913AFDC92' => '198.50.191.95:80',
        '3B33F6FCA645AD4E91428A3AF7DC736AD9FB727B' => '164.132.77.175:9030',
        '3D6D0771E54056AEFC28BB1DE816951F11826E97' => '212.47.230.49:9030',
        '3D7E274A87D9A89AF064C13D1EE4CA1F184F2600' => '176.10.107.180:9030',
        '3E53D3979DB07EFD736661C934A1DED14127B684' => '217.79.179.177:9030',
        '439D0447772CB107B886F7782DBC201FA26B92D1' => '178.62.86.96:9030',
        '4623A9EC53BFD83155929E56D6F7B55B5E718C24' => '163.172.157.213:8080',
        '46791D156C9B6C255C2665D4D8393EC7DBAA7798' => '31.31.78.49:80',
        '4791FC0692EAB60DF2BCCAFF940B95B74E7654F6' => '69.162.139.9:9030',
        '47B596B81C9E6277B98623A84B7629798A16E8D5' => '51.254.246.203:9030',
        '489D94333DF66D57FFE34D9D59CC2D97E2CB0053' => '37.187.102.186:9030',
        '49E7AD01BB96F6FE3AB8C3B15BD2470B150354DF' => '188.165.194.195:9030',
        '4A0C3E177AF684581EF780981AEAF51A98A6B5CF' => '62.102.148.67:80',
        '4CC9CC9195EC38645B699A33307058624F660CCF' => '51.254.101.242:9002',
        '51E1CF613FD6F9F11FE24743C91D6F9981807D82' => '81.7.16.182:80',
        '5665A3904C89E22E971305EE8C1997BCA4123C69' => '94.23.204.175:9030',
        '587E0A9552E4274B251F29B5B2673D38442EE4BF' => '95.130.12.119:80',
        '58ED9C9C35E433EE58764D62892B4FFD518A3CD0' => '185.21.100.50:9030',
        '5A5E03355C1908EBF424CAF1F3ED70782C0D2F74' => '78.142.142.246:80',
        '5E853C94AB1F655E9C908924370A0A6707508C62' => '120.29.217.46:80',
        '5EB8D862E70981B8690DEDEF546789E26AB2BD24' => '109.163.234.5:80',
        '616081EC829593AF4232550DE6FFAA1D75B37A90' => '95.128.43.164:80',
        '68F175CCABE727AA2D2309BCD8789499CEE36ED7' => '163.172.139.104:8080',
        '6A7551EEE18F78A9813096E82BF84F740D32B911' => '85.214.62.48:80',
        '6EF897645B79B6CB35E853B32506375014DE3621' => '80.127.137.19:80',
        '7187CED1A3871F837D0E60AC98F374AC541CB0DA' => '95.183.48.12:80',
        '722D365140C8C52DBB3C9FF6986E3CEFFE2BA812' => '85.214.151.72:9030',
        '72B2B12A3F60408BDBC98C6DF53988D3A0B3F0EE' => '85.235.250.88:80',
        '7350AB9ED7568F22745198359373C04AC783C37C' => '176.31.191.26:80',
        '763C9556602BD6207771A7A3D958091D44C43228' => '134.119.36.135:80',
        '774555642FDC1E1D4FDF2E0C31B7CA9501C5C9C7' => '188.166.133.133:9030',
        '789EA6C9AE9ADDD8760903171CFA9AC5741B0C70' => '81.30.158.213:9030',
        '79861CF8522FC637EF046F7688F5289E49D94576' => '171.25.193.131:80',
        '7A32C9519D80CA458FC8B034A28F5F6815649A98' => '82.223.21.74:9030',
        '7BB70F8585DFC27E75D692970C0EEB0F22983A63' => '51.254.136.195:80',
        '80AAF8D5956A43C197104CEF2550CD42D165C6FB' => '193.11.114.45:9031',
        '823AA81E277F366505545522CEDC2F529CE4DC3F' => '192.160.102.164:80',
        '844AE9CAD04325E955E2BE1521563B79FE7094B7' => '192.87.28.82:9030',
        '8672E8A01B4D3FA4C0BBE21C740D4506302EA487' => '188.166.23.127:80',
        '8844D87E9B038BE3270938F05AF797E1D3C74C0F' => '93.180.156.84:9030',
        '892F941915F6A0C6E0958E52E0A9685C190CF45C' => '212.47.241.21:80',
        '8C00FA7369A7A308F6A137600F0FA07990D9D451' => '163.172.194.53:9030',
        '8FA37B93397015B2BC5A525C908485260BE9F422' => '178.254.44.135:9030',
        '9007C1D8E4F03D506A4A011B907A9E8D04E3C605' => '151.80.42.103:9030',
        '91E4015E1F82DAF0121D62267E54A1F661AB6DC7' => '173.255.245.116:9030',
        '9231DF741915AA1630031A93026D88726877E93A' => '51.255.41.65:9030',
        '92CFD9565B24646CAC2D172D3DB503D69E777B8A' => '178.16.208.57:80',
        '92ECC9E0E2AF81BB954719B189AC362E254AD4A5' => '91.219.237.244:80',
        '94C4B7B8C50C86A92B6A20107539EE2678CF9A28' => '204.8.156.142:80',
        '998BF3ED7F70E33D1C307247B9626D9E7573C438' => '163.172.223.200:80',
        '99E246DB480B313A3012BC3363093CC26CD209C7' => '81.7.10.93:31336',
        '9A0D54D3A6D2E0767596BF1515E6162A75B3293F' => '91.229.20.27:9030',
        '9A68B85A02318F4E7E87F2828039FBD5D75B0142' => '66.111.2.20:9030',
        '9B31F1F1C1554F9FFB3455911F82E818EF7C7883' => '185.100.86.128:9030',
        '9BF04559224F0F1C3C953D641F1744AF0192543A' => '5.9.151.241:9030',
        '9C900A7F6F5DD034CFFD192DAEC9CCAA813DB022' => '86.105.212.130:9030',
        '9F5068310818ED7C70B0BC4087AB55CB12CB4377' => '178.254.20.134:80',
        '9F7D6E6420183C2B76D3CE99624EBC98A21A967E' => '46.28.110.244:80',
        '9FBEB75E8BC142565F12CBBE078D63310236A334' => '91.121.84.137:4952',
        'A0766C0D3A667A3232C7D569DE94A28F9922FCB1' => '178.62.22.36:80',
        'A10C4F666D27364036B562823E5830BC448E046A' => '171.25.193.77:80',
        'A478E421F83194C114F41E94F95999672AED51FE' => '171.25.193.78:80',
        'A9406A006D6E7B5DA30F2C6D4E42A338B5E340B2' => '163.172.149.122:80',
        'ABCB4965F1FEE193602B50A365425105C889D3F8' => '192.34.63.137:9030',
        'ABF7FBF389C9A747938B639B20E80620B460B2A9' => '109.163.234.9:80',
        'ACD889D86E02EDDAB1AFD81F598C0936238DC6D0' => '86.59.119.88:80',
        'ACDD9E85A05B127BA010466C13C8C47212E8A38F' => '185.129.62.62:9030',
        'AD253B49E303C6AB1E048B014392AC569E8A7DAE' => '163.172.131.88:80',
        'ADB2C26629643DBB9F8FE0096E7D16F9414B4F8D' => '31.185.104.20:80',
        'AEA43CB1E47BE5F8051711B2BF01683DB1568E05' => '37.187.7.74:80',
        'AF322D83A4D2048B22F7F1AF5F38AFF4D09D0B76' => '46.28.205.170:80',
        'B0553175AADB0501E5A61FC61CEA3970BE130FF2' => '5.9.147.226:9030',
        'B143D439B72D239A419F8DCE07B8A8EB1B486FA7' => '212.129.62.232:80',
        'B1D81825CFD7209BD1B4520B040EF5653C204A23' => '198.199.64.217:80',
        'B291D30517D23299AD7CEE3E60DFE60D0E3A4664' => '136.243.214.137:80',
        'B44FBE5366AD98B46D829754FA4AC599BAE41A6A' => '178.16.208.60:80',
        'B5212DB685A2A0FCFBAE425738E478D12361710D' => '93.115.97.242:9030',
        'B6904ADD4C0D10CDA7179E051962350A69A63243' => '81.2.209.10:443',
        'B83DC1558F0D34353BB992EF93AFEAFDB226A73E' => '193.11.114.46:9032',
        'B84F248233FEA90CAD439F292556A3139F6E1B82' => '85.248.227.164:444',
        'BC7ACFAC04854C77167C7D66B7E471314ED8C410' => '89.163.247.43:9030',
        'BCEDF6C193AA687AE471B8A22EBF6BC57C2D285E' => '198.96.155.3:8080',
        'BCEF908195805E03E92CCFE669C48738E556B9C5' => '128.199.55.207:9030',
        'C13B91384CDD52A871E3ECECE4EF74A7AC7DCB08' => '185.35.202.221:9030',
        'C37BC191AC389179674578C3E6944E925FE186C2' => '213.239.217.18:1338',
        'C414F28FD2BEC1553024299B31D4E726BEB8E788' => '188.138.112.60:1433',
        'C793AB88565DDD3C9E4C6F15CCB9D8C7EF964CE9' => '85.248.227.163:443',
        'CBEFF7BA4A4062045133C053F2D70524D8BBE5BE' => '178.62.199.226:80',
        'D1B8AAA98C65F3DF7D8BB3AF881CAEB84A33D8EE' => '134.119.3.164:9030',
        'D3E5EDDBE5159388704D6785BE51930AAFACEC6F' => '31.171.155.108:9030',
        'D5039E1EBFD96D9A3F9846BF99EC9F75EDDE902A' => '37.187.115.157:9030',
        'D5C33F3E203728EDF8361EA868B2939CCC43FAFB' => '166.82.21.200:9030',
        'D62FB817B0288085FAC38A6DC8B36DCD85B70260' => '185.14.185.240:9030',
        'D760C5B436E42F93D77EF2D969157EEA14F9B39C' => '46.101.169.151:9030',
        'D9065F9E57899B3D272AA212317AF61A9B14D204' => '46.4.111.124:9030',
        'DAA39FC00B196B353C2A271459C305C429AF09E4' => '193.35.52.53:9030',
        'DD823AFB415380A802DCAEB9461AE637604107FB' => '178.33.183.251:80',
        'DD85503F2D1F52EF9EAD621E942298F46CD2FC10' => '178.62.173.203:9030',
        'DDD7871C1B7FA32CB55061E08869A236E61BDDF8' => '5.34.183.205:80',
        'DEB73705B2929AE9BE87091607388939332EF123' => '78.24.75.53:9030',
        'DED6892FF89DBD737BA689698A171B2392EB3E82' => '92.222.38.67:80',
        'E3DB2E354B883B59E8DC56B3E7A353DDFD457812' => '166.70.207.2:9030',
        'E589316576A399C511A9781A73DA4545640B479D' => '46.252.26.2:45212',
        'E65D300F11E1DB12C534B0146BDAB6972F1A8A48' => '167.114.35.28:9030',
        'EBE718E1A49EE229071702964F8DB1F318075FF8' => '131.188.40.188:443',
        'ED2338CAC2711B3E331392E1ED2831219B794024' => '192.87.28.28:9030',
        'F10BDE279AE71515DDCCCC61DC19AC8765F8A3CC' => '192.99.212.139:80',
        'F406219CDD339026D160E53FCA0EF6857C70F109' => '212.238.208.48:9030',
        'F69BED36177ED727706512BA6A97755025EEA0FB' => '46.28.207.141:80',
        'F8D27B163B9247B232A2EEE68DD8B698695C28DE' => '78.47.18.110:443',
        'F9246DEF2B653807236DA134F2AEAB103D58ABFE' => '178.254.13.126:80',
        'F93D8F37E35C390BCAD9F9069E13085B745EC216' => '185.96.180.29:80',
        'FC9AC8EA0160D88BCCFDE066940D7DD9FA45495B' => '86.59.119.83:80',
        'FD1871854BFC06D7B02F10742073069F0528B5CC' => '192.187.124.98:9030',
        'FE296180018833AF03A8EACD5894A614623D3F76' => '149.56.45.200:9030',
        'FFA72BD683BC2FCF988356E6BEC1E490F313FB07' => '193.11.164.243:9030',
    );

    private $preferredServer;

    private $_connectTimeout = 5;
    private $_userAgent = 'dapphp/TorUtils 1.1.8';

    private $_parser;
    private $_serverList;

    /**
     * DirectoryClient constructor
     */
    public function __construct()
    {
        $this->_serverList = array_merge($this->DirectoryAuthorities, $this->directoryFallbacks);
        shuffle($this->_serverList);

        $this->_parser = new Parser();
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

        $this->_connectTimeout = (int)$timeout;

        return $this;
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

        $descriptors = $this->_parser->parseDirectoryStatus($reply);

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

        $descriptors = $this->_parser->parseDirectoryStatus($reply);

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
        reset($this->_serverList);
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

            $fp = fsockopen($host, $port, $errno, $errstr, $this->_connectTimeout);
            if (!$fp) continue;

            $request = $this->_getHttpRequest('GET', $host, $uri);

            fwrite($fp, $request);

            $response = '';

            while (!feof($fp)) {
                $response .= fgets($fp);
            }

            fclose($fp);

            list($headers, $body) = explode("\r\n\r\n", $response, 2);
            $headers = $this->_parseHttpResponseHeaders($headers);

            if ($headers['status_code'] == '503') {
                trigger_error("Directory $server returned 503 {$headers['message']}", E_USER_NOTICE);
                continue;
            }

            if ($headers['status_code'] !== '200') {
                throw new \Exception(
                    sprintf('Directory returned a negative response code to request.  %s %s', $headers['status_code'], $headers['message'])
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
            $method, $uri, $host, $this->_userAgent
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
        $server = current($this->_serverList);
        next($this->_serverList);
        return $server;
    }
}
