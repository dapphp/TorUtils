## Name:

**Dapphp\TorUtils** - PHP classes for interacting with the Tor control protocol,
directory authorities and servers, and DNS exit lists.

## Version:

**1.1.8**

## Author:

Drew Phillips <drew@drew-phillips.com>

## Requirements:

* PHP 5.3 or greater

## Description:

**Dapphp\TorUtils** provides some PHP libraries for working with Tor.
The main functionality focuses on interacting with Tor using the Tor
control protocol and provides many methods to make it easy to send
commands, retrieve directory and node information, and modify Tor's
configuration using the control protocol.  A few other utility classes
are provided for robustness.

The following classes are provided:

- ControlClient: A class for interacting with Tor's control protocol which 
can be used to script your Tor relay or learn information about
other nodes in the Tor network.  With this class you can query directory
information through the controller, get and set Tor configuration values,
fetch information with the GETINFO command, subscribe to events, and send
raw commands to the controller and get back parsed responses. 

- DirectoryClient: A class for querying information directly from Tor
directory authorities (or any other Tor directory server).  This class
can be used to fetch information about active nodes in the network by
nickname or fingerprint or retrieve a list of all active nodes to get
information such as IP address, contact info, exit policies, certs,
uptime, flags and more. 

- TorDNSEL: A simple interface for querying an address against the Tor
DNS exit lists to see if an IP address belongs to a Tor exit node.

- TorCurlWrapper: A wrapper for cURL that ensures HTTP requests are proxied
through Tor using SOCKS5 with DNS resolution over Tor (if supported).  It also
turns cURL errors into an Exception and parses responses into headers and body
parts.

## Basic Example:

This library provides a lot of different functionality (see examples directory)
and a wide range of possibility but a common use case is sending a signal to
the Tor controller to change IP addresses.  This shows how to do just that:

    <?php

    require_once 'vendor/autoload.php'; // using composer

    use Dapphp\TorUtils\ControlClient;

    $tc = new ControlClient();

    try {
        $tc->connect(); // connect to 127.0.0.1:9051
        $tc->authenticate('password'); // can also use cookie or empty auth
        $tc->signal(ControlClient::SIGNAL_NEWNYM);
        echo "Signal sent - IP changed successfully!\n";
    } catch (\Exception $ex) {
        echo "Signal failed: " . $ex->getMessage() . "\n";
    }


## Examples:

The source package comes with several examples of interacting with the
Tor control protocol and directory authorities.  See the `examples/`
directory in the source package.

Currently, the following examples are provided:

- dc_GetAllDescriptors-simple.php: Uses the DirectoryClient class to query a
directory authority for a list of all currently known descriptors and prints
basic information on each descriptor.

- dc_GetServerDescriptor-simple.php: Uses the DirectoryClient to fetch info
about a single descriptor and prints the information.

- tc_AsyncEvents.php: Uses the ControlClient to subscribe to some events which
the controller will send to a registered callback as they are generated.

- tc_GetConf.php: Uses the ControlClient to interact with the controller to
fetch and set Tor configuration options.

- tc_GetInfo.php: Uses ControlClient to talk to the Tor controller to get
various pieces of information about the controller and routers on the network.

- tc_NewNym.php: Uses ControlClient to send the "NEWNYM" signal to the
controller to change IP addresses (as shown above).

- tc_CreateHiddenService.php: Tells the controller to create a new Onion
("Hidden") Service.  This example shows how to programatically add a new hidden
service, delete it, and re-create it with the private key that was generated.
The private key can be securely stored to restart the service at a later time
using the same onion address.

- tc_SendData.php: Shows how to use ControlClient to send arbitrary commands
and read the response from the controller.  Replies are returned as 
ProtocolReply objects which give easy access to the status of the reply (e.g.
success/fail) and provides methods to access individual reply lines or 
iterate over each line and process the data.

- TorDNSEL.php: An example of using the Tor DNS Exit Lists to check if a remote
IP address connecting to a specific IP:Port combination is a Tor exit router.

- CurlWrapper.php: Shows how to use the cURL wrapper class to make HTTP requests
through the Tor socks proxy.

- CurlCountry.php: Shows how to use Exit Nodes from a specific country with the
cURL wrapper.

## TODO:

The following commands are not directly implemented by ControlClient and would
need to be implemented or the implementation could communicate directly with
the controller using the provided functions to issue commands:

- RESETCONF
- SAVECONF
- MAPADDRESS
- EXTENDCIRCUIT
- SETCIRCUITPURPOSE
- ATTACHSTREAM
- POSTDESCRIPTOR
- REDIRECTSTREAM
- CLOSESTREAM
- CLOSECIRCUIT
- USEFEATURE
- LOADCONF
- TAKEOWNERSHIP
- DROPGUARDS
- HSFETCH
- HSPOST

## Copyright:

    Copyright (c) 2016 Drew Phillips
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
