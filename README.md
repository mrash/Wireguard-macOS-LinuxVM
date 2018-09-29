# Wireguard, macOS, and Linux Virtual Machines

## Introduction
Over the long term, the Wireguard VPN is set to send shockwaves through the VPN community
with its modern cryptographic design, performance, stealthiness against active scanners, and
committment to security through a minimally complex code base. It is my belief that these
characteristics firmly place Wireguard among the best VPN options available. Over time, it is
likely that commercial solutions will be developed around Wireguard similarly to commercial
wrappers around OpenVPN.

This repository is dedicated to deploying a Wireguard VPN on macOS via a Linux VM running
under a virtualization solution such as Parallels. There are many alternatives to this
approach - including omitting the Linux piece altogether and using the cross-platform macOS
[Wireguard tools](https://www.wireguard.com/xplatform/) - but I'm interested in using the
Wireguard kernel module from a Mac. This has to be done from a Linux VM.

The primary use case for running such a VPN solution is to provide security for network traffic
emanating from a Mac laptop that is connected to a potentially hostile wireless network. This
includes the network at the local coffee shop among many others. Nothing against coffee shops of
course (I love coffee), but they are in the business of making wonderful caffeinated potions - not
hardening their network infrastructure against adversaries. In terms of general threats to network
traffic, a properly deployed VPN allows you to shift much of the security burden to the other side
of the VPN. In this case, the remote Wireguard end point will be deployed in a major cloud provider
or ISP network. The security of, say, Google's GCE network or Amazon's AWS network is far higher
than the network of the local coffee shop.

**Note** macOS security is a broad topic, and this repository is meant only to discuss a VPN
solution based on Wireguard. For a comprehensive treatment of macOS security, including other
VPN options, see the excellent
[macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide).

## Prerequisites
To fully implement Wireguard in this manner, we'll assume the following:

 * An Ubuntu Linux VM is running under Parallels on a Mac laptop. Wireguard will run from
   this VM, and will constitute the "client" side of the VPN.
 * The Mac laptop will be connected wirelessly to the network at the local coffee shop, and
   have an IP assigned via DHCP as usual.
 * The "server" side of the Wireguard VPN is an Ubuntu system running on a major cloud
   provider with an Internet-facing IP address.
 * Wireguard has been [installed](https://www.wireguard.com/install/) on both Ubuntu VM's,
   and key pairs have been [generated and shared](https://www.wireguard.com/quickstart/).
 * Wireguard client - Mac laptop hostname and IP addresses:
   * Mac laptop hostname: `wgclient`
   * Mac laptop wireless IP on the coffee shop network: `192.168.10.54`, interface: `en0`
   * Mac laptop Ubuntu VM Wireguard hostname: `wgclientvm`, IP: `10.211.44.31`
   * Mac laptop Ubuntu VM Wireguard IP: `10.33.33.2`, interface: `wg0`
 * Wireguard server - Ubuntu system hostname and IP addresses:
   * Hostname: `wgserver`
   * IP: `2.2.2.2`, interface: `eth0`
   * Wireguard IP: `10.33.33.1`, interface: `wg0`

Graphically, the network setup looks like this:

![alt text][Wireguard-network-diagram]
[Wireguard-network-diagram]: doc/Wireguard_net.png "Wireguard Network Diagram"

## Wireguard Configuration
On `wgserver`, we have only one peer to worry about (`wgclientvm`), but this could be
expanded to arbitrarily many peers if necessary in order to support lots of VPN clients
for more complex scenarios. For now, we just have one peer, and the configuration is
shown below. Note the cryptographic keys have been replaced with dummy keys for obvious
reasons - you will need to generate your own keys per the prerequisites above. See the
[Wireguard Quickstart](https://www.wireguard.com/quickstart/) page for detailed
instructions. The main command to get things going is:

```bash
$ wg genkey | tee wg0.privkey | wg pubkey > wg0.pubkey
```

Now, the `wgserver` configuration:

```bash
[wgserver]# cat /etc/wireguard/wg0.conf
[Interface]
Address = 10.33.33.1/32
ListenPort = 30003
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIps = 10.33.33.2/32
```

And on `wgclientvm` we have:
```bash
[wgclientvm]# cat /etc/wireguard/wg0.conf
[Interface]
Address = 10.33.33.2/32
ListenPort = 30003
PrivateKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=

[Peer]
PublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
AllowedIps = 0.0.0.0/0, ::0/0
Endpoint = 1.1.1.1:30003
```

Note that the `AllowedIps` line in the client configuration allows all IPv4 and IPv6 addresses.
This is so that connections to any systems around the Internet worldwide will be allowed to
transit the Wireguard VPN. The server side does not need the same `AllowedIPs` line because the
source address of all traffic from the server's perspective will be the client IP of `10.33.33.2`.

With the Wireguard client and server configurations defined, it is time to bring up the VPN
from both sides.

```bash
[wgserver]# wg-quick up wg0
[#] ip link add wg0 type wireguard
[#] wg setconf wg0 /dev/fd/63
[#] ip address add 10.33.33.1/32 dev wg0
[#] ip link set mtu 1420 dev wg0
[#] ip link set wg0 up
[#] ip route add 10.33.33.2/32 dev wg0
```

```bash
[wgclientvm]# wg-quick up wg0
[#] ip link add wg0 type wireguard
[#] wg setconf wg0 /dev/fd/63
[#] ip address add 10.33.33.2/32 dev wg0
[#] ip link set mtu 1420 dev wg0
[#] ip link set wg0 up
[#] ip -6 route add ::/0 dev wg0 table 51820
[#] ip -6 rule add not fwmark 51820 table 51820
[#] ip -6 rule add table main suppress_prefixlength 0
[#] ip -4 route add 0.0.0.0/0 dev wg0 table 51820
[#] ip -4 rule add not fwmark 51820 table 51820
[#] ip -4 rule add table main suppress_prefixlength 0
[wgclientvm]# wg
interface: wg0
  public key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
  private key: (hidden)
  listening port: 30003
  fwmark: 0xca6c

peer: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
  endpoint: 1.1.1.1:30003
  allowed ips: 0.0.0.0/0, ::/0
  latest handshake: 2 seconds ago
  transfer: 384.27 KiB received, 62.09 KiB sent

[wgclientvm]# ping -c 3 10.33.33.1
PING 10.33.33.1 (10.33.33.1) 56(84) bytes of data.
64 bytes from 10.33.33.1: icmp_seq=1 ttl=64 time=2.39 ms
64 bytes from 10.33.33.1: icmp_seq=2 ttl=64 time=2.63 ms
64 bytes from 10.33.33.1: icmp_seq=3 ttl=64 time=2.33 ms

--- 10.33.33.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 2.336/2.454/2.632/0.134 ms
```

So, the VPN is up and running. This is great, but now we need to ensure that all traffic is
routed through the VPN. This applies to both the Ubuntu VM `wgclientvm` and, most importantly,
to the Mac laptop host `wgclient`. Achieving this is the subject of the next section.

## Routing and Traffic Filtering
Routing all traffic over the VPN needs to happen even though the Mac laptop has only one
interface `en0` that is connected to the local wireless network. Basic routing through the
default gateway of this network needs to remain intact, but we also need to first send
everything down to the `wgclientvm` system for routing over the established VPN tunnel.

A convenience script `wg-routes.py` is included for this task. This script is meant to be
executed on the Mac laptop `wgclient` and it adds three new routes to the routing table on
the Mac. Although the existing default route is not changed, it is overridden with two more
specific routes - each for half of the entire IPv4 address space with a gateway of the
`wgclientvm` IP. The final route is for the Wireguard server out of the gateway originally
assigned to the default route. The original default route can optionally be deleted after
these routes are established and everything is sent over the VPN.

The `wg-routes.py` script has a setup mode that generates a config file from the specified
Wireguard endpoints, and an operational mode that adds, deletes, or checks the status of
Wireguard routes. We start with the setup phase:

```bash
[wgclient]# ./wg-routes.py --setup --wg-client 10.211.44.31 --wg-server 2.2.2.2
Config written to '/var/root/.wg-routes.conf', now 'up|down|status' cmds can be used.
```

With the config file written, we can now bring the routes up and also check the status
(some output has been removed for brevity):

```bash
[wgclient]# ./wg-routes.py up
Running cmd: 'route add 0.0.0.0/1 10.211.44.31'
Running cmd: 'route add 128.0.0.0/1 10.211.44.31'
Running cmd: 'route add 2.2.2.2 192.168.10.1'

[wgclient]# ./wg-routes.py status
Wireguard client route active: '0/1        10.211.44.31  UGSc  50  0   vnic0'
Wireguard client route active: '128.0/1    10.211.44.31  UGSc   1  0   vnic0'
Wireguard server route active: '2.2.2.2    192.168.10.1  UGHS   0  0     en0'
```

Note in the above output that there is no need to manually specify the default
gateway `192.168.10.1` on the wireless network since `wg-routes.py` automatically
parses it out of the routing table.

```bash
[wgclient]# ./wg-routes.py down
Running cmd: 'route delete 0.0.0.0/1 10.211.44.31'
Running cmd: 'route delete 128.0.0.0/1 10.211.44.31'
Running cmd: 'route delete 2.2.2.2 192.168.10.1'
```

With the routes now directing all IP traffic to the `wgclientvm` system, there are
two details to take care of. First, on `wgclientvm` we need to create a NAT rule so that
all incoming traffic from the Mac laptop are translated to the source IP of the
Wireguard tunnel. Second, IP forwarding needs to be allowed on `wgclientvm` as well:

```bash
[wgclientvm]# iptables -t nat -A POSTROUTING -s 10.211.44.2 -j SNAT --to 10.33.33.2
[wgclientvm]# echo 1 > /proc/sys/net/ipv4/ip_forward
```

This concludes the necessary steps to route all traffic from both the Mac laptop `wgclient`
and the `wgclientvm` systems through Wireguard to the `wgserver` system and out to the
broader Internet. Note that the `wg-quick` tool that instantiated the Wireguard instance
on `wgclientvm` also sets up routing such that everything is sent over Wireguard.

Now let's test it:
```bash
```

### Traffic Filtering with PF and iptables

### Verifying Traffic Routing

### DNS

## License
This repository is released as open source software under the terms of
the **GNU General Public License (GPL v2+)**.

## Contact
All feature requests and bug fixes are managed through github issues tracking.
However, you can also email me (michael.rash_AT_gmail.com), or reach me through
Twitter ([@michaelrash](https://twitter.com/michaelrash)).
