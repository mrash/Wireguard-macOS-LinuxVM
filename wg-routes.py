#!/usr/bin/env python
#
#  File: wg_routes.py
#
#  Version: 0.1
#
#  Purpose: Manipulate the routing table on macOS to enable or disable default
#           routing through a Wireguard tunnel running under a Linux VM.
#
#
#  Copyright (C) 2018 Michael Rash (mbr@cipherdyne.org)
#
#  License (GNU General Public License version 2 or any later version):
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02111-1301,
#  USA
#

from tempfile import NamedTemporaryFile
import socket
import re
import argparse
import sys, os

try:
    import subprocess32 as subprocess
except ImportError:
    import subprocess

__version__ = '0.1'

def main():

    cargs = parse_cmdline()

    if cargs.version:
        print "wg-routes-" + __version__
        return 0

    if cargs.wg_server:
        wg_server = resolve(cargs.wg_server)
    else:
        raise NameError("[*] Specify the Wireguard server IP (or hostname) with --wg-server")

    if cargs.wg_client:
        wg_client = resolve(cargs.wg_client)
    else:
        raise NameError("[*] Specify the local VM IP/hostname where the Wireguard client is running with --wg-client")

    if not cargs.cmd or (cargs.cmd.lower() != 'up' and cargs.cmd.lower() != 'down'):
        raise NameError("[*] Set --cmd <up>|<down>")

    if cargs.default_gw:
        default_gw = cargs.default_gw
    else:
        default_gw = get_default_gw(cargs)

    ### now that we have the default gateway, the wireguard server, and the local
    ### VM IP's, add the routes
    route_update(default_gw, wg_client, wg_server, cargs)

    if cargs.cmd.lower() == 'up':
        up_guidance(wg_client)
    else:
        down_guidance(wg_client)

    return 0

def up_guidance(wg_client):
    print '''
With routing configured to send traffic to the Wireguard client system '%s',
it is usually necessary to add NAT rule in iptables along with allowing IP
forwarding. The NAT rule should translate incoming IP traffic from the Mac
to the Wireguard client IP assigned in the 'Address' line in the Wireguard
interface configuration file. The incoming traffic from the Mac is normally
the IP assigned to a virtual interface such as 'vnic0'. E.g.:

[wgclientvm]# iptables -t nat -A POSTROUTING -s <vnic0_IP> -j SNAT --to <WG_client_IP>

[wgclientvm]# echo 1 > /proc/sys/net/ipv4/ip_forward
''' % wg_client
    return

def down_guidance(wg_client):
    print '''
Applicable routes have been removed. The corresponding NAT rule and IP
forwarding configuration can be removed from the '%s' Wireguard client system.
''' % wg_client
    return

def route_update(default_gw, wg_client, wg_server, cargs):

    ### route add 0.0.0.0/1 <wg_client>
    ### route add 128.0.0.0/1 <wg_client>
    ### route add <wg_server> <default_gw>

    ### route add 0.0.0.0/1 10.111.55.31
    ### route add 128.0.0.0/1 10.111.55.31
    ### route add 2.2.2.2 192.168.0.1

    update_cmd = 'add'
    if cargs.cmd.lower() == 'down':
        update_cmd = 'delete'

    print
    for cmd in ["route %s 0.0.0.0/1 %s" % (update_cmd, wg_client),
            "route %s 128.0.0.0/1 %s" % (update_cmd, wg_client),
            "route %s %s %s" % (update_cmd, wg_server, default_gw)
        ]:
        print "Running cmd: '%s'" % cmd
        (es, out) = run_cmd(cmd, cargs)
        if (es != 0):
            for line in out:
                print line
        else:
            ### look for indications of errors not caught by the process
            ### exit status
            found_err = False
            if cargs.cmd.lower() == 'up':
                ### # route add 0.0.0.0/1 10.211.55.31
                ### route: writing to routing socket: File exists
                ### add net 0.0.0.0: gateway 10.211.55.31: File exists
                for line in out:
                    if 'File exists' in line:
                        found_err = True
                        break
            elif cargs.cmd.lower() == 'down':
                for line in out:
                    ### # route delete 0.0.0.0/1 10.211.55.31
                    ### route: writing to routing socket: not in table
                    ### delete net 0.0.0.0: gateway 10.211.55.31: not in table
                    if 'not in table' in line:
                        found_err = True
                        break
            if found_err:
                for line in out:
                    print line

    return

def resolve(host):
    ip = ''
    if ':' in host:
        raise NameError("[*] IPv6 coming soon....")
    else:
        if re.search('(?:[0-2]?\d{1,2}\.){3}[0-2]?\d{1,2}', host):
            ip = host
        else:
            ### it's a hostname, so resolve
            ip = socket.gethostbyname(host)
            if not ip or not re.search('(?:[0-2]?\d{1,2}\.){3}[0-2]?\d{1,2}', ip):
                raise NameError("[*] Could not resolve '%s' to an IP" % ip)
    return ip

def get_default_gw(cargs):

    gw    = ''
    flags = ''
    netstat_cmd = 'netstat -rn'

    ### parse 'netstat -rn' output on macOS to get the default (IPv4) gw
    ### Destination        Gateway            Flags        Refs      Use   Netif Expire
    ### default            192.168.0.1        UGSc           69        0     en0

    for line in run_cmd(netstat_cmd, cargs)[1]:
        m = re.search('default\s+((?:[0-2]?\d{1,2}\.){3}[0-2]?\d{1,2})\s+(\w+)\s', line)
        if m:
            gw    = m.group(1)
            flags = m.group(2)
            break

    if gw and flags:
        for flag in ['G', 'U']:
            if flag not in flags:
                raise NameError(
                    "[*] Default gateway '%s' does not have the '%s' flag, set with --default-gw" \
                            % (gw, flag))
    else:
        raise NameError(
            "[*] Could not parse default gateway from '%s' output, set with --default-gw" \
                    % netstat_cmd)

    return gw

def run_cmd(cmd, cargs):
    out = []
    if cargs.verbose:
        print "    CMD: '%s'" % cmd

    fh = NamedTemporaryFile(delete=False)
    es = subprocess.call(cmd, stdin=None,
            stdout=fh, stderr=subprocess.STDOUT, shell=True)
    fh.close()
    with open(fh.name, 'r') as f:
        for line in f:
            out.append(line.rstrip('\n'))
    os.unlink(fh.name)

    if (es != 0):
        print "[-] Non-zero exit status '%d' for CMD: '%s'" % (es, cmd)

    if cargs.verbose:
        for line in out:
            print line

    return es, out

def parse_cmdline():
    p = argparse.ArgumentParser()

    p.add_argument("--wg-server", type=str,
            help="Set the Wireguard upstream server IP/hostname",
            default=False)
    p.add_argument("--wg-client", type=str,
            help="Set the local VM IP/hostname where the Wireguard client is running",
            default=False)

    p.add_argument("--cmd", type=str,
            help="Set the command, e.g. 'up' (add routes) or 'down' (remove routes)",
            default=False)

    p.add_argument("--default-gw", type=str,
            help="Manually set the IPv4 default gw", default=False)

    p.add_argument("-v", "--verbose", action='store_true',
            help="Verbose mode", default=False)
    p.add_argument("-V", "--version", action='store_true',
            help="Print version and exit", default=False)

    return p.parse_args()

if __name__ == "__main__":
    sys.exit(main())
