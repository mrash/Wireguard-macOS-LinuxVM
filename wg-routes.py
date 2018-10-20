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

    config_file = os.path.expanduser('~/.wg-routes.conf')
    cmd  = ''
    conf = {}

    if len(sys.argv) == 2:
        cmd = sys.argv[1].lower()
    elif len(sys.argv) == 3:
        config_file = sys.argv[2]
    elif len(sys.argv) == 1:
        ### equate this with 'status'
        cmd = 'status'

    if cmd and '-' not in cmd:
        ### command mode, so validate the command and take the next steps
        if cmd != 'up' and cmd != 'down' and cmd != 'status':
            raise NameError("<cmd> must be one of up|down|status")

        if config_file:
            if not os.path.exists(config_file):
                raise NameError("config file '%s' does not exist" % config_file)

        parse_config(conf, config_file)

        if cmd == 'up' or cmd == 'down':
            ### now that we have the default gateway, the wireguard
            ### server, and the local VM IP's, add the routes
            route_update(cmd, conf)

            ### update the PF policy if so configured
            pf_update(cmd, conf, config_file)

            if cmd == 'up':
                up_guidance(conf['WG_CLIENT'])
            else:
                down_guidance(conf['WG_CLIENT'])
        else:
            route_status(conf)
            pf_status(conf)

        return 0

    ### we must be in --setup, --list, or --version mode. Write the config based on
    ### command line arguments in --setup mode.
    cargs = parse_cmdline()

    if cargs.version:
        print "wg-routes-" + __version__
        return 0

    if not cargs.setup and not cargs.list:
        raise NameError("Must use one of --setup or --list")

    if cargs.list:
        display_config(config_file, cargs)
        return 0

    if not cargs.wg_server:
        raise NameError("[*] Specify the Wireguard server IP (or hostname) with --wg-server")

    if not cargs.wg_client:
        raise NameError("[*] Specify the local VM IP/hostname where the Wireguard client is running with --wg-client")

    if not cargs.wg_port:
        raise NameError("[*] Specify the Wireguard UDP port number with --wg-port")

    if cargs.config_file:
        config_file = cargs.config_file

    if cargs.pf_config_file:
        pf_config_file = cargs.pf_config_file
    else:
        pf_config_file = os.path.expanduser("~/.wg-pf.conf")

    if cargs.pf_rules_file:
        pf_rules_file = cargs.pf_rules_file
    else:
        pf_rules_file = os.path.expanduser("~/.wg-pf.rules")

    if cargs.setup:
        ### write the config and exit
        write_config(config_file, pf_config_file, pf_rules_file, cargs)
        write_pf_config(pf_config_file, pf_rules_file, cargs)
        write_pf_rules(pf_rules_file, cargs)
        print "Configs written to '%s', '%s',\nand '%s'. Now 'up|down|status' cmds can be used." \
                % (config_file, pf_config_file, pf_rules_file)

    return 0

def parse_config(conf, config_file):
    with open(config_file, 'r') as f:
        for line in f:
            for var in ['WG_CLIENT',
                    'WG_SERVER',
                    'DEFAULT_GW',
                    'ENABLE_PF_POLICY',
                    'PF_CONFIG_FILE',
                    'PF_ANCHOR_FILE',
                    'PF_INTF']:
                m = re.search("^\s*%s\s+(\S+)" % var, line)
                if m:
                    ### resolve via DNS if necessary at parse time to allow hostnames
                    ### in the config
                    if var in ['WG_CLIENT', 'WG_SERVER', 'DEFAULT_GW']:
                        try:
                            conf[var] = resolve(m.group(1))
                        except:
                            raise NameError("[*] Could not resolve %s '%s' to an IP address." \
                                    % (var, m.group(1)))
                    else:
                        conf[var] = m.group(1)
                    break
    if 'DEFAULT_GW' not in conf or 'PF_INTF' not in conf:
        gw, intf = get_default_gw()
        if 'DEFAULT_GW' not in conf:
            conf['DEFAULT_GW'] = gw
        if 'PF_INTF' not in conf:
            conf['PF_INTF'] = gw
    return

def display_config(config_file, cargs):
    print "\nDisplaying config: '%s'\n\n" % config_file
    with open(config_file, 'r') as f:
        for line in f:
            print line.rstrip()
    print
    return

def write_config(config_file, pf_config_file, pf_rules_file, cargs):

    def_gw = "# DEFAULT_GW        NA"
    if cargs.default_gw:
        def_gw = "DEFAULT_GW          %s" % cargs.default_gw

    enable_pf = "ENABLE_PF_POLICY    Y"
    if cargs.disable_pf_policy:
        enable_pf = "ENABLE_PF_POLICY    N"

    pf_intf = "# PF_INTF           NA"
    if cargs.default_gw:
        pf_intf = "PF_INTF          %s" % cargs.pf_interface

    with open(config_file, 'w') as f:
        f.write('''#
# Configuration file for the '%s' utility
#

# The WG_CLIENT IP is usually a local VM running Wireguard
WG_CLIENT           %s

# The WG_SERVER IP is the remote Internet-connected system running Wireguard.
# All traffic will be routed through this system.
WG_SERVER           %s

# Normally the default gateway is parsed from the local routing table and
# therefore does not need to be set here. It is only set if the --default-gw
# command line switch is used.
%s

# Control whether to add a default-drop PF policy for everything except
# Wireguard communications and DHCP traffic. The default is for this feature
# to be enabled, but this can be changed with the --disable-pf-policy command
# line argument. Also set the paths to the PF config and rules files.
%s
PF_CONFIG_FILE      %s
PF_RULES_FILE       %s

# Normally the interface to which PF rules are restricted is parsed from the
# default gateway route. However, it can be set manually with --pf-interface
# if necessary
%s
''' % (__file__, cargs.wg_client, cargs.wg_server, def_gw, enable_pf,
    pf_config_file, pf_rules_file, pf_intf))

    return

def write_pf_config(pf_config_file, pf_rules_file, cargs):

    with open(pf_config_file, 'w') as f:
        f.write('''#
# This file is auto-generated by the '%s' tool, and sets up a PF policy
# that restricts communications to go over Wireguard.
anchor "wg-pf.rules"
load anchor "wg-pf.rules" from "%s"
''' % (__file__, pf_rules_file))

    return

def write_pf_rules(pf_rules_file, cargs):

    if cargs.pf_interface:
        intf = cargs.pf_interface
    else:
        intf = get_default_gw()[1]

    with open(pf_rules_file, 'w') as f:
        f.write('''#
# This file is auto-generated by the '%s' tool, and sets up a PF policy
# that restricts communications to go over Wireguard.
WG_SERVER = "%s"
WG_PORT = "%s"
INTF = "%s"

block in log on $INTF all
block out log on $INTF all

# Allow DHCP
pass quick on $INTF inet proto tcp from any port 67:68 to any port 67:68 keep state flags S/SA
pass quick on $INTF inet proto udp from any port 67:68 to any port 67:68 keep state

# Restrict everything to Wireguard communications
pass out quick on $INTF inet proto udp from any to $WG_SERVER port $WG_PORT keep state

''' % (__file__, cargs.wg_server, cargs.wg_port, intf))

    return

def up_guidance(wg_client):
    print '''
With routing configured to send traffic to the Wireguard client system
'%s', it is usually necessary to add NAT rule in iptables along with
allowing IP forwarding. The NAT rule should translate incoming IP traffic
from the Mac to the Wireguard client IP assigned in the 'Address' line in
the Wireguard interface configuration file. The incoming traffic from the
Mac is normally the IP assigned to a virtual interface such as 'vnic0'.
E.g.:

[wgclientvm]# iptables -t nat -A POSTROUTING -s <vnic0_IP> -j SNAT --to <WG_client_IP>

[wgclientvm]# echo 1 > /proc/sys/net/ipv4/ip_forward
''' % wg_client
    return

def down_guidance(wg_client):
    print '''
Applicable routes and PF rules have been removed. The corresponding NAT rule and
IP forwarding configuration can (optionally) be removed from the '%s'
Wireguard client system.
''' % wg_client
    return

def pf_update(cmd, conf, config_file):

    if conf['ENABLE_PF_POLICY'] != 'Y':
        print "PF policy disabled in config file '%s', no action taken." % config_file
        return

    if cmd == 'up':
        pf_test_rules(conf)
        pfcmd = "pfctl -f %s" % conf['PF_CONFIG_FILE']
        print "Implementing default-drop PF policy via command: '%s'" % pfcmd
        run_cmd(pfcmd)
    else:
        ### restore original PF rules
        pfcmd = "pfctl -f /etc/pf.conf"
        print "Restoring original PF rules via command: '%s'" % pfcmd
        run_cmd(pfcmd)

    return

def pf_status(conf):

    if conf['ENABLE_PF_POLICY'] != 'Y':
        print "PF policy disabled in config file '%s', no available status." % config_file
        return

    ### first see if the wg-pf.rules anchor is active
    found_wg_anchor = False

    wg_anchor = 'wg-pf.rules'
    (es, out) = run_cmd("pfctl -sr")
    if es == 0:
        for line in out:
            if 'anchor' in line and wg_anchor in line:
                found_wg_anchor = True
                break

    if found_wg_anchor:
        (es, out) = run_cmd("pfctl -a %s -sr" % wg_anchor)

        if es == 0:
            for line in out:
                if 'block' in line or 'pass' in line:
                    print "Wireguard PF '%s' anchor rule active: '%s'" % (wg_anchor, line)
    else:
        print "No active Wireguard PF anchor '%s'" % wg_anchor
    return

def pf_test_rules(conf):
    cmd = "pfctl -n -f %s" % conf['PF_CONFIG_FILE']
    (es, out) = run_cmd(cmd)
    if es != 0:
        print "[*] pf_test_rules() error, CMD: %s" % cmd
        for line in out:
            print line
    return

def route_status(conf):

    ### 0/1                10.111.55.31       UGSc           52        0   vnic0
    ### 128.0/1            10.111.55.31       UGSc            1        0   vnic0
    ### 2.2.2.2            192.168.0.1        UGHS            1       88     en

    netstat_cmd = 'netstat -rn'

    found_h1 = False
    found_h2 = False
    found_gw = False
    for line in run_cmd(netstat_cmd)[1]:
        if re.search("^\s*0\/1\s+%s\s" % conf['WG_CLIENT'], line):
            found_h1 = line.rstrip()
        elif re.search("^\s*128\.0\/1\s+%s\s" % conf['WG_CLIENT'], line):
            found_h2 = line.rstrip()
        elif re.search("^\s*%s\s+%s\s" % (conf['WG_SERVER'], conf['DEFAULT_GW']), line):
            found_gw = line.rstrip()

    if found_h1:
        print "Wireguard client route active: '%s'" % found_h1
    else:
        print "No Wireguard client route '0/1 -> %s'" % conf['WG_CLIENT']
    if found_h2:
        print "Wireguard client route active: '%s'" % found_h2
    else:
        print "No Wireguard client route '128.0/1 -> %s'" % conf['WG_CLIENT']
    if found_gw:
        print "Wireguard server route active: '%s'" % found_gw
    else:
        print "No Wireguard server route '%s -> %s'" % (conf['WG_SERVER'],
                conf['DEFAULT_GW'])
    return

def route_update(rcmd, conf):

    ### route add 0.0.0.0/1 <wg_client>
    ### route add 128.0.0.0/1 <wg_client>
    ### route add <wg_server> <default_gw>

    ### route add 0.0.0.0/1 10.111.55.31
    ### route add 128.0.0.0/1 10.111.55.31
    ### route add 2.2.2.2 192.168.0.1

    update_cmd = 'add'
    if rcmd == 'down':
        update_cmd = 'delete'

    print
    for cmd in ["route %s 0.0.0.0/1 %s" % (update_cmd, conf['WG_CLIENT']),
            "route %s 128.0.0.0/1 %s" % (update_cmd, conf['WG_CLIENT']),
            "route %s %s %s" % (update_cmd, conf['WG_SERVER'], conf['DEFAULT_GW'])
        ]:
        print "Running cmd: '%s'" % cmd
        (es, out) = run_cmd(cmd)

        ### look for indications of errors not caught by the process
        ### exit status
        found_err = False
        if rcmd == 'up':
            ### # route add 0.0.0.0/1 10.111.55.31
            ### route: writing to routing socket: File exists
            ### add net 0.0.0.0: gateway 10.111.55.31: File exists
            for line in out:
                if 'File exists' in line:
                    found_err = True
                    break
        elif rcmd == 'down':
            for line in out:
                ### # route delete 0.0.0.0/1 10.111.55.31
                ### route: writing to routing socket: not in table
                ### delete net 0.0.0.0: gateway 10.111.55.31: not in table
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

def get_default_gw():

    gw    = ''
    flags = ''
    intf  = ''
    netstat_cmd = 'netstat -rn'

    ### parse 'netstat -rn' output on macOS to get the default (IPv4) gw
    ### Destination        Gateway            Flags        Refs      Use   Netif Expire
    ### default            192.168.0.1        UGSc           69        0     en0

    for line in run_cmd(netstat_cmd)[1]:
        m = re.search('default\s+((?:[0-2]?\d{1,2}\.){3}[0-2]?\d{1,2})\s+(\w+)\s+(?:\S+\s+){2}(\S+)', line)
        if m:
            gw    = m.group(1)
            flags = m.group(2)
            intf  = m.group(3)
            break

    if gw and flags:
        for flag in ['G', 'U']:
            if flag not in flags:
                raise NameError(
                    "[*] Default gateway '%s' does not have the '%s' flag, set --default-gw and --pf-interface" \
                            % (gw, flag))
    else:
        raise NameError(
            "[*] Could not parse default gateway from '%s' output, set --default-gw and --pf-interface" \
                    % netstat_cmd)

    return gw, intf

def run_cmd(cmd):
    out = []

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
    p.add_argument("--wg-port", type=str,
            help="Set the UDP port number that is used in the Wireguard configuration",
            default=False)
    p.add_argument("--default-gw", type=str,
            help="Manually set the IPv4 default gw (normally parsed from the routing table)",
            default=False)

    p.add_argument("--disable-pf-policy", action='store_true',
            help="Do not create a default-drop PF policy for all except Wireguard communications",
            default=False)
    p.add_argument("--pf-config-file", type=str,
            help="Set the path to the PF config file (default: ~/.wg-pf.conf)",
            default=False)
    p.add_argument("--pf-rules-file", type=str,
            help="Set the path to the PF rules file (default: ~/.wg-pf.rules)",
            default=False)
    p.add_argument("--pf-interface", type=str,
            help="Set the interface for PF rules (normally parsed from the default gw route)",
            default=False)

    p.add_argument("--list", action='store_true',
            help="List the current configuration parameters", default=False)
    p.add_argument("--setup", action='store_true',
            help="Write the --wg-server, --wg-client, and (optional) --default-gw to the config file",
            default=False)

    p.add_argument("-c", "--config-file", type=str,
            help="Specify the path to the config file (defaults to ~/.wg-routes.conf)",
            default=False)

    p.add_argument("-v", "--verbose", action='store_true',
            help="Verbose mode", default=False)
    p.add_argument("-V", "--version", action='store_true',
            help="Print version and exit", default=False)

    return p.parse_args()

if __name__ == "__main__":
    sys.exit(main())
