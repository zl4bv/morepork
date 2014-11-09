#! /usr/bin/python
"""Vandervecken controlled Mininet example

   host --- switch --- host

with the switch controlled by an OpenFlow controller (Vandervecken) that
acts as a router.

For Python API see: http://mininet.org/api/annotated.html

Note that the defaultRoute paramter is appended to 'ip route add default',
so needs to be in 'ip' syntax; if it is a single word then it is assumed
to be an interface (ie, 'ip route add default dev PARAM' is run).  See
comments on Node.setDefaultRoute().

Also note that Mininet always brings up the Open vSwitch in OpenFlow 1.0
mode (AFAICT); there is a patch to MiniNet to allow specifying "protocols="
on the switch, but it doesn't seem to have been integrated:

https://groups.google.com/a/openflowhub.org/forum/#!topic/floodlight-dev/Z5l7-qgSuVc

People are using:

sudo ovs-vsctl set bridge s1 protocols=OpenFlow13

from the command line.

Written by Ewen McNeill <ewen2naos.co.nz>, 2014-07-17

Adapted by Ben Vidulich <ben@vidulich.co.nz>, 2014-10-28
"""

import datetime
import os
import re
import sys
import subprocess
import time
import threading

from mininet.net  import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo
from mininet.link import Intf
from mininet.log  import setLogLevel
from mininet.cli  import CLI
from mininet.util import run

setLogLevel('info')
#setLogLevel('debug')    # For diagnostics

def checkIntf( intf ):
    "Make sure intf exists and is not configured."
    if ( ' %s:' % intf ) not in quietRun( 'ip link show' ):
        error( 'Error:', intf, 'does not exist!\n' )
        exit( 1 )
    ips = re.findall( r'\d+\.\d+\.\d+\.\d+', quietRun( 'ifconfig ' + intf ) )
    if ips:
        error( 'Error:', intf, 'has an IP address,'
               'and is probably in use!\n' )
        exit( 1 )

class IdsThread(threading.Thread):

    def __init__(self):
        super(IdsThread, self).__init__()
        self.p = None

    def run(self):
        self.p = subprocess.Popen(['ssh', '-i/home/ben/.ssh/id_rsa', 'ben@192.168.0.152', '/home/ben/ids.py'])

    def stop(self):
        if self.p:
            self.p.terminate()

class MeasurementThread(threading.Thread):

    port_stats_file = 'port-stats-%s.csv'

    def __init__(self, switch):
        super(MeasurementThread, self).__init__()
        self.switch = switch
        self._stop = threading.Event()

        if 'TAG' in os.environ:
            self.tag = os.environ['TAG']
        else:
            self.tag = ''

        self.dump_pattern = re.compile(r'port\s+(?P<port>.*): rx pkts=(?P<rx_pkts>\d+), bytes=(?P<rx_bytes>\d+), drop=(?P<rx_drop>\d+), errs=(?P<rx_errs>\d+), frame=(?P<rx_frame>\d+), over=(?P<rx_over>\d+), crc=(?P<rx_crc>\d+)\r\n\s+tx pkts=(?P<tx_pkts>\d+), bytes=(?P<tx_bytes>\d+), drop=(?P<tx_drop>\d+), errs=(?P<tx_errs>\d+), coll=(?P<tx_coll>\d+)')

        t = datetime.datetime.today()
        self.start_time = int(t.strftime('%s'))
        self.port_stats_file = self.port_stats_file % self.start_time

        if not os.path.isfile(self.port_stats_file):
            with open(self.port_stats_file, 'w') as myfile:
                myfile.write("duration_sec,tag,port,rx_bytes,rx_pkts,tx_bytes,tx_pkts\n")

    def run(self):
        while not self.stopped():
            time.sleep(1)
            t = datetime.datetime.today()
            now = int(t.strftime('%s'))
            duration = now - self.start_time
            dump = self.switch.dpctl('dump-ports')
            matches = [m.groupdict() for m in re.finditer(self.dump_pattern, dump)]
            with open(self.port_stats_file, 'a') as myfile:
                for m in matches:
                    myfile.write("%s,%s,%s,%s,%s,%s,%s\n" % (duration, self.tag, m['port'], m['rx_bytes'], m['rx_pkts'], m['tx_bytes'], m['tx_pkts']))

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()

class MoreporkOneSwitch(Topo):
    "Morepork One Switch example topology"

    def __init__(self):
        super(MoreporkOneSwitch, self).__init__()

        # Add hosts and switches
        self.srcHost  = self.addHost('h1', ip='10.0.0.1' )
        self.dstHost = self.addHost('h2', ip='10.0.0.2' )
        oneSwitch = self.addSwitch('s1', dpid='0000000000000099',
                                   listenPort=6634,
                                   protocols='OpenFlow13' )

        # Add links
        self.addLink( self.srcHost, oneSwitch )
        self.addLink( oneSwitch, self.dstHost )

# try to get hw intf from the command line; by default, use eth0
intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'eth0'

sw = MoreporkOneSwitch()
ryu = RemoteController('ryu', ip='127.0.0.1', port=6633 )
net = Mininet(topo=sw, switch=OVSSwitch, build=False)
net.addController(ryu)
net.build()

# Add physical interface
switch = net.switches[ 0 ]
_intf = Intf( 'eth0', node=switch )
_intf2 = Intf( 'eth2', node=switch )

net.start()
run("ovs-vsctl set bridge s1 protocols=OpenFlow10,OpenFlow13")

thread1 = MeasurementThread(switch)
thread1.daemon = True
thread1.start()

thread2 = IdsThread()
thread2.daemon = True
thread2.start()

print 'Warming up...'
time.sleep(30)
print 'Beginning attack...'
dstHost, srcHost = net.getNodeByName('h1', 'h2')
dstHost.cmd('iperf -s -p 53 -u &')
srcHost.cmd('iperf -c ', dstHost.IP(), ' -p 53 -u -t 120') # Run for 2 minutes
print 'Attack complete...'
time.sleep(30)
print 'Cool-down complete...'

thread1.stop()
thread2.stop()
net.stop()
thread1.join(1.0)
thread2.join(1.0)