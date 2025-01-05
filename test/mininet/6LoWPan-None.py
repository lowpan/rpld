#!/usr/bin/env python

import sys

from mininet.log import setLogLevel, info
from mn_wifi.sixLoWPAN.link import LoWPAN
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi

"""This example creates a simple network topology with 4 nodes

       sensor1 (root)
      /       \
    /          \
sensor2      sensor3
               |
               |
             sensor4
"""


def topology():
    "Create a network."
    net = Mininet_wifi(iot_module='mac802154_hwsim')
    info("*** Creating nodes\n")
    
    sensor1 = net.addSensor('sensor1', ip6='fe80::1/64', panid='0xbeef',
                            dodag_root=True, storing_mode=2)
    
    sensor2 = net.addSensor('sensor2', ip6='fe80::2/64', panid='0xbeef',
                            storing_mode=2)

    info("*** Configuring nodes\n")
    net.configureNodes()

    info("*** Adding links\n")
    net.addLink(sensor1, sensor2, cls=LoWPAN)

    info("*** Starting network\n")
    net.build()

    if '-r' in sys.argv:
        info("*** Configuring RPLD\n")
        net.configRPLD(net.sensors)

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
