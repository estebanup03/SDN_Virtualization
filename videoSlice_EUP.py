'''
Coursera:
- Software Defined Networking (SDN) course
-- Network Virtualization

Professor: Nick Feamster
Teaching Assistant: Arpit Gupta
'''

"""#######################################################################################################################################
  ______     _       _                   _    _      _ _            _____ _          _           _     _ _        
 |  ____|   | |     | |                 | |  | |    (_) |          |  __ (_)        | |         | |   (_) |       
 | |__   ___| |_ ___| |__   __ _ _ __   | |  | |_ __ _| |__   ___  | |__) |  ___  __| |_ __ __ _| |__  _| |_ __ _ 
 |  __| / __| __/ _ \ '_ \ / _` | '_ \  | |  | | '__| | '_ \ / _ \ |  ___/ |/ _ \/ _` | '__/ _` | '_ \| | __/ _` |
 | |____\__ \ ||  __/ |_) | (_| | | | | | |__| | |  | | |_) |  __/ | |   | |  __/ (_| | | | (_| | | | | | || (_| |
 |______|___/\__\___|_.__/ \__,_|_| |_|  \____/|_|  |_|_.__/ \___| |_|   |_|\___|\__,_|_|  \__,_|_| |_|_|\__\__,_|


						   _____ _____  _   _   ___   ___ ___   ___       _____ _____ 
						  / ____|  __ \| \ | | |__ \ / _ \__ \ / _ \     |_   _|_   _|
						 | (___ | |  | |  \| |    ) | | | | ) | | | |______| |   | |  
						  \___ \| |  | | . ` |   / /| | | |/ /| | | |______| |   | |  
						  ____) | |__| | |\  |  / /_| |_| / /_| |_| |     _| |_ _| |_ 
						 |_____/|_____/|_| \_| |____|\___/____|\___/     |_____|_____|

####################################################################################################################################															  

 ____ ____ ____ ____ ____ ____ ____ _________ ____ ____ ____ ____ ____ ____ ____ ____ _________ _____
||M |||I |||N |||I |||N |||E |||T |||       |||H |||O |||M |||E |||W |||O |||R |||K |||       |||III ||
||__|||__|||__|||__|||__|||__|||__|||_______|||__|||__|||__|||__|||__|||__|||__|||__|||_______|||____||
|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/_______\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/_______\|/____\|

####################################################################################################################################
"""

from pox.core import core
from collections import defaultdict

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
from collections import namedtuple
import os

log = core.getLogger()


class VideoSlice (EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)

        # Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
        self.adjacency = defaultdict(lambda:defaultdict(lambda:None))
        
        '''
        The structure of self.portmap is a four-tuple key and a string value.
        The type is:
        (dpid string, src MAC addr, dst MAC addr, port (int)) -> dpid of next switch
        '''
        s1 = '00-00-00-00-00-01'
        s2 = '00-00-00-00-00-02'
        s3 = '00-00-00-00-00-03'
        s4 = '00-00-00-00-00-04'
        h1 = '00:00:00:00:00:01'
        h2 = '00:00:00:00:00:02'
        h3 = '00:00:00:00:00:03'
        h4 = '00:00:00:00:00:04'

        self.portmap = { 
                        (s1, EthAddr(h1), EthAddr(h3), 80): s3,
                        (s3, EthAddr(h1), EthAddr(h3), 80): s4,
                        (s1, EthAddr(h1), EthAddr(h4), 80): s3,
                        (s3, EthAddr(h1), EthAddr(h4), 80): s4,
                        (s1, EthAddr(h2), EthAddr(h3), 80): s3,
                        (s3, EthAddr(h2), EthAddr(h3), 80): s4,
                        (s1, EthAddr(h2), EthAddr(h4), 80): s3,
                        (s3, EthAddr(h2), EthAddr(h4), 80): s4,
                        (s4, EthAddr(h3), EthAddr(h1), 80): s3,
                        (s3, EthAddr(h3), EthAddr(h1), 80): s1,
                        (s4, EthAddr(h3), EthAddr(h2), 80): s3,
                        (s4, EthAddr(h3), EthAddr(h2), 80): s1,
                        (s3, EthAddr(h4), EthAddr(h1), 80): s3,
                        (s4, EthAddr(h4), EthAddr(h1), 80): s1,
                        (s3, EthAddr(h4), EthAddr(h2), 80): s3,
                        (s4, EthAddr(h4), EthAddr(h2), 80): s1,

        }

    def _handle_LinkEvent (self, event):
        l = event.link
        sw1 = dpid_to_str(l.dpid1)
        sw2 = dpid_to_str(l.dpid2)

        log.debug ("link %s[%d] <-> %s[%d]",
                   sw1, l.port1,
                   sw2, l.port2)

        self.adjacency[sw1][sw2] = l.port1
        self.adjacency[sw2][sw1] = l.port2


    def _handle_PacketIn (self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """
        packet = event.parsed
        tcpp = event.parsed.find('tcp')

        def install_fwdrule(event,packet,outport):
            msg = of.ofp_flow_mod()
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.actions.append(of.ofp_action_output(port = outport))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        def forward (message = None):
            s1 = "00-00-00-00-00-01"
            s2 = "00-00-00-00-00-02"
            s3 = "00-00-00-00-00-03"
            s4 = "00-00-00-00-00-04"
            h1 = EthAddr('00:00:00:00:00:01')
            h2 = EthAddr('00:00:00:00:00:02')
            h3 = EthAddr('00:00:00:00:00:03')
            h4 = EthAddr('00:00:00:00:00:04')
            this_dpid = dpid_to_str(event.dpid)

            if packet.dst.is_multicast:
                flood()
                return
            else:
                log.debug("Got unicast packet for %s at %s (input port %d):",
                          packet.dst, dpid_to_str(event.dpid), event.port)
                try:
                    """ Add your logic here """
                    out_port = 'N/A'
                    if this_dpid == s1:                         #Se ejecuta lógica por switch
                        if tcpp.dstport == 80 and (packet.dst != h1 and packet.dst != h2):   # Todo el trafico que tenga como destino el puerto 80 tiene que ir al otro lado de la red
                            out_port = 2
                        elif packet.dst == h2:                                               # Trafico destinado hacia h2
                            out_port = 4
                        elif packet.dst == h1:
                            out_port = 3
                        elif packet.dst == h3 or packet.dst == h4:
                            out_port = 1
                    elif this_dpid == s3:
                        if packet.dst == h1 or packet.dst == h2:
                            out_port = 1
                        elif packet.dst == h3 or packet.dst == h4:
                            out_port = 2
                    elif this_dpid == s2:
                        if packet.dst == h1 or packet.dst == h2:
                            out_port = 1
                        elif packet.dst == h3 or packet.dst == h4:
                            out_port = 2
                    elif this_dpid == s4:
                        if tcpp.dstport == 80 and (packet.dst != h3 and packet.dst != h4):
                            out_port = 2
                        elif packet.dst == h1 or packet.dst == h2:
                            out_port = 1
                        elif packet.dst == h4:
                            out_port = 4
                        elif packet.dst == h3:
                            out_port = 3
                    install_fwdrule(event,packet,out_port)
                    log.debug("Switch %s forwards packet incoming from port %s to port %s ", this_dpid, event.port, out_port)
                except AttributeError:
                    log.debug("packet type has no transport ports, flooding")

                    # flood and install the flow table entry for the flood
                    install_fwdrule(event,packet,of.OFPP_FLOOD)

        # flood, but don't install the rule
        def flood (message = None):
            """ Floods the packet """
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        forward()


    def _handle_ConnectionUp(self, event):
        dpid = dpidToStr(event.dpid)
        log.debug("Switch %s has come up.", dpid)
        

def launch():
    # Run spanning tree so that we can deal with topologies with loops
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    '''
    Starting the Video Slicing module
    '''
    core.registerNew(VideoSlice)
