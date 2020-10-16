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


class TopologySlice (EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        log.debug("Enabling Slicing Module")
        
        
    """This event will be raised each time a switch will connect to the controller"""
    def _handle_ConnectionUp(self, event):
        
        # Use dpid to differentiate between switches (datapath-id)
        # Each switch has its own flow table. As we'll see in this 
        # example we need to write different rules in different tables.
        dpid = dpidToStr(event.dpid)
        log.debug("Switch %s has come up.", dpid)
        """ Add your logic here """
        """Reglas: Cada par significa puerto de entrada y puerto de salida que corresponden a un mismo Slice"""
        rules = {
            's1': [[1, 3], [2, 4]],
            's2': [1, 2],
            's3': [1, 2],
            's4': [[1, 3], [2, 4]]
        }
        msg = of.ofp_flow_mod()
        if dpid == "00-00-00-00-00-01": #Si es el switch 1 instale las siguientes reglas
            log.debug("Implementing rules for %s.", dpid) #Mensaje para avisar que esta colocando las reglas para el switch
            for v in rules['s1']:                           #For para recorrer la cantidad de pares que hayan
                in_port = v[0]                              #Asignacion de variables para facilidad de lectura
                out_port = v[1]                             #Asignacion de variables para facilidad de lectura
                msg.match.in_port = in_port                 #Condicion de match en el mensaje a enviar al switch
                msg.actions.append(of.ofp_action_output(port=out_port)) #Accion para sacar el paquete por el puerto de salida si hace match con el puerto de entrada
                log.debug('Rules for in port %s and out port %s',in_port,out_port) #Mostrar en pantalla lo que va a enviar al switch
                event.connection.send(msg)                  #Enviar el mensaje el switch
                msg = of.ofp_flow_mod()                     #Limpiar el mensaje, con el append quedaba con varios puertos de salida y no funcionaba
                msg.match.in_port = out_port                #Se crea la regla inversa para que haya conectividad bidireccional
                msg.actions.append(of.ofp_action_output(port=in_port))              #Accion
                log.debug('Rules for in port %s and out port %s', out_port,in_port)  # Mostrar en pantalla lo que va a enviar al switch
                event.connection.send(msg)
        elif dpid == "00-00-00-00-00-02":
            log.debug("Implementing rules for %s.", dpid)
            in_port = rules['s2'][0]
            out_port = rules['s2'][1]
            msg.match.in_port = in_port
            msg.actions.append(of.ofp_action_output(port=out_port))
            log.debug('Rules for in port %s and out port %s',in_port,out_port) #Mostrar en pantalla lo que va a enviar al switch
            event.connection.send(msg)
            msg = of.ofp_flow_mod()
            msg.match.in_port = out_port
            msg.actions.append(of.ofp_action_output(port=in_port))
            log.debug('Rules for in port %s and out port %s',out_port,in_port) #Mostrar en pantalla lo que va a enviar al switch
            event.connection.send(msg)
        elif dpid == "00-00-00-00-00-03":
            log.debug("Implementing rules for %s.", dpid)
            in_port = rules['s3'][0]
            out_port = rules['s3'][1]
            msg.match.in_port = in_port
            msg.actions.append(of.ofp_action_output(port=out_port))
            log.debug('Rules for in port %s and out port %s',in_port,out_port) #Mostrar en pantalla lo que va a enviar al switch
            event.connection.send(msg)
            msg = of.ofp_flow_mod()
            msg.match.in_port = out_port
            msg.actions.append(of.ofp_action_output(port=in_port))
            log.debug('Rules for in port %s and out port %s',out_port,in_port) #Mostrar en pantalla lo que va a enviar al switch
            event.connection.send(msg)
        elif dpid == "00-00-00-00-00-04":
            for v in rules['s1']:
                in_port = v[0]
                out_port = v[1]
                msg.match.in_port = in_port
                msg.actions.append(of.ofp_action_output(port=out_port))
                log.debug('Rules for in port %s and out port %s',in_port,out_port) #Mostrar en pantalla lo que va a enviar al switch
                event.connection.send(msg)
                msg = of.ofp_flow_mod()
                msg.match.in_port = out_port
                msg.actions.append(of.ofp_action_output(port=in_port))
                log.debug('Rules for in port %s and out port %s',out_port,in_port) #Mostrar en pantalla lo que va a enviar al switch
                event.connection.send(msg)
                msg = of.ofp_flow_mod()

def launch():
    # Run spanning tree so that we can deal with topologies with loops
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    '''
    Starting the Topology Slicing module
    '''
    core.registerNew(TopologySlice)
