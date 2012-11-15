from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
import fileinput
import re
# Get a logger
log = core.getLogger("fw")

class Firewall (object):
  """
  Firewall class.
  Extend this to implement some firewall functionality.
  Don't change the name or anything -- the eecore component
  expects it to be firewall.Firewall.
  """
  def __init__(self):
    """
    Constructor.
    Put your initialization code here.
    """
    self.banned_ports = set()
    for line in fileinput.input('/root/pox/ext/banned-ports.txt'):
        portNumber = int(line.rstrip())
        log.debug(portNumber)
        self.banned_ports.add(portNumber)
    self.banned_domains = set()
    for line in fileinput.input('/root/pox/ext/banned-domains.txt'):
        domain = str(line.rstrip()) # Return a copy of the string with trailing characters removed. 
        log.debug(domain)
        self.banned_domains.add(domain)
    self.monitered_strings = set()
    for line in fileinput.input('/root/pox/ext/monitored-strings.txt'):
        temp = str(line.rstrip())
        address, search_string = temp.split(':')
        address = str(address)
        search_string = str(search_string)
        log.debug(address + ':' + search_string)
        self.monitered_strings.add((address, search_string))
    self.counts = dict() # key: (address, search_string, port), value: number of times the search_string appears
    self.countsIncomingbuffer = dict() # key: (address, port), value: string (initialized to empty string) 
    self.countsOutgoingbuffer = dict() # key: (address, port), value: string (initialized to empty string)
    self.countsBuffetSize = dict() # key: address, value: len(LongestString) -1
    log.debug("Firewall initialized.")
    
  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    if flow.dstport in self.banned_ports:
        log.debug("Denied Connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.deny = True
        return
    if flow.dstport == 80:
        log.debug("Deferred connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.defer = True
        return
    forward = True
    dst_address = str(flow.dst) # the IP Address for destination
    longestString = 0
    for address, search_string in self.monitered_strings:
        if dst_address == address:
            log.debug(address + ':' + search_string + ":" + str(flow.dstport))
            self.counts[(address, search_string, int(flow.dstport))] = 0
            if len(search_string)>longestString:
                longestString = len(search_string)
                self.countsBuffetSize[address] = longestString -1
            forward = False
            
    if forward:
        log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.forward = True
        return
    else:
        log.debug("Deferred connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.defer = True
            
    
        
        
      
    
  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    """ check for monitored string data here"""
    for monitored_address, search_string in self.monitered_strings:
        if flow.dst == monitored_address:
            log.debug("Monitored outgoing connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
            event.action.monitor_forward = True
            return
        if flow.src == monitored_address:
            log.debug("Monitored incoming connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
            event.action.monitor_backward = True
            return
    """ check for banned_domains here"""
    forward = True
    log.debug("handle deferred connection")
    user=re.compile("Host: (.*?)\r") # consulted from http://stackoverflow.com/questions/10832974/python-regular-expression-for-http-request-header
    host = user.findall(packet.payload.payload.payload)
    if (host[0] in self.banned_domains):
        log.debug(host[0])
        forward = False
    for banned_domains in self.banned_domains:
        if banned_domains in host[0]:
            log.debug(host[0])
            forward = False 
    if forward:
        log.debug("Allowed Connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.forward = True
    else:
        log.debug("Denied Connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.deny = True
    
    
  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    """ for every port in every pair of src_destination, we need a buffer for income and another for outgoing"""
    if reverse:
        
        
    
    
    
    pass
