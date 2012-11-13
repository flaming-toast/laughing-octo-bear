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
    for line in fileinput.input('/root/pox/ext/monitored-strings.txt'):
        temp = str(line.rstrip())
        address, search_string = temp.split(':')
        
        
        
        
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
        
        
      
    
    log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
    event.action.forward = True
  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
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
    pass
