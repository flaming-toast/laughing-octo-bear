from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
import fileinput
import re
from pox.lib.recoco.recoco import *
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
    self.monitered_strings = set() # (address, search_string)
    for line in fileinput.input('/root/pox/ext/monitored-strings.txt'):
        temp = str(line.rstrip())
        address, search_string = temp.split(':')
        address = str(address)
        search_string = str(search_string)
        log.debug(address + ':' + search_string)
        self.monitered_strings.add((address, search_string))
    self.counts = dict() # key: (address, search_string, dstport), value: number of times the search_string appears
    self.countsIncomingbuffer = dict() # key: (address, srcport, dstport), value: string (initialized to empty string) 
    self.countsOutgoingbuffer = dict() # key: (address, srcport, dstport), value: string (initialized to empty string)
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
            self.countsIncomingbuffer[(address, int(flow.srcport), int(flow.dstport))] = ""
            self.countsOutgoingbuffer[(address, int(flow.srcport), int(flow.dstport))] = ""
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
        log.debug("Allowed Connection2 [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        for monitored_address, search_string in self.monitered_strings:
            if str(flow.dst) == monitored_address:
                log.debug(str(flow.dst))
                event.action.monitor_forward = True
                event.action.monitor_backward = True
        event.action.forward = True
    else:
        log.debug("Denied Connection2 [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        event.action.deny = True
    
    
  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    """ for every port in every pair of src_destination, we need a buffer for income and another for outgoing"""
    
    # timer = Timer(10, writeToFile, "hello")
    
    srcport = packet.payload.payload.srcport # srcport in TCP Header
    dstport = packet.payload.payload.dstport # dstport in TCP Header
    srcport = int(srcport)
    dstport = int(dstport)
    srcip = packet.payload.srcip 
    srcip = str(srcip)
    dstip = packet.payload.dstip
    dstip = str(dstip)
    data = str(packet.payload.payload.payload)
    
    if reverse: # for incoming packet/data
        buffered = str(self.countsIncomingbuffer[(srcip, srcport, dstport)])
        data = buffered + data
        for ip, search_string in self.monitered_strings:
            if ip == srcip:
                number = data.find(search_string)
                self.counts[(ip, search_string, srcport)] += number
        for ip, search_string in self.monitered_strings:
            if ip == srcip:
                number = buffered.find(search_string)
                self.counts[(ip, search_string, srcport)] -= number
        bufferLength = self.countsBuffetSize[srcip]
        bufferedData = data[len(data)-bufferLength:len(data)]
        self.countsIncomingbuffer[(srcip, srcport, dstport)] = bufferedData
    else: # for outgoing packet/data
        buffered = str(self.countsOutgoingbuffer[(dstip, srcport, dstport)])
        data = buffered + data
        for ip, search_string in self.monitered_strings:
            if ip == srcip:
                number = data.find(search_string)
                self.counts[(ip, search_string, dstport)] += number
        for ip, search_string in self.monitered_strings:
            if ip == srcip:
                number = buffered.find(search_string)
                self.counts[(ip, search_string, dstport)] -= number
        bufferLength = self.countsBuffetSize[dstip]
        bufferedData = data[len(data)-bufferLength:len(data)]
        self.countsOutgoingbuffer[(dstip, srcport, dstport)] = bufferedData


    
    
    def writeToFile(message):
        log.debug("Timer is off!!!!!")
        
        pass
    
        
    
    

