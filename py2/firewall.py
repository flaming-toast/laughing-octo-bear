from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import *
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
    self.ftpAddress = {} # Key: Destaddress, Value: List of allowed ports
    self.timers = {} # key: (Destaddress, dataPorts), Value: Timer
    log.debug("Firewall initialized.")
    self.packet_string = "" # find FTP response code 227 or 229

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    if int(flow.dstport) >= 0 and int(flow.dstport) <= 1023:
      if int(flow.dstport) == 21:
          log.debug("ftp connection")
          event.action.monitor_backward = True
          return
      log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
      event.action.forward = True
    else:
        if self.ftpAddress.has_key(str(flow.dst)):
            if int(flow.dstport) in self.ftpAddress[str(flow.dst)]:
                if self.timers.has_key((str(flow.dst), int(flow.dstport))):
                    self.timers[(str(flow.dst), int(flow.dstport))].cancel()
                    del self.timers[(str(flow.dst), int(flow.dstport))]
                self.ftpAddress[str(flow.dst)].remove(int(flow.dstport))
                event.action.forward = True
                log.debug("ftp data connection established on port: " + str(flow.dstport))
                log.debug(self.ftpAddress)
                return
        event.action.deny = True
        

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
    pass
    
  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    srcport = packet.payload.payload.srcport # srcport in TCP Header
    dstport = packet.payload.payload.dstport # dstport in TCP Header
    srcport = int(srcport)
    dstport = int(dstport)
    srcip = packet.payload.srcip 
    srcip = str(srcip)
    dstip = packet.payload.dstip
    dstip = str(dstip)
    data = str(packet.payload.payload.payload)
   
# process packets and find 227/229 response, account for fragmented packets.
    match = re.match('\s*(22[79])\s*', data) # search the packet. If there's 227 or 229 we are interested in it.
    if match: 
	self.response = match.group() # save captured response code
	log.debug("FOUND RESPONSE: " + self.response)
	self.search_flag = True
	self.packet_string += data # dump the packet into the temporary string
	# inspect the temporary string, find the newlines

    if (self.search_flag): 
	if (re.search('[\r\n]*', data[data.find(self.response):])):
		log.debug("PACKET STRING: " + self.packet_string) 
		self.packet_string = "" # reset the string
		self.search_flag = False
        else: # we didn't find the newline after the response code, keep appending
		self.packet_string += data
		
    if srcport == 21:
        if "229" in data[:3]:
            log.debug(data)
            p = re.compile('\d+')
            numbers = p.findall(data)
            portnum = int(numbers[len(numbers)-1])
            if self.ftpAddress.has_key(srcip):
                self.ftpAddress[srcip].append(portnum)
            else:
                self.ftpAddress[srcip]= []
                self.ftpAddress[srcip].append(portnum)
            self.setTimer(srcip, portnum)
            log.debug(self.ftpAddress)
            log.debug("229 successful")
        if "227" in data[:3]:
            p = re.compile('\d+')
            numbers = p.findall(data)
            log.debug(numbers)
            octet1 = p.findall(data)[-2]
            octet2 = p.findall(data)[-1]
            portnum = int(octet1)*256 + int(octet2)
            if self.ftpAddress.has_key(srcip):
                self.ftpAddress[srcip].append(portnum)
            else:
                self.ftpAddress[srcip]= []
                self.ftpAddress[srcip].append(portnum)
            self.setTimer(srcip, portnum)
            log.debug(self.ftpAddress)
            log.debug("227 successful")
	
    event.action.forward = True
    #log.debug("Monitored connection [" + srcip + ":"+ str(srcport) + "," + dstip + ":" + str(dstport))
    
    
    
  def setTimer(self, destAddress, dataPort):
     if self.timers.has_key((destAddress, dataPort)):
         self.timers[(destAddress, dataPort)].cancel()
         self.timers[(destAddress, dataPort)] = Timer(10.0, self.timeoutFunc, args=(destAddress, dataPort))
     else:
         self.timers[(destAddress, dataPort)] = Timer(10.0, self.timeoutFunc, args=(destAddress, dataPort))
         

  def timeoutFunc(self, destAddress, dataPort):
      if self.timers.has_key((destAddress, dataPort)):
          del self.timers[(destAddress, dataPort)]
      if self.ftpAddress.has_key(destAddress):
          if dataPort in self.ftpAddress[destAddress]:
              self.ftpAddress[destAddress].remove(dataPort)
      log.debug(self.ftpAddress)
      log.debug("timed-out")
      
    

