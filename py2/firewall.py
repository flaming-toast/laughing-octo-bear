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
    self.ftpAddress = {}
    log.debug("Firewall initialized.")

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    if int(flow.dstport) >= 0 and int(flow.dstport) <= 1023:
      if int(flow.dstport) == 21:
          log.debug("ftp connection")
          event.action.monitor_forward = True
          event.action.monitor_backward = True
          return
      log.debug("Allowed connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
      event.action.forward = True
    else:
        if self.ftpAddress.has_key(str(flow.dst)):
            if int(flow.dstport) in self.ftpAddress[str(flow.dst)]:
                # set timer
                event.action.forward = True
        

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
    if srcport == 21:
        if "229" in data[:3]:
            temp = data.split(" ")
            temp1 = temp[5].split("|")
            port = int(temp1[3])
            if self.ftpAddress.has_key(srcip):
                if port not in self.ftpAddress[srcip]:
                    self.ftpAddress[srcip].append(port)
                # set timer
            else:
                self.ftpAddress[srcip] = []
                self.ftpAddress[srcip].append(port)
                # set timer
            log.debug(self.ftpAddress)
        if "227" in data[:3]:
            p = re.compile('\d+')
            octet1 = p.findall(data)[5]
            octet2 = p.findall(data)[6]
            portnum = int(octet1)*256 + int(octet2)
            if self.ftpAddress.has_key(srcip):
                if portnum not in self.ftpAddress[srcip]:
                    self.ftpAddress[srcip].append(portnum)
                # set timer
            else:
                self.ftpAddress[srcip] = []
                self.ftpAddress[srcip].append(portnum)
                # set timer
            log.debug(self.ftpAddress)    
            
            
    
    #log.debug("Monitored connection [" + srcip + ":"+ str(srcport) + "," + dstip + ":" + str(dstport))
    event.action.forward = True
    pass
