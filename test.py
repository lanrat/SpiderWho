#/usr/bin/python
import sys
#from pywhois.whois.parser import WhoisEntry
#from pywhois.whois.whois import NICClient
from proxywhois import NICClient
#import socket

import threading

#for testing
import time

class ThreadClass(threading.Thread):
  def __init__(self,proxy,port,domain):
    threading.Thread.__init__(self)
    self.client = NICClient()
    #TODO add better roxy type handling
    self.client.set_proxy(self.client.PROXY_TYPE_HTTP,proxy,port)
    #TODO move out of here
    self.domain = domain

  def whois(self,domain):
    #always use the native python client
    #time.sleep(5)
    #whoisClient = NICClient(self.socks.socksocket);
    text = self.client.whois_lookup(None, domain, 0) #what do these do?
    return text

  def run(self):
    #self.socks.setdefaultproxy(self.socks.PROXY_TYPE_HTTP,self.proxy,self.port)
    time.sleep(2)
    var = self.whois(self.domain)

    print var


if __name__ == '__main__':
  #print(whois(sys.argv[1]))
  t1.start()
  t2.start()

