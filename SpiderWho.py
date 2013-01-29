#!/usr/bin/env python
import Queue
import sys
from proxywhois import NICClient
import threading
import time

class WhoisThread(threading.Thread):
  def __init__(self,proxy,port,queue):
    threading.Thread.__init__(self)
    self.client = NICClient()
    #TODO add better roxy type handling
    self.client.set_proxy(self.client.PROXY_TYPE_HTTP,proxy,port)
    self.queue = queue

  def whois(self,domain):
    #always use the native python client
    text = self.client.whois_lookup(None, domain, 0) #what do these do?
    return text

  #TODO write this
  def save_data(self,domain,text):
    #save to a file
    print text
    return

  def run(self):
    while True:
      #get next host
      domain = self.queue.get()

      #TOOD rm
      print "WHOIS: " + domain
    
      data = self.whois(domain)
      self.save_data(domain,data)

      #inform the queue we are done
      self.queue.task_done()

      time.sleep(20) #update this


if __name__ == '__main__':
  """main"""
  if not len(sys.argv) == 3:
    print "usage: " + sys.argv[0] + " proxy_list domain_list"
    exit()
  
  q = Queue.Queue()
  i = 0
  print "Starting threads.."
  for l in open(sys.argv[1],'r'):
      if l[0] != '#':
        s = l.split()
        if len(s) == 2:
          #TODO validate!
          t = WhoisThread(s[0],int(s[1]),q)
          t.setDaemon(True)
          t.start()
          i += 1
  print str(i) + " threads started"

  print "adding domains to queue"
  i = 0
  for l in open(sys.argv[2],'r'):
    q.put(l.strip())
    i += 1
  print "done " + str(i) +" domains in queue"

  print "All threads running"
  while threading.active_count() > 0:
      time.sleep(0.1)
  #q.join()
  print "Done!"

