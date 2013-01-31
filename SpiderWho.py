#!/usr/bin/env python
import Queue
import sys
#from proxywhois import NICClient
import proxywhois
import threading
import time

class WhoisThread(threading.Thread):
  def __init__(self,proxy,port,queue,fail):
    threading.Thread.__init__(self)
    self.client = proxywhois.NICClient()
    #TODO add better proxy type handling
    self.client.set_proxy(proxywhois.socks.PROXY_TYPE_HTTP,proxy,port)
    self.queue = queue
    self.wait = 20 #TODO change this
    self.folder = "whois/"
    self.fail = fail
    self.proxy_server = proxy
    self.proxy_port = port
    self.running = True

  def whois(self,domain):
    #always use the native python client
    text = self.client.whois_lookup(None, domain, 0)
    return text

  def save_data(self,domain,text):
    #save to a file
    f = open(self.folder+domain,'w')
    f.write(text)
    f.close()
    #print text

  def run(self):
    while self.running:
      #get next host
      domain = self.queue.get()

      #TOOD rm
      #print "WHOIS: " + domain
      try:
        data = self.whois(domain)
      except proxywhois.socks.GeneralProxyError as e:
        if e.value[0] == 6: #is there a proxy error?
          print "Unable to connect to proxy: "+ self.proxy_server +":"+ str(self.proxy_port)
          self.running = False;
          self.queue.put(domain)
        else:
          print "Error Running whois on domain:["+domain+"] " + str(e)
          self.fail.append(domain)
      except proxywhois.socks.HTTPError as e:
        #TODO also handle the socks case
        #bad domain name
        print "Invalid domain: " + domain
        self.fail.append(domain)
      except Exception as e:
        print "FAILED: [" + domain + "] error: " + str(sys.exc_info()[0])
        self.fail.append(domain)
      else:
        print "SUCSESS: [" + domain + "]"
        self.save_data(domain,data)
      finally:
        #inform the queue we are done
        self.queue.task_done()

      if not q.empty() and self.running:
        time.sleep(self.wait)


if __name__ == '__main__':
  """main"""
  if not len(sys.argv) == 3:
    print "usage: " + sys.argv[0] + " <proxy list file> <domain list file>"
    exit()
 
  fail_list = list()

  q = Queue.Queue()
  print "Starting threads.."
  for l in open(sys.argv[1],'r'):
      if l[0] != '#':
        s = l.split()
        if len(s) == 2:
          #TODO validate!
          t = WhoisThread(s[0],int(s[1]),q,fail_list)
          t.setDaemon(True)
          t.start()
  print str(threading.active_count()) + " threads started"

  print "adding domains to queue"
  i = 0
  for l in open(sys.argv[2],'r'):
    l = l.strip()
    if len(l) > 3:
      q.put(l.strip())
      i += 1
  print "done " + str(i) +" domains in queue"

  print "All threads running"
  try:
    while threading.active_count() > 1 and not q.empty():
      print "T: " + str(threading.active_count())
      print "Q: " + str(q.qsize())
      time.sleep(5) # TODO remove the print statments change the sleep value
  except KeyboardInterrupt:
    print "Keyboard Interrupt... Exiting"
  else:
    print "Done!"
  
  q.join()
  #TODO tmp
  print "T: " + str(threading.active_count())
  print "Q: " + str(q.qsize())

  print "saving " +str(len(fail_list))+" fails"
  fail_file = open("fail.txt",'a+')
  for d in fail_list:
    fail_file.write(d+'\n')
  fail_file.close()
  print "all done"

