import threading
from Queue import Queue
import sys #for debugging
import proxywhois
import time
from SocksiPy import socks

debug = True

class WhoisThread(threading.Thread):
  def __init__(self,proxy,port,queue,fail):
    threading.Thread.__init__(self)
    self.client = proxywhois.NICClient()
    #TODO add better proxy type handling
    self.proxy_type = socks.PROXY_TYPE_HTTP
    self.queue = queue
    self.wait = 20 #TODO change this
    self.folder = "whois/"
    self.fail = fail
    self.proxy_server = proxy
    self.proxy_port = port
    self.client.set_proxy(self.proxy_type,proxy,port)
    self.running = True

  def getExternalIP(self):
    """this method uses the proxy socket to get the remote IP on that proxy"""
    host = "curlmyip.com"
    #host = "ipaddr.me"
    #host = "icanhazip.com"
    #host = "bot.whatismyipaddress.com"
    #host = "myip.dnsdynamic.com"
    try:
      s = socks.socksocket(socks.socket.AF_INET, socks.socket.SOCK_STREAM)
      s.setproxy(self.proxy_type,self.proxy_server,self.proxy_port)
      s.connect((host,80))
      s.send('GET /\r\n\r\n')
      r = s.recv(4096)
    except socks.GeneralProxyError as e:
      return None
    else:
      return r.split()[-1]


  def whois(self,domain):
    #always use the native python client
    text = self.client.whois_lookup(None, domain, 0)
    return text

  def save_data(self,domain,text):
    #save to a file
    #TODO make this its own thread of (domain,text)
    f = open(self.folder+domain,'w')
    f.write(text)
    f.close()

  def run(self):
    ManagerThread.incrementWorkerThreadCount()
    #get and print my remote IP, also tests the proxy for usability
    ip = self.getExternalIP()
    if not ip:
      print "WARNING: Failed to connect to proxy: "+ self.proxy_server
      ManagerThread.decrementWorkerThreadCount()
      return
    else:
      if debug:
        print "Thread running with proxy: "+ self.proxy_server +" with remote IP: " + str(ip)

    if not ManagerThread.addRemoteProxyIP(ip):
      print "WARNING: Proxy: "+self.proxy_server+" with remote ip: "+ip+" is already being used"
      ManagerThread.decrementWorkerThreadCount()
      return
    
    while self.running:
      #get next host
      domain = self.queue.get().upper()

      try:
        data = self.whois(domain)
      except proxywhois.socks.GeneralProxyError as e:
        if e.value[0] == 6: #is there a proxy error?
          print "Unable to connect to proxy: "+ self.proxy_server +":"+ str(self.proxy_port)
          self.running = False
          self.queue.put(domain)
        else:
          print "Error Running whois on domain:["+domain+"] " + str(e)
          self.fail.put(domain)
      except proxywhois.socks.HTTPError as e:
        #TODO also handle the socks case
        #bad domain name
        print "Invalid domain: " + domain
        self.fail.put(domain)
      except Exception as e:
        print "FAILED: [" + domain + "] error: " + str(sys.exc_info()[0])
        self.fail.put(domain)
      else:
        if debug:
          print "SUCSESS: [" + domain + "]"
        self.save_data(domain,data)
      finally:
        #inform the queue we are done
        self.queue.task_done()

      if not self.queue.empty() and self.running:
        time.sleep(self.wait)
    ManagerThread.decrementWorkerThreadCount()


#this thread is in charge of starting all the other 
#threads and keeping track of thir running status
class ManagerThread(threading.Thread):
  #static variable to track worker thread count
  numWorkerThreads = 0
  numWorkerThreads_lock = threading.Lock()
  proxy_ip_list = list()
  proxy_ip_list_lock = threading.Lock()

  @staticmethod
  def addRemoteProxyIP(ip):
    ManagerThread.proxy_ip_list_lock.acquire()
    ret = None
    try:
      if not ip in ManagerThread.proxy_ip_list:
        ManagerThread.proxy_ip_list.append(ip)
        ret = True
      else:
        ret = False
    finally:
      ManagerThread.proxy_ip_list_lock.release()
      return ret

  @staticmethod
  def incrementWorkerThreadCount():
    ManagerThread.numWorkerThreads_lock.acquire()
    try:
      ManagerThread.numWorkerThreads += 1
    finally:
      ManagerThread.numWorkerThreads_lock.release()

  @staticmethod
  def decrementWorkerThreadCount():
    ManagerThread.numWorkerThreads_lock.acquire()
    try:
      ManagerThread.numWorkerThreads -= 1
    finally:
      ManagerThread.numWorkerThreads_lock.release()

  @staticmethod
  def getWorkerThreadCount():
    ret = -1
    ManagerThread.numWorkerThreads_lock.acquire()
    try:
      ret = ManagerThread.numWorkerThreads
    finally:
      ManagerThread.numWorkerThreads_lock.release()
    return ret

  def __init__(self,proxy_list,domain_list):
    threading.Thread.__init__(self)
    self.proxy_list = proxy_list
    self.domain_list = domain_list
    self.input_queue = Queue(maxsize=10000)
    self.fail_queue = Queue()
    self.fail_file = "fail.txt"
    self.input_thread = None
    self.fail_thread = None
    self.ready = False

  def getQueueSize(self):
    return self.input_queue.qsize()

  def run(self):
    #start FailThread
    self.fail_thread = FailThread(self.fail_file,self.fail_queue)
    self.fail_thread.daemon = True
    self.fail_thread.start()

    #start whois threads
    try:
      for l in open(self.proxy_list,'r'):
        l = l.strip()
        if l[0] != '#': #if not a comment
          s = l.split()
          if len(s) == 2:
            #TODO validate!
            try:
              i = int(s[1])
            except ValueError:
              print "Proxy "+ s[0] + " has non-int port"
            else:
              t = WhoisThread(s[0],i,self.input_queue,self.fail_queue)
              t.daemon = True
              t.start()
    except IOError:
      print "Unable to open proxy file: " + self.proxy_list
    print str(ManagerThread.getWorkerThreadCount()) + " worker threads started"

    #now start EnqueueThread
    self.input_thread = EnqueueThread(self.domain_list,self.input_queue)
    self.input_thread.start()

    #wait for threads to settle
    time.sleep(0.2)

    self.ready = True

    #now wait for all the work to be done
    while self.input_thread.isAlive():
      time.sleep(0.1)

    self.input_queue.join()

    print "All work done, finishing saving failures"

    #finish saving fails before exit
    #can I join a daemon thread?
    self.fail_queue.join()


#runs in the background and when an input fails it loggs the bad 
#data in a file
class FailThread(threading.Thread):
  def __init__(self,filename,queue):
    threading.Thread.__init__(self)
    self._filename = filename
    self._queue = queue
    self._num_fails = 0

  def numFails(self):
    return self._num_fails

  def run(self):
    while True:
      l = self._queue.get()
      self._num_fails += 1
      try:
        fail_file = open(self._filename,'a+')
        fail_file.write(l+'\n')
        fail_file.close()
      except IOError:
        print "Unabe to write to fail file"
      finally:
        self._queue.task_done()


#this is a simple thread to read input lines from a 
#file and add them to the queue for prossessing
class EnqueueThread(threading.Thread):
  def __init__(self,filename,queue):
    threading.Thread.__init__(self)
    self._filename = filename
    self._queue = queue
    self._domains = 0

  def getDomainCount(self):
    return self._domains

  def run(self):
    try:
      for l in open(self._filename,'r'):
        l = l.strip()
        if len(l) > 3:
          self._queue.put(l)
          self._domains +=1
    except IOError: 
      print "Unable to open file: "+ self._filename

