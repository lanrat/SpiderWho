import threading
from Queue import Queue
import sys #for debugging
import proxywhois
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
    #TODO make this its own thread of (domain,text)
    f = open(self.folder+domain,'w')
    f.write(text)
    f.close()
    #print text

  def run(self):
    ManagerThread.incrementWorkerThreadCount()
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
    #first start whois threads
    print "Starting threads.."
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
    print str(threading.active_count()) + " threads started"

    #now start FailThread
    self.fail_thread = FailThread(self.fail_file,self.fail_queue)
    self.fail_thread.daemon = True
    self.fail_thread.start()
    print "Fail thread started"

    #now start EnqueueThread
    self.input_thread = EnqueueThread(self.domain_list,self.input_queue)
    #self.input_thread.setDaemon(True)
    self.input_thread.start()
    print "Input thread started"

    self.ready = True
    
    #now wait for all the work to be done
    while not self.input_thread.done:
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
      fail_file = open(self._filename,'a+')
      fail_file.write(l+'\n')
      fail_file.close()
      self._queue.task_done()


#this is a simple thread to read input lines from a 
#file and add them to the queue for prossessing
class EnqueueThread(threading.Thread):
  def __init__(self,filename,queue):
    threading.Thread.__init__(self)
    self._filename = filename
    self._queue = queue
    self._done = False
    self._domains = 0

  def getDomainCount(self):
    return self._domains

  def done(self):
    return self._done

  def run(self):
    try:
      for l in open(self._filename,'r'):
        l = l.strip()
        if len(l) > 3:
          self._queue.put(l)
          self._domains +=1
    except IOError: 
      print "Unable to open file: "+ self._filename
    self._done = True

