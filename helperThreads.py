import threading
from Queue import Queue
import time
import whoisThread

#this thread is in charge of starting all the other 
#threads and keeping track of thir running status
class ManagerThread(threading.Thread):

  def getWorkerThreadCount(self):
    return whoisThread.getWorkerThreadCount();

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
              #TODO add better proxy type handling
              proxy = whoisThread.Proxy(s[0],i,whoisThread.socks.PROXY_TYPE_HTTP)
              t = whoisThread.WhoisThread(proxy,self.input_queue,self.fail_queue)
              t.start()
    except IOError:
      print "Unable to open proxy file: " + self.proxy_list
      return
    print str(whoisThread.getWorkerThreadCount()) + " worker threads started"

    #now start EnqueueThread
    self.input_thread = EnqueueThread(self.domain_list,self.input_queue)
    self.input_thread.start()

    #wait for threads to settle
    time.sleep(0.2)

    self.ready = True

    #now wait for all the work to be done
    while self.input_thread.isAlive():
      time.sleep(0.1)
    
    print "Done loading domains to queue"

    self.input_queue.join()

    print "All work done, finishing saving failures"

    #finish saving fails before exit
    #can I join a daemon thread?
    self.fail_queue.join()


#runs in the background and when an input fails it logs the bad 
#data in a file
class FailThread(threading.Thread):
  def __init__(self,filename,queue):
    threading.Thread.__init__(self)
    self.daemon = True
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
        fail_file.write(l.domain+'\n')
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
    self.valid = False

  def getDomainCount(self):
    return self._domains

  def run(self):
    try:
      fh = open(self._filename,'r')
      self.valid = True
    except IOError: 
      self.valid = False
      print "Unable to open file: "+ self._filename
      return
    for l in fh:
      l = l.strip()
      if len(l) > 3:
        self._queue.put(whoisThread.WhoisResult(l))
        self._domains +=1

