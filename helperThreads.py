import threading
from Queue import Queue
import time
import whoisThread
import os
import urlparse

output_folder = "results/"
log_folder = "logs/"
fail_file = "fail.txt"
save_ext = "whois"
max_queue_size = 10000


debug = True

#this thread is in charge of starting all the other 
#threads and keeping track of thir running status
class ManagerThread(threading.Thread):

  def getActiveThreadCount(self):
    '''returns the number of threads spawned'''
    return whoisThread.getWorkerThreadCount();


  def getWorkingThreadCount(self):
      '''return the number of threads that are actually doing something'''
      count = 0
      for t in self.threads:
          if t and t.working:
              count += 1
      return count

  
  def __init__(self,proxy_list,domain_list,np,out_dir,skip=False):
    threading.Thread.__init__(self)
    self.proxy_list = proxy_list
    self.domain_list = domain_list
    self.nt = np
    self.output_dir = out_dir+"/"
    self.skip = skip
    self.input_queue = Queue(maxsize=max_queue_size)
    self.save_queue = Queue(maxsize=max_queue_size)
    self.input_thread = None
    self.save_thread = None
    self.ready = False
    self.threads = list()

  def getQueueSize(self):
    return self.input_queue.qsize()

  def run(self):
    #startSaveThread
    self.save_thread = SaveThread(self.output_dir+log_folder, self.output_dir+output_folder, self.output_dir+fail_file, self.save_queue)
    self.save_thread.start()

    #start whois threads
    try:
      for l in open(self.proxy_list,'r'):
        if self.nt == 0 or len(self.threads) < self.nt:
          l = l.strip()
          if l[0] != '#': #if not a comment
            url = urlparse.urlparse(l)
            proxy_type = None
            if url.scheme == "http":
                proxy_type = whoisThread.socks.PROXY_TYPE_HTTP
            elif url.scheme == "socks":
                proxy_type = whoisThread.socks.PROXY_TYPE_SOCKS4
            else:
                print "Unknown Proxy Type"
            if proxy_type:
                proxy = whoisThread.Proxy(url.hostname,url.port,whoisThread.socks.PROXY_TYPE_HTTP)
                t = whoisThread.WhoisThread(proxy,self.input_queue,self.save_queue)
                t.start()
                self.threads.append(t)
    except IOError:
      print "Unable to open proxy file: " + self.proxy_list
      return
    print str(whoisThread.getWorkerThreadCount()) + " threads started"

    #now start EnqueueThread
    self.input_thread = EnqueueThread(self.domain_list,self.input_queue,self.output_dir+output_folder,self.skip)
    self.input_thread.start()

    #wait for threads to settle
    time.sleep(0.2)

    self.ready = True

    #now wait for all the work to be done
    while self.input_thread.isAlive():
      time.sleep(0.1)
    
    if debug:
      print "Done loading domains to queue"

    self.input_queue.join()

    if debug:
      print "Saving results"
    self.save_queue.join()



#this is a simple thread to read input lines from a 
#file and add them to the queue for prossessing
class EnqueueThread(threading.Thread):
  def __init__(self,filename,queue,out="./",skip=False):
    threading.Thread.__init__(self)
    self._filename = filename
    self._queue = queue
    self._domains = 0
    self.valid = False
    self.skip = skip
    self.skipped = 0
    self.out = out

  def getNumSkipped(self):
      return self.skipped

  def skipDomain(self,domain):
      return os.path.isfile(self.out+domain+"."+save_ext)

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
      l = l.strip().upper()
      if len(l) > 3:
        if not (self.skip and self.skipDomain(l)):
          self._queue.put(whoisThread.WhoisResult(l))
          self._domains +=1
        else:
          self.skipped +=1

#runs in the background and saves data as we collect it 
class SaveThread(threading.Thread):
  def __init__(self,log_folder,out_folder,fail_filename,queue):
    threading.Thread.__init__(self)
    self._out_folder = out_folder
    self._log_folder = log_folder
    self._fail_filename = fail_filename
    self._queue = queue
    self._num_saved = 0
    self._num_faild = 0
    if not os.path.exists(out_folder):
      os.makedirs(out_folder)
    if not os.path.exists(log_folder):
      os.makedirs(log_folder)

  def getNumFails(self):
    return self._num_faild

  def getNumSaved(self):
    return self._num_saved

  def run(self):
    while True:
      r = self._queue.get()
      try:
        self.saveLog(r)
        if r.current_attempt.success:
          self.saveData(r)
        else:
          self.saveFail(r)
      finally:
        self._num_saved += 1
        self._queue.task_done()

  
  def saveLog(self,record):
    try:
      f = open(self._log_folder+record.domain+".log",'w')
      f.write('\n'.join(record.getLogData()) + '\n')
      f.close()
      return True
    except IOError:
      print "Unabe to write "+record.domain+".log log to file"
      return False


  def saveFail(self,record):
    self._num_faild += 1
    try:
      fail_file = open(self._fail_filename,'a+')
      fail_file.write(record.domain+'\n')
      fail_file.close()
      return True
    except IOError:
      print "Unabe to write to fail file"
      return False


  def saveData(self,record):
    try:
      f = open(self._out_folder+record.domain+"."+save_ext,'w')
      f.write(record.getData())
      f.close()
      return True
    except IOError:
      print "Unabe to write "+record.domain+" data to file"
      return False


