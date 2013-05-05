import threading
from Queue import Queue
import time
import whoisThread
import os

output_folder = "results/"
log_folder = "logs/"
fail_file = "fail.txt"
max_queue_size = 10000


debug = True

#this thread is in charge of starting all the other 
#threads and keeping track of thir running status
class ManagerThread(threading.Thread):

  def getWorkerThreadCount(self):
    return whoisThread.getWorkerThreadCount();

  def __init__(self,proxy_list,domain_list):
    threading.Thread.__init__(self)
    self.proxy_list = proxy_list
    self.domain_list = domain_list
    self.input_queue = Queue(maxsize=max_queue_size)
    self.save_queue = Queue(maxsize=max_queue_size)
    self.input_thread = None
    self.save_thread = None
    self.ready = False

  def getQueueSize(self):
    return self.input_queue.qsize()

  def run(self):
    #startSaveThread
    self.save_thread = SaveThread(log_folder,output_folder,fail_file,self.save_queue)
    self.save_thread.start()

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
              t = whoisThread.WhoisThread(proxy,self.input_queue,self.save_queue)
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
    
    if debug:
      print "Done loading domains to queue"

    self.input_queue.join()

    if debug:
      print "Saving results"
    self.save_queue.join()



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
      f = open(self._out_folder+record.domain,'w')
      f.write(record.getData())
      f.close()
      return True
    except IOError:
      print "Unabe to write "+record.domain+" data to file"
      return False


