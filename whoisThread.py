import threading
import proxywhois
import socks
import sys #for debugging
import time

debug = True

#static vars
numWorkerThreads_lock = threading.Lock()
numWorkerThreads = 0
proxy_ip_list_lock = threading.Lock()
proxy_ip_list = list()


def addRemoteProxyIP(ip):
  global proxy_ip_list_lock
  global proxy_ip_list
  proxy_ip_list_lock.acquire()
  ret = None
  try:
    if not ip in proxy_ip_list:
      proxy_ip_list.append(ip)
      ret = True
    else:
      ret = False
  finally:
    proxy_ip_list_lock.release()
    return ret


def incrementWorkerThreadCount():
  global numWorkerThreads_lock
  global numWorkerThreads
  numWorkerThreads_lock.acquire()
  try:
    numWorkerThreads += 1
  finally:
    numWorkerThreads_lock.release()


def decrementWorkerThreadCount():
  global numWorkerThreads_lock
  global numWorkerThreads
  numWorkerThreads_lock.acquire()
  try:
    numWorkerThreads -= 1
  finally:
    numWorkerThreads_lock.release()


def getWorkerThreadCount():
  global numWorkerThreads_lock
  global numWorkerThreads
  ret = -1
  numWorkerThreads_lock.acquire()
  try:
    ret = numWorkerThreads
  finally:
    numWorkerThreads_lock.release()
  return ret



#this object is used to store the results of a whois result as it is passed around
class WhoisResult:
  def __init__(self,domain):
    self.domain = domain.upper()
    self.attempts = list()
    self.current_attempt = None
    self.data = None #TODO RM
    self.maxAttempts = False

  def addAttempt(self,attempt):
    self.attempts.append(attempt)
    self.current_attempt = self.attempts[-1]
    return self.current_attempt

  def addError(self,error):
    if self.current_attempt:
      self.current_attempt.addError(error)
    else:
      print "ERROR: Adding error to result without attempt"

  def getLogData(self):
    log = list()
    log.append("DOMAIN: "+self.domain)
    log.append("Attempts: "+str(self.numAttempts()))
    log.append("Max Attempts: "+ str(self.maxAttempts))
    for (num, attempt) in enumerate(self.attempts):
      log.append("-----------Attempt:"+str(num)+"------------")
      log += attempt.getLogData()
    return log

  def setData(self,data):
    self.data = data

  def getData(self):
    return self.data

  def numAttempts(self):
    return len(self.attempts)


#class to hold details on an attempt to whois a particular domain
class WhoisAttempt:
  def __init__(self,proxy):
    #timestamp (float)
    self.timestamp = time.time()
    self.success = False
    self.proxy = proxy
    self.errors = list()

  def addError(self,error):
    self.errors.append(error)

  def getLogData(self):
    #TODO add whois referal/server data
    log = list()
    log.append("Timestamp: "+ str(self.timestamp))
    log.append("Proxy: "+ self.proxy.getLog())
    log.append("Sucsess: "+ str(self.success))
    numErrors = len(self.errors)
    log.append("Errors: "+ str(numErrors))
    for error in self.errors:
      log.append("--Error: "+str(error))
    return log



#class to hold a proxy object
class Proxy:
  def __init__(self,ip,port,proxy_type):
    self.server = ip
    self.port = port
    self.proxy_type = proxy_type
    self.external_ip = None
    self.ready = False
    self.errors = 0
    self.client = proxywhois.NICClient()


  def connect(self):
    self.updateExternalIP()
    self.client.set_proxy(self.proxy_type,self.server,self.port)
    if not self.external_ip:
      return False
    self.ready = True
    return self.ready

  def getLog(self):
    return str(self) +" Errors: "+ str(self.errors)


  def __repr__(self):
    ret = "Server:"+self.server +":"+str(self.port)
    if self.external_ip:
      ret += " ExtIP:"+self.external_ip
    return ret


  def updateExternalIP(self):
    """this method uses the proxy socket to get the remote IP on that proxy"""
    host = "curlmyip.com"
    #host = "ipaddr.me"
    #host = "icanhazip.com"
    #host = "bot.whatismyipaddress.com"
    #host = "myip.dnsdynamic.com"
    try:
      s = socks.socksocket(socks.socket.AF_INET, socks.socket.SOCK_STREAM)
      s.setproxy(self.proxy_type,self.server,self.port)
      s.connect((host,80))
      s.send('GET /\r\n\r\n')
      r = s.recv(4096)
    except socks.GeneralProxyError as e:
      return None
    else:
      self.external_ip = r.split()[-1]
      return self.external_ip


  def whois(self,record):
    if not self.ready:
      return False
    #TODO expand to save data in result
    text = self.client.whois_lookup(None, record.domain, 0)
    record.setData(text)
    return text


#main thread which handles all whois lookups, one per proxy
class WhoisThread(threading.Thread):
  def __init__(self,proxy,queue,save):
    threading.Thread.__init__(self)
    self.daemon = True
    self.queue = queue
    self.proxy = proxy
    self.wait = 20 #TODO change this
    self.save_queue = save
    self.running = True


  def fail(self,record,error):
    self.proxy.errors += 1
    record.addError(error)
    print "["+ str(self.proxy) +"] "+ error
    if record.numAttempts() < 3:
      self.queue.put(record)
    else:
      record.maxAttempts = True
      self.save_queue.put(record)


  def run(self):
    incrementWorkerThreadCount()
    #get and print my remote IP, also tests the proxy for usability
    if not self.proxy.connect():
      print "WARNING: Failed to connect to proxy: " + str(self.proxy)
      decrementWorkerThreadCount()
      return
    else:
      if debug:
        print "Thread running with proxy: "+ str(self.proxy)

    if not addRemoteProxyIP(self.proxy.external_ip):
      print "WARNING: Proxy is already being used"
      decrementWorkerThreadCount()
      return
    
    while self.running:
      #get next host
      record = self.queue.get()
      record.addAttempt(WhoisAttempt(self.proxy))
      try:
        if not self.proxy.whois(record):
          raise Exception("NULL WHOIS value")
      except proxywhois.socks.GeneralProxyError as e:
        if e.value[0] == 6: #is there a proxy error?
          error = "Unable to connect to once valid proxy"
          print error
          record.addError(error)
          self.queue.put(record)
          self.running = False
        else:
          error = "Error Running whois on domain:["+record.domain+"] " + str(e)
          self.fail(record,error)
      except proxywhois.socks.HTTPError as e:
        #TODO also handle the socks case
        #bad domain name
        error = "Invalid domain: " + record.domain
        self.fail(record,error)
      except Exception as e:
        error = "FAILED: [" + record.domain + "] error: " + str(sys.exc_info()[0])
        self.fail(record,error)
      else:
        record.current_attempt.success = True
        if debug:
          print "SUCSESS: [" + record.domain + "]"
        self.save_queue.put(record)
      finally:
        #inform the queue we are done
        self.queue.task_done()

      if not self.queue.empty() and self.running:
        time.sleep(self.wait) #TODO change this to be dynamic
    decrementWorkerThreadCount()


