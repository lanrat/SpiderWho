import threading
import proxywhois
import socks
import sys #for debugging
import time
import traceback
import re
import urlparse

debug = True


#NULL whois result Exception
class NullWhois(Exception):
  def __init__(self, value):
    self.value = value
  def __str__(self):
    return repr(self.value)

class WhoisTimeoutException(Exception):
  def __init__(self, value):
    self.value = value
  def __str__(self):
    return repr(self.value)



#static vars
numWorkerThreads_lock = threading.Lock()
numWorkerThreads = 0
proxy_ip_list_lock = threading.Lock()
proxy_ip_list = list()
socket_timeout = 30 #seconds


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
    self.maxAttempts = False

  def valid(self):
    '''performs quick checking to verify that the data we got may contain some valid data'''
    #search for email
    match = re.search(r'[\w.-]+@[\w.-]+', self.getData())
    if match:
        return True
    return False

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

  def getData(self,all_data=True):
    """Returnes the string response of the last response on the last attempt"""
    if all_data:
        return self.attempts[-1].getResponse()
    else:
        return self.attempts[-1].getLastResponse()

  def numAttempts(self):
    return len(self.attempts)

  def getLastAttempt(self):
    if len(self.attempts) > 0:
      return self.attempts[-1]
    else:
      return None


#class to hold details on an attempt to whois a particular domain
class WhoisAttempt:
  def __init__(self,proxy):
    #timestamp (float)
    self.timestamp = time.time()
    self.success = False
    self.proxy = proxy
    self.errors = list()
    self.responses = list() #contains a list of WhoisResponse classes in the order they were queried

  def addError(self,error):
    self.errors.append(error)

  def getLogData(self):
    log = list()
    log.append("Timestamp: "+ str(self.timestamp))
    log.append("Proxy: "+ self.proxy.getLog())
    log.append("Success: "+ str(self.success))
    log.append("Responses: "+str(len(self.responses)))
    for response in self.responses:
      log += response.getLogData()
    numErrors = len(self.errors)
    log.append("Errors: "+ str(numErrors))
    for error in self.errors:
      log.append("--Error: "+str(error))
    return log

  def getLastResponse(self):
    if len(self.responses) > 0:
      return self.responses[-1]
    else:
      return None

  def getResponse(self):
    if len(self.responses) < 1:
      return None
    else:
      ret = ""
      for response in self.responses:
        ret += response.getResponse()
        ret += "\n"
      return ret

  def addResponse(self,response):
    self.responses.append(response)

"""Class used to store the response of an individual
whois query, may be a thick or thin result"""
class WhoisResponse:
  def __init__(self,server):
    self.server = server
    self.response = None

  def setResponse(self,response):
    self.response = response

  def getResponse(self):
    return self.response

  def getServer(self):
    return self.server

  def getLogData(self):
    log = list()
    log.append("WHOIS server: "+str(self.server))
    log.append("======Response=====================")
    log.append(str(self.response))
    log.append("===================================")
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
    self.history = dict() #TODO make more iteligent
    self.delay = 20 # delay in seconds to wait before reusing the same proxy

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
    host = "http://www.sysnet.ucsd.edu/cgi-bin/whoami.sh"
    url = urlparse.urlparse(host)
    for i in range(3): #try 3 times
      try:
        s = socks.socksocket(socks.socket.AF_INET, socks.socket.SOCK_STREAM)
        s.settimeout(socket_timeout)
        s.setproxy(self.proxy_type,self.server,self.port)
        s.connect((url.hostname,80))
        s.send('GET '+url.path+' \nHost: '+url.hostname+'\r\n\r\n')
        r = s.recv(4096)
      except Exception as e:
        time.sleep(0.1)
      else:
        if len(r):
            self.external_ip = r.split()[-1]
            return self.external_ip
        time.sleep(0.1)
    return None

  def whois(self,record):
    """This fucnction is a replacment of whois_lookup
    from the proxywhois class"""
    if not self.ready:
      return False
    # this is the maximum amout of times we will recurse looking for 
    # a thin whois server to reffer us
    recurse_level = 2
    whois_server = self.client.choose_server(record.domain)
    while (recurse_level > 0) and (whois_server != None):
      if whois_server in self.history:
        tdelta = time.time() - self.history[whois_server]
        if tdelta < self.delay:
          #if debug:
          #  print "Whois server ["+whois_server+"] used recently, sleeping for "+str(self.delay-tdelta)+" seconds"
          time.sleep(self.delay-tdelta) #TODO dont ever sleep
      self.history[whois_server] = time.time()
      response = WhoisResponse(whois_server)
      data = None
      try:
          data = self.client.whois(record.domain,whois_server,0)
      except:
          pass
      if data == None or len(data) < 1:
        error = "Error: Empty response recieved for domain: "+record.domain+" on server: "+whois_server+" Using proxy: "+self.server
        if debug:
            print error
        raise NullWhois(error)
      if data.count('\n') < 4: #if we got less than 4 lines in the response
        error = "Error: recieved small response for domain: "+record.domain+" on server: "+whois_server+" Using proxy: "+self.server
        raise WhoisTimeoutException(error)
      response.setResponse(data)
      record.getLastAttempt().addResponse(response)
      recurse_level -= 1
      if recurse_level > 0:
        whois_server = self.client.findwhois_server(response.getResponse(),whois_server)
    return response #returns the last response used


#main thread which handles all whois lookups, one per proxy
class WhoisThread(threading.Thread):
  def __init__(self,proxy,queue,save,validCheck):
    threading.Thread.__init__(self)
    self.daemon = True
    self.queue = queue
    self.proxy = proxy
    self.save_queue = save
    self.running = True
    self.working = False
    self.validCheck = validCheck

  def fail(self,record,error):
    self.proxy.errors += 1
    record.addError(error)
    if (debug):
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

    if not addRemoteProxyIP(self.proxy.external_ip):
      print "WARNING: Proxy is already being used ["+self.proxy.server+"] on port: "+str(self.proxy.port)+" with remote IP: "+self.proxy.external_ip
      decrementWorkerThreadCount()
      return
    
    while self.running:
      #get next host
      record = self.queue.get()
      self.working = True
      record.addAttempt(WhoisAttempt(self.proxy))
      try:
        self.proxy.whois(record)
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
      except NullWhois as e:
          self.fail(record,str(e))
      except WhoisTimeoutException as e:
          self.fail(record,str(e))
      except Exception as e:
        if debug:
          traceback.print_exc()
        error = "FAILED: [" + record.domain + "] error: " + str(sys.exc_info()[0])
        self.fail(record,error)
      else:
        if (not self.validCheck) or record.valid():
            record.current_attempt.success = True
            self.save_queue.put(record)
        else:
            error =  "INVALID RESULT: [" + record.domain + "] Failed validity check"
            self.fail(record,error)
      finally:
        #inform the queue we are done
        self.queue.task_done()
        self.working = False

    decrementWorkerThreadCount()


