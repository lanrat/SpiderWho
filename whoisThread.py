import threading
import proxywhois
import socks
import sys #for debugging
import time
#from helperThreads import ManagerThread #circular import error

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


class WhoisThread(threading.Thread):
  def __init__(self,proxy,port,queue,fail):
    threading.Thread.__init__(self)
    self.daemon = True
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
    incrementWorkerThreadCount()
    #get and print my remote IP, also tests the proxy for usability
    ip = self.getExternalIP()
    if not ip:
      print "WARNING: Failed to connect to proxy: "+ self.proxy_server
      decrementWorkerThreadCount()
      return
    else:
      if debug:
        print "Thread running with proxy: "+ self.proxy_server +" with remote IP: " + str(ip)

    if not addRemoteProxyIP(ip):
      print "WARNING: Proxy: "+self.proxy_server+" with remote ip: "+ip+" is already being used"
      decrementWorkerThreadCount()
      return
    
    while self.running:
      #get next host
      domain = self.queue.get().upper()
      if debug:
        print "["+ip+"]got domain: " + domain

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
    decrementWorkerThreadCount()


