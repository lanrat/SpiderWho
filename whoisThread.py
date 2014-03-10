import threading
import proxywhois
import socks
import sys
import time
import traceback
import re
import urlparse
import config
import string

#NULL whois result Exception
class NullWhoisException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return "Null Whois: "+repr(self.value)

class WhoisTimeoutException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return "Whois Timeout on: "+repr(self.value)

class WhoisLinesException(Exception):
    def __init__(self, value,data):
        self.value = value
        self.data = data
    def __str__(self):
        return "Response Too Small: "+repr(self.value)+"\n"+repr(self.data)

class WhoisRatelimitException(Exception):
    def __init__(self, server, hard_limit=True):
        self.server = server
        self.hard = hard_limit
    def strict(self):
        if self.server in config.STRICT_SERVERS:
            return True
        return False
    def __str__(self):
        return "Whois Ratelimit Reached on: "+repr(self.server)+" Hard Limit: "+str(self.hard)

class WhoisBadDomainException(Exception):
    def __init__(self, domain):
        self.domain = domain
    def __str__(self):
        return "Invalid Domain: "+repr(self.domain)



#static vars
numActiveThreads_lock = threading.Lock()
numActiveThreads = 0
numProxyThreads_lock = threading.Lock()
numProxyThreads = 0
proxy_ip_list_lock = threading.Lock()
proxy_ip_list = list()
socket_timeout = 30 #seconds
numLookups_lock = threading.Lock()
numLookups = 0


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

def incrementLookupCount():
    global numLookups_lock
    global numLookups
    numLookups_lock.acquire()
    try:
        numLookups += 1
    finally:
        numLookups_lock.release()

def getLookupCount():
    global numActiveThreads_loc
    global numActiveThreads
    ret = -1
    numLookups_lock.acquire()
    try:
        ret = numLookups
    finally:
        numLookups_lock.release()
    return ret

'''
Active threads are threaads that are not sleeing and activly querying a reccord
'''
def incrementActiveThreadCount():
    global numActiveThreads_lock
    global numActiveThreads
    numActiveThreads_lock.acquire()
    try:
        numActiveThreads += 1
    finally:
        numActiveThreads_lock.release()

def decrementActiveThreadCount():
    global numActiveThreads_lock
    global numActiveThreads
    numActiveThreads_lock.acquire()
    try:
        numActiveThreads -= 1
    finally:
        numActiveThreads_lock.release()

def getActiveThreadCount():
    global numActiveThreads_lock
    global numActiveThreads
    ret = -1
    numActiveThreads_lock.acquire()
    try:
        ret = numActiveThreads
    finally:
        numActiveThreads_lock.release()
    return ret

'''
Proxy threads are threads with working proxies
'''
def incrementProxyThreadCount():
    global numProxyThreads_lock
    global numProxyThreads
    numProxyThreads_lock.acquire()
    try:
        numProxyThreads += 1
    finally:
        numProxyThreads_lock.release()

def decrementProxyThreadCount():
    global numProxyThreads_lock
    global numProxyThreads
    numProxyThreads_lock.acquire()
    try:
        numProxyThreads -= 1
    finally:
        numProxyThreads_lock.release()

def getProxyThreadCount():
    global numProxyThreads_lock
    global numProxyThreads
    ret = -1
    numProxyThreads_lock.acquire()
    try:
        ret = numProxyThreads
    finally:
        numProxyThreads_lock.release()
    return ret



#this object is used to store the results of a whois result as it is passed around
class WhoisResult:
    def __init__(self, domain):
        self.domain = domain.upper()
        self.attempts = list()
        self.current_attempt = None
        self.maxAttempts = False
        self.next_whois_server = None

    def getNextServer(self):
        return self.next_whois_server

    def setNextServer(self,server):
        self.next_whois_server = server

    def valid(self):
        '''performs quick checking to verify that the data we got may contain some valid data'''
        #search for email
        match = re.search(config.EMAIL_REGEX, self.getData())
        if match:
            return True
        return False

    def addAttempt(self, attempt):
        self.attempts.append(attempt)
        self.current_attempt = self.attempts[-1]
        return self.current_attempt

    def addError(self, error):
        if self.current_attempt:
            self.current_attempt.addError(error)
        else:
            print "ERROR: Adding error to result without attempt"

    def getLogData(self):
        log = list()
        log.append("DOMAIN: "+self.domain)
        log.append("Attempts: "+str(self.numAttempts()))
        log.append("Max Attempts: "+ str(self.maxAttempts))
        log.append("Last Whois Server: "+ str(self.next_whois_server))
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
    def __init__(self, proxy):
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
    def __init__(self, server):
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
    def __init__(self,ip, port, proxy_type):
        self.server = ip
        self.port = port
        self.proxy_type = proxy_type
        self.external_ip = None
        self.ready = False
        self.errors = 0
        self.client = proxywhois.NICClient()
        self.history = dict()

    def connect(self):
        self.updateExternalIP()
        self.client.set_proxy(self.proxy_type, self.server, self.port)
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
                s.setproxy(self.proxy_type,self.server, self.port)
                s.connect((url.hostname, 80))
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
        whois_server = record.getNextServer()
        if whois_server == None:
            whois_server = self.client.choose_server(record.domain)
        while (recurse_level > 0) and (whois_server != None):
            whois_server = whois_server.lower()
            record.setNextServer(whois_server)
            if whois_server in self.history:
                tdelta = time.time() - self.history[whois_server]
                if tdelta < config.WHOIS_SERVER_JUMP_DELAY: #if the amount of time since the last query is less than the delay
                    if (config.WHOIS_SERVER_JUMP_DELAY-tdelta) < config.WHOIS_SERVER_SLEEP_DELAY: #if the time left to wait is less then the sleep delay
                        decrementActiveThreadCount()
                        time.sleep(config.WHOIS_SERVER_JUMP_DELAY-tdelta)
                        incrementActiveThreadCount()
                    else:
                        time.sleep(0.1) #this protects us from busy waiting
                        raise WhoisRatelimitException(whois_server, False)
            #TODO have thread remove old entries from history every x runs (runs % x)
            self.history[whois_server] = time.time()
            response = WhoisResponse(whois_server)
            incrementLookupCount()
            data = None
            try:
                data = self.client.whois(record.domain, whois_server, 0)
            except:
                pass
            if data == None or len(data) < 1:
                error = "Error: Empty response recieved for domain: "+record.domain+" on server: "+whois_server+" Using proxy: "+self.server
                if config.DEBUG:
                    print error
                raise NullWhoisException(error)

            response.setResponse(data)
            record.getLastAttempt().addResponse(response)

            nLines = data.count('\n')
            if nLines < config.MIN_RESPONSE_LINES: #if we got less than the minimul amount of lines to be considered a valid response
                data_lower = data.lower()

                #TODO move these checks into a response checking function

                ''' check for org rate limits'''
                if "whois limit exceeded" in data_lower:
                    raise WhoisRatelimitException(whois_server)

                '''non-existant domain'''
                if "invalid domain name" in data_lower:
                    raise WhoisBadDomainException(record.domain)
                if "no match for" in data_lower:
                    raise WhoisBadDomainException(record.domain)
                if " is not registered here." in data_lower:
                    raise WhoisBadDomainException(record.domain)
                if "not found" in data_lower:
                    raise WhoisBadDomainException(record.domain)
                if "can't get information on local domain" in data_lower:
                    raise WhoisBadDomainException(record.domain)
                if "no information available" in data_lower:
                    raise WhoisBadDomainException(record.domain)

                error = "Error: recieved small "+str(nLines)+" response for domain: "+record.domain+" on server: "+whois_server+" Using proxy: "+self.server
                raise WhoisLinesException(error,data)
            recurse_level -= 1
            if recurse_level > 0:
                whois_server = self.client.findwhois_server(response.getResponse(),whois_server)
        return response #returns the last response used


#main thread which handles all whois lookups, one per proxy
class WhoisThread(threading.Thread):
    def __init__(self, proxy, queue,save):
        threading.Thread.__init__(self)
        self.daemon = True
        self.queue = queue
        self.proxy = proxy
        self.save_queue = save
        self.running = False

    def fail(self, record, error, requeue=True):
        self.proxy.errors += 1
        record.addError(error)
        if config.DEBUG:
            print "["+ str(self.proxy) +"] "+ error
        if requeue and record.numAttempts() < config.MAX_ATTEMPTS:
            self.queue.put(record)
        else:
            record.maxAttempts = True
            self.save_queue.put(record)

    def run(self):
        #get and print my remote IP, also tests the proxy for usability
        while True:

            #wait untill proxy is active if down
            while not self.proxy.connect():
                if config.DEBUG:
                    print "WARNING: Failed to connect to proxy: " + str(self.proxy)
                time.sleep(20)


            if not addRemoteProxyIP(self.proxy.external_ip):
                if config.DEBUG:
                    print "WARNING: Proxy is already being used ["+self.proxy.server+"] on port: "+str(self.proxy.port)+" with remote IP: "+self.proxy.external_ip
                return

            self.running = True
            incrementProxyThreadCount()

            while self.running:
                #get next host
                record = self.queue.get()
                incrementActiveThreadCount()
                record.addAttempt(WhoisAttempt(self.proxy))
                try:
                    self.proxy.whois(record)
                except WhoisRatelimitException as e:
                    #we reached a server who's wait is more than the allowed sleeping time
                    #give the request to another server
                    self.fail(record, str(e))
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
                except (proxywhois.socks.HTTPError, proxywhois.socks.Socks4Error, proxywhois.socks.Socks5Error) as e:
                    #bad domain name
                    error = "Invalid domain: " + record.domain
                    self.fail(record,error)
                except (NullWhoisException, WhoisTimeoutException, WhoisLinesException) as e:
                    self.fail(record, str(e))
                except WhoisBadDomainException as e:
                    self.fail(record, str(e), False)
                except WhoisBadDomainException as e:
                    error = "FAILED: [" + record.domain + "] error: " + str(sys.exc_info()[0])
                    self.fail(record,error)
                else:
                    if (not config.RESULT_VALIDCHECK) or record.valid():
                        record.current_attempt.success = True
                        self.save_queue.put(record)
                    else:
                        error =  "INVALID RESULT: [" + record.domain + "] Failed validity check"
                        self.fail(record,error)
                finally:
                    #inform the queue we are done
                    self.queue.task_done()

                    decrementActiveThreadCount()

            decrementProxyThreadCount()

