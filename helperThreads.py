import threading
from Queue import Queue
import time
import whoisThread
import os
import urlparse
import config


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


    def __init__(self):
        threading.Thread.__init__(self)
        self.input_queue = Queue(maxsize=config.max_queue_size)
        self.save_queue = Queue(maxsize=config.max_queue_size)
        self.input_thread = None
        self.save_thread = None
        self.ready = False
        self.threads = list()

    def getQueueSize(self):
        return self.input_queue.qsize()

    def run(self):
        #startSaveThread
        self.save_thread = SaveThread(self.save_queue)
        self.save_thread.start()

        #start whois threads
        try:
            for l in open(config.proxy_list,'r'):
                if config.num_proxies == 0 or len(self.threads) < config.num_proxies:
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
            print "Unable to open proxy file: " + config.proxy_list
            return
        if config.debug:
            print str(whoisThread.getWorkerThreadCount()) + " threads started"

        #now start EnqueueThread
        self.input_thread = EnqueueThread(self.input_queue)
        self.input_thread.start()

        #wait for threads to settle
        time.sleep(0.2)

        self.ready = True

        #now wait for all the work to be done
        while self.input_thread.isAlive():
            time.sleep(0.1)

        if config.debug:
            print "Done loading domains to queue"

        self.input_queue.join()

        if config.debug:
            print "Saving results"
        self.save_queue.join()



#this is a simple thread to read input lines from a
#file and add them to the queue for prossessing
class EnqueueThread(threading.Thread):
    def __init__(self,queue):
        threading.Thread.__init__(self)
        self._queue = queue
        self._domains = 0
        self.valid = False
        self.skipped = 0
        self._results_folder = config.output_folder+config.results_folder

    def getNumSkipped(self):
        return self.skipped

    def skipDomain(self,domain):
        path = self._results_folder+domain+"."+config.save_ext
        return os.path.isfile(path)

    def getDomainCount(self):
        return self._domains

    def run(self):
        try:
            fh = open(config.domain_list,'r')
            self.valid = True
        except IOError:
            self.valid = False
            print "Unable to open file: "+ config.domain_list
            return
        for l in fh:
            l = l.strip().upper()
            if len(l) > 3:
                if not (config.skip_done and self.skipDomain(l)):
                    self._queue.put(whoisThread.WhoisResult(l))
                    self._domains +=1
                else:
                    self.skipped +=1

#runs in the background and saves data as we collect it
class SaveThread(threading.Thread):
    def __init__(self,queue):
        threading.Thread.__init__(self)
        self._queue = queue
        self._num_saved = 0
        self._num_good = 0
        self._num_faild = 0
        self._fail_filepath =  config.output_folder + config.fail_filename
        self._log_folder = config.output_folder + config.log_folder
        self._results_folder = config.output_folder + config.results_folder
        if not os.path.exists(config.output_folder):
            os.makedirs(config.output_folder)
        if not os.path.exists(self._log_folder):
            os.makedirs(self._log_folder)
        if not os.path.exists(self._results_folder):
            os.makedirs(self._results_folder)

    def getNumFails(self):
        return self._num_faild

    def getNumSaved(self):
        return self._num_saved

    def getNumGood(self):
        return self._num_good

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
        try:
            fail_file = open(self._fail_filepath,'a+')
            fail_file.write(record.domain+'\n')
            fail_file.close()
            self._num_faild += 1
            return True
        except IOError:
            print "Unabe to write to fail file"
            return False


    def saveData(self,record):
        try:
            f = open(self._results_folder+record.domain+"."+config.save_ext,'w')
            f.write(record.getData())
            f.close()
            self._num_good += 1
            return True
        except IOError:
            print "Unabe to write "+record.domain+" data to file"
            return False


