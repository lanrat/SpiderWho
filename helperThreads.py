import threading
from Queue import Queue
import time
import whoisThread
import os
import os.path
import urlparse
import config
import tarfile
import StringIO

#this thread is in charge of starting all the other
#threads and keeping track of thir running status
class ManagerThread(threading.Thread):
    '''main thread that is responsible for starting and keeping
    track of all other threads'''

    def __init__(self):
        threading.Thread.__init__(self)
        self.input_queue = Queue() #maxsize set inside EnqueueThread
        self.save_queue = Queue(maxsize=config.MAX_QUEUE_SIZE)
        self.input_thread = None
        self.save_thread = None
        self.ready = False
        self.threads = list()


    def run(self):
        #startSaveThread
        self.save_thread = SaveThread(self.save_queue)
        self.save_thread.start()

        #start whois threads
        try:
            for l in open(config.PROXY_LIST,'r'):
                if config.NUM_PROXIES == 0 or len(self.threads) < config.NUM_PROXIES:
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
                            proxy = whoisThread.Proxy(url.hostname, url.port, proxy_type)
                            t = whoisThread.WhoisThread(proxy, self.input_queue, self.save_queue)
                            t.start()
                            self.threads.append(t)
        except IOError:
            print "Unable to open proxy file: " + config.PROXY_LIST
            return
        if config.DEBUG:
            print str(whoisThread.getProxyThreadCount()) + " threads started"

        #now start EnqueueThread
        self.input_thread = EnqueueThread(self.input_queue)
        self.input_thread.start()

        #wait for threads to settle
        time.sleep(0.2)

        self.ready = True

        #now wait for all the work to be done
        while self.input_thread.isAlive():
            time.sleep(0.5)

        if config.DEBUG:
            print "Done loading domains to queue"

        while self.input_queue.qsize() > whoisThread.getProxyThreadCount():
            time.sleep(config.WHOIS_SERVER_JUMP_DELAY)

        #when the reamining queries are all waiting for an open proxy, reduce the delay
        #TODO this does not always prevent getting stuck on the last few
        config.WHOIS_SERVER_JUMP_DELAY = config.WHOIS_SERVER_SLEEP_DELAY
        config.WHOIS_SERVER_SLEEP_DELAY = 1

        self.input_queue.join()

        if config.DEBUG:
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
        self._results_folder = config.OUTPUT_FOLDER+config.RESULTS_FOLDER
        self._inputSize = 0.1 # not 0 to prevent divide by 0 errors
        self._fh = None

    def getNumSkipped(self):
        return self.skipped

    def skipDomain(self, domain):
        path = self._results_folder+domain+"."+config.SAVE_EXT
        return os.path.isfile(path)

    def getDomainCount(self):
        return self._domains

    def getProgress(self):
        if self._fh == None:
            return 1.0
        return self._fh.tell() / self._inputSize

    def run(self):
        try:
            self._fh = open(config.DOMAIN_LIST, 'r')
            self.valid = True
            self._inputSize = float(os.fstat(self._fh.fileno()).st_size)
        except IOError:
            self.valid = False
            print "Unable to open file: "+ config.DOMAIN_LIST
            return
        for l in self._fh:
            if self.skipped < config.SKIP_DOMAINS:
                self.skipped +=1
                continue
            l = l.strip().lower()
            if len(l) > 3:
                if not (config.SKIP_DONE and self.skipDomain(l)):
                    while self._queue.qsize() >= config.MAX_QUEUE_SIZE:
                        time.sleep(0.1)
                    self._queue.put(whoisThread.WhoisResult(l))
                    self._domains +=1
                else:
                    self.skipped +=1
        self._fh.close()
        self._fh = None

#runs in the background and saves data as we collect it
class SaveThread(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self._queue = queue
        self._num_saved = 0
        self._num_good = 0
        self._num_faild = 0
        self._num_tared = 0
        self._tar_file = None
        self._fail_filepath = self.getFailFileName()
        self._log_folder = config.OUTPUT_FOLDER + config.LOG_FOLDER
        self._results_folder = config.OUTPUT_FOLDER + config.RESULTS_FOLDER
        if not os.path.exists(config.OUTPUT_FOLDER):
            os.makedirs(config.OUTPUT_FOLDER)
        if not os.path.exists(self._log_folder) and config.SAVE_LOGS:
            os.makedirs(self._log_folder)
        if not os.path.exists(self._results_folder):
            os.makedirs(self._results_folder)

    def getFailFileName(self):
        fail_filepath = config.OUTPUT_FOLDER + config.FAIL_FILENAME
        if os.path.isfile(fail_filepath):
            fail_filepath += "."
            i = 1;
            while os.path.isfile(fail_filepath + str(i)):
                i += 1
            return fail_filepath + str(i)
        return fail_filepath

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
                if config.SAVE_LOGS:
                    self.saveLog(r)
                if r.current_attempt.success:
                    self.saveData(r)
                else:
                    self.saveFail(r)
            finally:
                self._num_saved += 1
                self._queue.task_done()


    def saveLog(self, record):
        try:
            f = open(self._log_folder+record.domain+"."+config.LOG_EXT,'w')
            f.write('\n'.join(record.getLogData()) + '\n')
            f.close()
            return True
        except IOError:
            print "Unabe to write "+record.domain+".log log to file"
            return False


    def saveFail(self, record):
        try:
            fail_file = open(self._fail_filepath, 'a+')
            fail_file.write(record.domain+'\n')
            fail_file.close()
            self._num_faild += 1
            return True
        except IOError:
            print "Unabe to write to fail file"
            return False

    def saveData(self, record):
        if config.SAVE_TAR:
            return self.saveDataTar(record)
        else:
            return self.saveDataFile(record)

    def startTar(self):
        self._num_tared = 0
        tarname = self.nextTarName()
        self._tar_file = tarfile.open(tarname, "w:gz")

    
    def nextTarName(self):
        tstamp = time.strftime("%Y.%m.%d-%H.%M")
        tar_filepath = self._results_folder+tstamp
        if os.path.isfile(tar_filepath+".tgz"):
            tar_filepath += "."
            i = 1;
            while os.path.isfile(tar_filepath+str(i)+".tgz"):
                i += 1
            return tar_filepath + str(i)+".tgz"
        return tar_filepath+".tgz"



    def closeTar(self):
        """ensure this runs on program exit"""
        if self._tar_file:
            self._tar_file.close()
        self._tar_file = None

    def saveDataTar(self, record):
        if not self._tar_file:
            self.startTar()

        # append record to tar
        if config.SPLIT_THICK:
            data = record.getThinData()
            if data:
                who_file = tarfile.TarInfo("thin/"+record.domain+"."+config.SAVE_EXT)
                who_file.size = len(data)
                who_file.mtime = time.time()
                self._tar_file.addfile(who_file, StringIO.StringIO(data))
            else:
# warning no thin data found
                if config.DEBUG:
                    print "Warning: no thin data for "+record.domain

            data = record.getThickData()
            if data:
                who_file = tarfile.TarInfo("thick/"+record.domain+"."+config.SAVE_EXT)
                who_file.size = len(data)
                who_file.mtime = time.time()
                self._num_tared += 1
                self._tar_file.addfile(who_file, StringIO.StringIO(data))
                self._num_good += 1
            else:
# warning no thick data found
                if config.DEBUG:
                    print "Warning: no thick data for "+record.domain
        else:
            who_file = tarfile.TarInfo(record.domain+"."+config.SAVE_EXT)
            data = record.getAllData()
            who_file.size = len(data)
            who_file.mtime = time.time()
            self._num_tared += 1
            self._tar_file.addfile(who_file, StringIO.StringIO(data))
            self._num_good += 1

        if self._num_tared == config.SAVE_TAR_SIZE:
            self.closeTar()
        return True
        

    def saveDataFile(self, record):
        try:
            if config.SPLIT_THICK:
                f1 = open(self._results_folder+record.domain+".thick."+config.SAVE_EXT, 'w')
                f1.write(record.getThickData())
                f1.close()
                f2 = open(self._results_folder+record.domain+".thin."+config.SAVE_EXT, 'w')
                f2.write(record.getThinData())
                f2.close()
            else:
                f = open(self._results_folder+record.domain+"."+config.SAVE_EXT, 'w')
                f.write(record.getAllData())
                f.close()
            self._num_good += 1
            return True
        except IOError:
            print "Unabe to write "+record.domain+" data to file"
            return False

