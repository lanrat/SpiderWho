#!/usr/bin/env python
import sys
import time
from helperThreads import ManagerThread

debug = True

def run(proxy_list,domain_list):
  t = ManagerThread(proxy_list,domain_list)
  t.daemon = True
  start_time = time.time()
  t.start()

  #wait for threads to get ready and settle
  if not t.ready:
    time.sleep(0.1)

  try:
    while t.getWorkerThreadCount() > 1 and t.isAlive():
      if debug:
        print "|----------------------"
        print "| Domains: "+ str(t.input_thread.getDomainCount())
        print "| Failures:  "+ str(t.fail_thread.numFails())
        print "| Worker Threads: "+ str(t.getWorkerThreadCount())
        print "| Queue size: "+ str(t.getQueueSize())
        print "|----------------------"
      time.sleep(5) # this is ugly
    if (t.getWorkerThreadCount() == 0):
      print "No valid Proxy threads running!!"
  except KeyboardInterrupt:
    print "Keyboard Interrupt... Exiting"
  else:
    print "Done!"
  finally:
    end_time = time.time()
    time_delta = (end_time - start_time)
    #sanity checks for the fail
    if not t.fail_queue.empty():
        print "timeout expired: exiting before all fails finished writing to disk"
       
    if t.ready and t.input_thread.valid:
      #real status output
      print "Loaded "+ str(t.input_thread.getDomainCount()) +" Domains"
      print "Had "+ str(t.fail_thread.numFails()) +" Failures"
      print "Ending with "+ str(t.getWorkerThreadCount()) +" worker threads"
      if t.getQueueSize() > 0:
        print "Ending queue size is: "+ str(t.getQueueSize())
      print "Running time: "+str(round(time_delta,2))+" secconds"
      print "Averaging "+ str(round((t.input_thread.getDomainCount()-t.getQueueSize())/time_delta,2)) + " lookups per seccond"

if __name__ == '__main__':
  if not len(sys.argv) == 3:
    print "usage: " + sys.argv[0] + " <proxy list file> <domain list file>"
    exit()

  run (sys.argv[1],sys.argv[2])

