#!/usr/bin/env python
import sys
import time
from helperThreads import ManagerThread
from datetime import timedelta

debug = True
start_time = time.time()


def printStatus(t):
    running_seconds = (time.time() - start_time)
    delta  = timedelta(seconds=running_seconds)
    print "|----------------------"
    print "| Domains: "+ str(t.input_thread.getDomainCount())
    print "| Failures:  "+ str(t.fail_thread.numFails())
    #print "| Saved:  "+ str(t.getSavedRecords()) #TODO SaveThread
    print "| Worker Threads: "+ str(t.getWorkerThreadCount())
    print "| Queue size: "+ str(t.getQueueSize())
    print "| Lookups per seccond: "+ str(round((t.input_thread.getDomainCount()-t.getQueueSize())/running_seconds,2))
    print "| Running time: "+ str(delta)
    print "|----------------------"


def run(proxy_list,domain_list):
  t = ManagerThread(proxy_list,domain_list)
  t.daemon = True #required for ctrl-c exit
  start_time = time.time()
  t.start()

  #wait for threads to get ready and settle
  if not t.ready:
    time.sleep(0.1)

  try:
    while t.getWorkerThreadCount() > 1 and t.isAlive():
      if debug:
        printStatus(t)
      time.sleep(5) # this is ugly
    if (t.getWorkerThreadCount() == 0):
      print "No valid Proxy threads running!!"
  except KeyboardInterrupt:
    print "Keyboard Interrupt... Exiting"
  else:
    if debug:
      print "Done!"
  finally:
    #sanity checks for the fail
    if not t.fail_queue.empty():
        print "timeout expired: exiting before all fails finished writing to disk"
    if t.ready and t.input_thread.valid:
      #real status output
      printStatus(t)
      if t.getQueueSize() > 0:
        print "Ending with non-empty queue!"


if __name__ == '__main__':
  if not len(sys.argv) == 3:
    print "usage: " + sys.argv[0] + " <proxy list file> <domain list file>"
    exit()
  run (sys.argv[1],sys.argv[2])

