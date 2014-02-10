#!/usr/bin/env python
import time
from helperThreads import ManagerThread
from datetime import timedelta
import argparse
import config


def printStatus(t):
    running_seconds = (time.time() - config.start_time)
    delta  = timedelta(seconds=running_seconds)
    print "|----------------------"
    print "| Domains: "+ str(t.input_thread.getDomainCount())
    print "| Saved:  "+ str(t.save_thread.getNumSaved())
    print "| Good:  "+ str(t.save_thread.getNumGood())
    print "| Failures:  "+ str(t.save_thread.getNumFails())
    if config.skip_done:
        print "| Skipped:  "+ str(t.input_thread.getNumSkipped())
    print "| Active Threads: "+ str(t.getActiveThreadCount())
    print "| Working Threads: "+ str(t.getWorkingThreadCount())
    print "| Queue size: "+ str(t.getQueueSize())
    print "| Lookups per second: "+ str(round((t.input_thread.getDomainCount()-t.getQueueSize())/running_seconds,2))
    print "| Running time: "+ str(delta)
    print "|----------------------"


def run():
    t = ManagerThread()
    t.daemon = True #required for ctrl-c exit
    config.start_time = time.time()
    t.start()

    print "Waiting for threads to settle"
    while not t.ready:
        time.sleep(0.2)

    try:
      while t.getActiveThreadCount() >= 1 and t.isAlive():
          if config.debug or True: #TODO TEMP
              printStatus(t)
          time.sleep(1)
      if (t.getActiveThreadCount() == 0):
          print "No valid Proxy threads running!!"
    except KeyboardInterrupt:
        print "Keyboard Interrupt... Exiting"
    else:
        if config.debug:
            print "Done!"
    finally:
        if t.ready and t.input_thread.valid:
          #real status output
          printStatus(t)
          if t.getQueueSize() > 0:
              print "Ending with non-empty queue!"


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("proxy_list",help="file containign a list of http proxies and ports")
    parser.add_argument("domain_list",help="file containing a list of domains to use")
    parser.add_argument("-np",help="Maximum number of proxies to use. Default: 0/All",type=int,default=0)
    parser.add_argument("-o",help="Output directory to store results. Default: out/",default="out")
    parser.add_argument("-s",help="Skip domains that already have results. Default: false",action='store_true',default=False)
    parser.add_argument("-d",help="Enable debug printing",action='store_true',default=False)
    parser.add_argument("-v",help="Enable Email validity check",action='store_true',default=False)
    args = parser.parse_args()

    config.proxy_list = args.proxy_list
    config.domain_list = args.domain_list
    config.num_proxies = args.np
    config.output_folder = args.o+"/"
    config.skip_done = args.s
    config.debug = args.d
    config.result_validCheck = args.v

    run()

