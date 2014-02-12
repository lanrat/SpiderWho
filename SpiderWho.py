#!/usr/bin/env python
import time
from helperThreads import ManagerThread
import datetime
import argparse
import config
import sys


def printStatusLine():
    sys.stdout.write("Domains\tLookups\tGood\tFail\tSaved\tSkipped\tActiveT\tTotalT\tLPS\tTime")
    sys.stdout.write("\n")
    sys.stdout.flush()


def printStatusData(m):
    running_seconds = (time.time() - config.start_time)

    domains = m.input_thread.getDomainCount()
    lookups = m.getLookupCount()
    good_saved = m.save_thread.getNumGood()
    fail_saved = m.save_thread.getNumFails()
    total_saved = m.save_thread.getNumSaved()
    skipped = m.input_thread.getNumSkipped()
    active_threads = m.getActiveThreadCount()
    total_threads = m.getTotalThreadCount()
    lps = round((lookups/running_seconds),2)
    running_time = str(datetime.timedelta(seconds=int(running_seconds)))

    sys.stdout.write("\r%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.2f\t%s\t" %
            (domains, lookups, good_saved, fail_saved, total_saved, skipped, active_threads,
                total_threads, lps, running_time))
    sys.stdout.flush()


def run():
    t = ManagerThread()
    t.daemon = True #required for ctrl-c exit
    config.start_time = time.time()
    t.start()

    if config.debug:
        print "Waiting for threads to settle"
    while not t.ready:
        time.sleep(0.2)

    if config.print_status:
        printStatusLine()
        printStatusData(t)

    time.sleep(0.5)

    try:
        while t.getTotalThreadCount() >= 1 and t.isAlive():
            if config.print_status:
                printStatusData(t)
            time.sleep(1)
        if (t.getTotalThreadCount() == 0):
            print "No valid Proxy threads running!!"
    except KeyboardInterrupt:
        print "\nKeyboard Interrupt... Exiting"
    else:
        if config.print_status:
            printStatusData(t)
            sys.stdout.write("\n")
        if config.debug:
            print "Done!"
    finally:
        if t.ready and t.input_thread.valid:
            if config.debug and t.getQueueSize() > 0:
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
    parser.add_argument("-q",help="Disable status printing",action='store_true',default=False)
    args = parser.parse_args()

    config.proxy_list = args.proxy_list
    config.domain_list = args.domain_list
    config.num_proxies = args.np
    config.output_folder = args.o+"/"
    config.skip_done = args.s
    config.debug = args.d
    config.result_validCheck = args.v
    config.print_status = not args.q

    run()
