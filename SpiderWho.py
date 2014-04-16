#!/usr/bin/env python
'''
Main SpiderWho entrypoint
See ./SpiderWho.py -h for how to use
'''
import time
from helperThreads import ManagerThread
import datetime
import argparse
import config
import sys
import whoisThread

last_lookups = 0

def set_proc_name(newname):
    try:
        import setproctitle
        setproctitle.setproctitle(newname)
    except:
        pass

def print_status_line():
    '''prints the statusline header'''
    sys.stdout.write("Domains\tLookups\tGood\tFail\tSaved\tActive/Proxies\tLPS\tQsize\tTime")
    sys.stdout.write("\n")
    sys.stdout.flush()

def print_status_data(manager):
    '''updates the statusline data'''
    global last_lookups
    running_seconds = (time.time() - config.START_TIME)

    domains = manager.input_thread.getDomainCount()
    lookups = whoisThread.getLookupCount()
    good_saved = manager.save_thread.getNumGood()
    fail_saved = manager.save_thread.getNumFails()
    total_saved = manager.save_thread.getNumSaved()
    skipped = manager.input_thread.getNumSkipped()
    active_threads = whoisThread.getActiveThreadCount()
    total_threads = whoisThread.getProxyThreadCount()
    running_time = str(datetime.timedelta(seconds=int(running_seconds)))
    last_lps = (lookups-last_lookups)/config.STATUS_UPDATE_DELAY
    total_lps = lookups/running_seconds
    q_size = manager.input_queue.qsize()
    lps = round(((last_lps * 0.8) + (total_lps * 0.2)), 1)

    last_lookups = lookups

    sys.stdout.write("\r%d  \t%d  \t%d  \t%d  \t%d  \t%d / %d  \t%.1f  \t%d \t%s " %
            (domains, lookups, good_saved, fail_saved, total_saved, active_threads, total_threads, lps, q_size, running_time))

    sys.stdout.flush()


def run():
    '''main entrypoint once config has been set by main'''
    manager = ManagerThread()
    manager.daemon = True #required for ctrl-c exit
    config.START_TIME = time.time()
    manager.start()

    if config.DEBUG:
        print "Waiting for threads to settle"
    while not manager.ready:
        time.sleep(0.2)

    if config.PRINT_STATUS:
        print_status_line()
        print_status_data(manager)

    time.sleep(0.5)

    try:
        while whoisThread.getProxyThreadCount() >= 1 and manager.isAlive():
            if config.PRINT_STATUS:
                print_status_data(manager)
            time.sleep(config.STATUS_UPDATE_DELAY)
        if (whoisThread.getProxyThreadCount() == 0):
            print "No valid Proxy threads running!!"
    except KeyboardInterrupt:
        pass
    finally:
        if config.PRINT_STATUS:
            print_status_data(manager)
            sys.stdout.write("\n")
        if config.SAVE_LOGS:
            whoisThread.printExceptionCounts()


if __name__ == '__main__':
    set_proc_name("SpiderWho")
    parser = argparse.ArgumentParser()
    parser.add_argument("proxies", help="file containing a list of http proxies and ports")
    parser.add_argument("domains", help="file containing a list of domains to use")
    parser.add_argument("-np", help="Maximum number of proxies to use. Default: 0/All", type=int, default=0)
    parser.add_argument("-o", help="Output directory to store results. Default: out/", default="out")
    parser.add_argument("-s", help="Skip domains that already have results. Default: false", action='store_true', default=False)
    parser.add_argument("-d", help="Enable debug printing", action='store_true', default=False)
    parser.add_argument("-e", help="Enable Email validity check", action='store_true', default=False)
    parser.add_argument("-l", help="Enable log saving", action='store_true', default=False)
    parser.add_argument("-q", help="Disable status printing", action='store_true', default=False)
    parser.add_argument("-lazy", help="Enable Lazy mode. Give up after a few ratelimits", action='store_true', default=False)
    args = parser.parse_args()

    config.PROXY_LIST = args.proxies
    config.DOMAIN_LIST = args.domains
    config.NUM_PROXIES = args.np
    config.OUTPUT_FOLDER = args.o+"/"
    config.SKIP_DONE = args.s
    config.DEBUG = args.d
    config.RESULT_VALIDCHECK = args.e
    config.PRINT_STATUS = not args.q
    config.SAVE_LOGS = args.l
    config.LAZY_MODE = args.lazy

    run()

