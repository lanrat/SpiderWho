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


def print_status_line():
    '''prints the statusline header'''
    sys.stdout.write("Domains\tLookups\tGood\tFail\tSaved\tSkipped\tActiveT\tTotalT\tLPS\tTime")
    sys.stdout.write("\n")
    sys.stdout.flush()


def print_status_data(manager):
    '''updates the statusline data'''
    running_seconds = (time.time() - config.START_TIME)

    domains = manager.input_thread.getDomainCount()
    lookups = manager.getLookupCount()
    good_saved = manager.save_thread.getNumGood()
    fail_saved = manager.save_thread.getNumFails()
    total_saved = manager.save_thread.getNumSaved()
    skipped = manager.input_thread.getNumSkipped()
    active_threads = manager.getActiveThreadCount()
    total_threads = manager.getTotalThreadCount()
    lps = round((lookups/running_seconds), 2)
    running_time = str(datetime.timedelta(seconds=int(running_seconds)))

    sys.stdout.write("\r%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.2f\t%s\t" %
            (domains, lookups, good_saved, fail_saved, total_saved, skipped, active_threads, total_threads, lps, running_time))
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
        while manager.getTotalThreadCount() >= 1 and manager.isAlive():
            if config.PRINT_STATUS:
                print_status_data(manager)
            time.sleep(3)
        if (manager.getTotalThreadCount() == 0):
            print "No valid Proxy threads running!!"
    except KeyboardInterrupt:
        print "\nKeyboard Interrupt... Exiting"
    else:
        if config.PRINT_STATUS:
            print_status_data(manager)
            sys.stdout.write("\n")
        if config.DEBUG:
            print "Done!"


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("proxy_list", help="file containign a list of http proxies and ports")
    parser.add_argument("domain_list", help="file containing a list of domains to use")
    parser.add_argument("-np", help="Maximum number of proxies to use. Default: 0/All", type=int, default=0)
    parser.add_argument("-o", help="Output directory to store results. Default: out/", default="out")
    parser.add_argument("-s", help="Skip domains that already have results. Default: false", action='store_true', default=False)
    parser.add_argument("-d", help="Enable debug printing", action='store_true', default=False)
    parser.add_argument("-v", help="Enable Email validity check", action='store_true', default=False)
    parser.add_argument("-l", help="Disable log saving", action='store_true', default=False)
    parser.add_argument("-q", help="Disable status printing", action='store_true', default=False)
    args = parser.parse_args()

    config.PROXY_LIST = args.proxy_list
    config.DOMAIN_LIST = args.domain_list
    config.NUM_PROXIES = args.np
    config.OUTPUT_FOLDER = args.o+"/"
    config.SKIP_DONE = args.s
    config.DEBUG = args.d
    config.RESULT_VALIDCHECK = args.v
    config.PRINT_STATUS = not args.q
    config.SAVE_LOGS = not args.l

    run()

