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


def getTerminalSize():
    """
    stolen from http://stackoverflow.com/questions/566746/how-to-get-console-window-width-in-python
    returns (width, height)
    """
    import os
    env = os.environ
    def ioctl_GWINSZ(fd):
        try:
            import fcntl, termios, struct, os
            cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ,
        '1234'))
        except:
            return
        return cr
    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except:
            pass
    if not cr:
        cr = (env.get('LINES', 25), env.get('COLUMNS', 80))

        ### Use get(key[, default]) instead of a try/catch
        #try:
        #    cr = (env['LINES'], env['COLUMNS'])
        #except:
        #    cr = (25, 80)
    return int(cr[1]), int(cr[0])

def print_status_line():
    '''prints the statusline header'''
    title = "\r%9s  %9s  %6s  %9s  %7s/%-7s  %6s  %s" % ("All", "New", "Fail", "Completed", "Active", "Proxies", "LPS", "Time")
    sys.stdout.write(title)
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
    lps = round(((last_lps * 0.8) + (total_lps * 0.2)), 1)
    last_lookups = lookups
    allDomains = domains + skipped
    
    failp = 0.0
    if total_saved != 0:
        failp = 100.0 * ( float(fail_saved) / float(total_saved + skipped) )

    # term info
    #(width, height) = getTerminalSize()
    
    data = "\r%9d  %9d  %5.1f%%  %9d  %6d / %-6d  %6.1f  %s " % (allDomains, domains, failp, good_saved, active_threads, total_threads, lps, running_time)

    sys.stdout.write(data)
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
        while whoisThread.getProxyThreadCount() > 0 and manager.isAlive():
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
    parser.add_argument("proxies", help="file containing a list of proxies and ports")
    parser.add_argument("domains", help="file containing a list of domains to use")
    parser.add_argument("-n", "--numProxies", help="Maximum number of proxies to use. All=0 Default: "+str(config.NUM_PROXIES), type=int, default=config.NUM_PROXIES)
    parser.add_argument("-o", "--out", help="Output directory to store results. Default: "+config.OUTPUT_FOLDER, default=config.OUTPUT_FOLDER)
    parser.add_argument("-s", "--skip", help="Skip domains that already have results. Default: "+str(config.SKIP_DONE), action='store_true', default=config.SKIP_DONE)
    parser.add_argument("-sn", "--skipNumber", help="Skip n domains that already have results. Default: 0", type=int, default=config.SKIP_DOMAINS)
    parser.add_argument("-d", "--debug", help="Enable debug printing", action='store_true', default=config.DEBUG)
    parser.add_argument("-e", "--emailVerify", help="Enable Email validity check", action='store_true', default=config.RESULT_VALIDCHECK)
    parser.add_argument("-l", "--log", help="Enable log saving", action='store_true', default=config.SAVE_LOGS)
    parser.add_argument("-q", "--quiet", help="Disable status printing", action='store_true', default=(not config.PRINT_STATUS))
    parser.add_argument("-z", "--lazy", help="Enable Lazy mode. Give up after a few ratelimits", action='store_true', default=config.LAZY_MODE)
    args = parser.parse_args()

    config.PROXY_LIST = args.proxies
    config.DOMAIN_LIST = args.domains
    config.NUM_PROXIES = args.numProxies
    config.OUTPUT_FOLDER = args.out+"/"
    config.SKIP_DONE = args.skip
    config.DEBUG = args.debug
    config.RESULT_VALIDCHECK = args.emailVerify
    config.PRINT_STATUS = not args.quiet
    config.SAVE_LOGS = args.log
    config.LAZY_MODE = args.lazy
    config.SKIP_DOMAINS = args.skipNumber

    run()

