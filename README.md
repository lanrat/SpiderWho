
# SpiderWho

### A fast WHOIS crawler

## Usage
```
usage: SpiderWho.py [-h] [-n NUMPROXIES] [-o OUT] [-f] [-s] [-sn SKIPNUMBER]
                    [-d] [-e] [-l] [-q] [-z]
                    proxies domains

positional arguments:
  proxies               file containing a list of proxies and ports
  domains               file containing a list of domains to use

optional arguments:
  -h, --help            show this help message and exit
  -n NUMPROXIES, --numProxies NUMPROXIES
                        Maximum number of proxies to use. All=0 Default: 0
  -o OUT, --out OUT     Output directory to store results. Default: out/
  -f, --files           Output to files instead of tgz. Default: False
  -s, --skip            Skip domains that already have results. Only
                        compatible with --files Default: False
  -sn SKIPNUMBER, --skipNumber SKIPNUMBER
                        Skip n domains that already have results. Default: 0
  -d, --debug           Enable debug printing
  -e, --emailVerify     Enable Email validity check
  -l, --log             Enable log saving
  -q, --quiet           Disable status printing
  -z, --lazy            Enable Lazy mode. Give up after a few ratelimits
```

### Proxy Lists
Proxy lists should have one proxy per line in the following format:  
`http://MyProxyHost:port`.  
Both http and socks proxies are supported. Comments are allowed and start with "#".

### Domain Lists
Domain lists should have one domain per line.
List may contain domain names or IP addresses.

### Lazy mode
Lazy mode will increase your Lookups per Second (LPS) and overall speed at the cost of accuracy
In lazy mode, if a WHOIS server has a rate limit much stronger than what we expect we will fail the domain after 3 attempts.
In normal mode we will try until we get a result.

### Output
```
Prog       All        New    Fail  Completed   Active/Proxies     DPS  Time
 14%  16803445    2438762    9.7%    2192796      90 / 270       32.3  18:11:47   
```
Prog: How much of the input domain list has been read and queued.
All: How many domains have been scanned as input (also includes skipped domains with the -sn option)
New: Number of domains set to be crawled.
Fail: Percent of domains that have failed more than the max retries amount.
Completed: Total number of domains with saved results.  
Active: The number of active threads actively performing a WHOIS query not waiting due to rate limiting or other blocking operations.
Proxies: The total number of working and proxies. This number may change as proxies provided go up or down.  
DPS/LPS: Domains or Lookups per second. How many queries have been performed each second.  
Time: The total running time of the program.  

### Output Data
By default a .tgz file is created in the output directory with the results that is rotated and named
with the timestamp of the first record it contains.
This behavior an be disabled with the --files option to create a new file for every domain, however
this will cause poor behavior on large scans due to the massive amount of files out into a single directory.

### Advanced Settings
Advanced settings can be changed in config.py.  
config.py contains default values that can be overridden  by command arguments.

## TODO
1. Adaptive query back-off
2. Support for whois servers that forward to http
