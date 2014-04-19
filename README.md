
#SpiderWho

### A fast WHOIS crawler

## Usage
```
usage: SpiderWho.py [-h] [-n NUMPROXIES] [-o OUT] [-s] [-d] [-e] [-l] [-q]
                    [-z]
                    proxies domains

positional arguments:
  proxies               file containing a list of proxies and ports
  domains               file containing a list of domains to use

optional arguments:
  -h, --help            show this help message and exit
  -n NUMPROXIES, --numProxies NUMPROXIES
                        Maximum number of proxies to use. All=0 Default: 0
  -o OUT, --out OUT     Output directory to store results. Default: out/
  -s, --skip            Skip domains that already have results. Default: False
  -d, --debug           Enable debug printing
  -e, --emailVerify     Enable Email validity check
  -l, --log             Enable log saving
  -q, --quiet           Disable status printing
  -z, --lazy            Enable Lazy mode. Give up after a few ratelimits
```

### Proxy Lists
Proxy lists should have one proxy per line in the following format:  
`http://MyProxyHost:port`.  
Both http and socks proxies are supported Comments are allowed and start with "#".

### Domain Lists
Domain lists should have one domain per line.
List may contain domain names or IP addresses.

### Lazy mode
Lazy mode will increase your LPS and overall speed at the cost of accuracy
In lazy mode, if a WHOIS server has a rate limit much stronger than what we expect we will fail the domain after 3 attempts.
In normal mode we will try until we get a result.

### Output
```
Domains Lookups Good    Fail    Saved   Skipped ActiveT TotalT  LPS     Time
11219   1611    1021    70      1091    0       100     242     77.00   0:00:20
```
Domains: Total domains loaded into the crawler.  
Lookups: Total number of WHOIS queries performed.  
Good: Total number of successful saves.  
Fail: Total number of queries that have failed more than the max retries amount.  
Saved: Total number of saved queries. When logging is disabled this number is equal to Good.  
Sipped: The total number of domains that have been skipped because a result was already found in the output directory.  
ActiveT: The number of active threads actively performing a WHOIS query not waiting due to rate limiting.  
TotalT: The total number of working and active proxies. This number may change as proxies provided go up or down.  
LPS: Lookups per second. How many queries have been performed each second.  
Time: The total running time of the program.  

### Advanced Settings
Advanced settings can be changed in config.py.  
config.py contains default values that can be overridden  by command arguments.

## TODO
1. Adaptive query back-off
2. Support for whois servers that forward to http
3. Update this README

