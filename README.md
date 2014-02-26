
#SpiderWho

### A fast WHOIS crawler

## Usage
```
usage: SpiderWho.py [-h] [-np NP] [-o O] [-s] [-d] [-e] [-l] [-q]
                    proxy_list domain_list

positional arguments:
  proxy_list   file containing a list of http proxies and ports
  domain_list  file containing a list of domains to use

optional arguments:
  -h, --help   show this help message and exit
  -np NP       Maximum number of proxies to use. Default: 0/All
  -o O         Output directory to store results. Default: out/
  -s           Skip domains that already have results. Default: false
  -d           Enable debug printing
  -e           Enable Email validity check
  -l           Enable log saving
  -q           Disable status printing
```

### Proxy Lists
Proxy lists should have one proxy per line in the following format:
`http://MyProxyHost:port`.
Comments are allowed and start with "#".

### Domain Lists
Domain lists should have one domain per line

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
TotalT: The total number of worker threads, should be the same as number of proxies.  
LPS: Lookups per second. How many queries have been performed each second.  
Time: The total running time of the program.  

## TODO
1. support IP WHOIS
2. Better detection of failures
3. Save incremental logs


