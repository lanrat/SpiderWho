
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
Proxy lists should have one proxy per line in the following format
`http://MyProxyHost:port`
Comments are allowed and start with "#"

### Domain Lists
Domain lists should have one domain per line

## TODO
1. support IP WHOIS
2. Better detection of failures
3. Save incremental logs


