import sys
from pywhois.whois.parser import WhoisEntry
from pywhois.whois.whois import NICClient


def whois(domain):
  #always use the native python client
  whoisClient = NICClient();
  text = whoisClient.whois_lookup(None, domain, 0) #what do these do?
  result = WhoisEntry.load(domain,text)
  return result

if __name__ == '__main__':
  print(whois(sys.argv[0]))

