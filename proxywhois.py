#!/usr/bin/env python
#taken from pywhois class with some modifications

from SocksiPy import socks

debug = False

def enforce_ascii(a):
    if isinstance(a, str) or isinstance(a, unicode):
        # return a.encode('ascii', 'replace')
        r = ""
        for i in a:
            if ord(i) >= 128:
                r += "?"
            else:
                r += i
        return r
    else:
        return a


class NICClient(object) :

    ABUSEHOST           = "whois.abuse.net"
    NICHOST             = "whois.crsnic.net"
    INICHOST            = "whois.networksolutions.com"
    DNICHOST            = "whois.nic.mil"
    GNICHOST            = "whois.nic.gov"
    ANICHOST            = "whois.arin.net"
    LNICHOST            = "whois.lacnic.net"
    RNICHOST            = "whois.ripe.net"
    PNICHOST            = "whois.apnic.net"
    MNICHOST            = "whois.ra.net"
    QNICHOST_TAIL       = ".whois-servers.net"
    SNICHOST            = "whois.6bone.net"
    BNICHOST            = "whois.registro.br"
    NORIDHOST           = "whois.norid.no"
    IANAHOST            = "whois.iana.org"
    DENICHOST           = "de.whois-servers.net"
    DEFAULT_PORT        = "nicname"
    WHOIS_SERVER_ID     = "Whois Server:"
    WHOIS_ORG_SERVER_ID = "Registrant Street1:Whois Server:"


    WHOIS_RECURSE       = 0x01
    WHOIS_QUICK         = 0x02

    ip_whois = [ LNICHOST, RNICHOST, PNICHOST, BNICHOST ]

    def __init__(self) :
        self.use_qnichost = False
        self.use_proxy = False
        self.proxy_type = None
        self.proxy_server = None
        self.proxy_port = None

    def set_proxy(self,proxy_type,server,port):
        """Enables the use of the specified proxy for lookups"""
        self.use_proxy = True
        self.proxy_type = proxy_type
        self.proxy_server = server
        self.proxy_port = port

    def findwhois_server(self, buf, hostname):
        """Search the initial TLD lookup results for the regional-specifc
        whois server for getting contact details.
        """
        #print 'finding whois server'
        #print 'parameters:', buf, 'hostname', hostname
        nhost = None
        parts_index = 1
        start = buf.find(NICClient.WHOIS_SERVER_ID)
        #print 'start', start
        if (start == -1):
            start = buf.find(NICClient.WHOIS_ORG_SERVER_ID)
            parts_index = 2

        if (start > -1):  
            end = buf[start:].find('\n')
            #print 'end:', end
            whois_line = buf[start:end+start]
            #print 'whois_line', whois_line
            nhost = whois_line.split(NICClient.WHOIS_SERVER_ID+' ').pop()
            nhost = nhost.split('http://').pop()
            #if the whois address is domain.tld/something then
            #s.connect((hostname, 43)) does not work
            if nhost.count('/') > 0:
                nhost = None
            #print 'nhost:',nhost
        elif (hostname == NICClient.ANICHOST):
            for nichost in NICClient.ip_whois:
                if (buf.find(nichost) != -1):
                    nhost = nichost
                    break
        return nhost

    def whois(self, query, hostname, flags):
        """Perform initial lookup with TLD whois server
        then, if the quick flag is false, search that result
        for the region-specifc whois server and do a lookup
        there for contact details
        """
        if debug:
          print 'parameters given:', query, hostname, flags
        #pdb.set_trace()
        s = socks.socksocket(socks.socket.AF_INET, socks.socket.SOCK_STREAM)

        #added code for proxy
        if (self.use_proxy):
          s.setproxy(self.proxy_type,self.proxy_server,self.proxy_port)

        #convert hostname to ascii
        hostname = hostname.encode('ascii','ignore')

        s.connect((hostname, 43))
        """send takes bytes as an input
        """
        queryBytes = None
        if (hostname == NICClient.DENICHOST):
            #print 'the domain is in NIC DENIC'
            queryBytes = ("-T dn,ace -C UTF-8 " + query + "\r\n").encode()
            #print 'queryBytes:', queryBytes
        else:
            queryBytes = (query  + "\r\n").encode()
        s.send(queryBytes)
        """recv returns bytes
        """
        #print s
        response = b''
        while True:
            d = s.recv(4096)
            response += d
            if not d:
                break
        s.close()
        #pdb.set_trace()
        nhost = None
        if debug:
          print '===========response=============='
          print response
          print "================================="
        response = enforce_ascii(response)
        if (flags & NICClient.WHOIS_RECURSE and nhost == None):
            nhost = self.findwhois_server(response.decode(), hostname)
        if (nhost != None):
            response += self.whois(query, nhost, 0)
        #print 'returning whois response'
        return response.decode()
   
    def choose_server(self, domain):
        """Choose initial lookup NIC host"""
        if (domain.endswith("-NORID")):
            return NICClient.NORIDHOST
        pos = domain.rfind('.')
        if (pos == -1):
            return None
        tld = domain[pos+1:]
        if (tld[0].isdigit()):
            return NICClient.ANICHOST
   
        return tld + NICClient.QNICHOST_TAIL
   
    def whois_lookup(self, options, query_arg, flags):
        """Main entry point: Perform initial lookup on TLD whois server,
        or other server to get region-specific whois server, then if quick
        flag is false, perform a second lookup on the region-specific
        server for contact records"""
        #print 'whois_lookup'
        nichost = None
        #pdb.set_trace()
        # this would be the case when this function is called by other than main
        if (options == None):                    
            options = {}
     
        if ( (not 'whoishost' in options or options['whoishost'] == None)
            and (not 'country' in options or options['country'] == None)):
            self.use_qnichost = True
            options['whoishost'] = NICClient.NICHOST
            if ( not (flags & NICClient.WHOIS_QUICK)):
                flags |= NICClient.WHOIS_RECURSE
           
        if ('country' in options and options['country'] != None):
            result = self.whois(query_arg, options['country'] + NICClient.QNICHOST_TAIL, flags)
        elif (self.use_qnichost):
            nichost = self.choose_server(query_arg)
            if (nichost != None):
                result = self.whois(query_arg, nichost, flags)
        else:
            result = self.whois(query_arg, options['whoishost'], flags)
        #print 'whois_lookup finished'
        return result
#---- END OF NICClient class def ---------------------

if __name__ == "__main__":
  import sys #for args
  flags = 0
  nic_client = NICClient()
  #(options, args) = parse_command_line(sys.argv)
  #if (options.b_quicklookup is True):
  #    flags = flags|NICClient.WHOIS_QUICK
  #print(nic_client.whois_lookup(options.__dict__, args[1], flags))
  print(nic_client.whois_lookup(None, sys.argv[1], 0))
