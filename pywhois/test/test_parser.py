import unittest

import os
import sys
sys.path.append('../')

import datetime

import simplejson
from glob import glob

from whois.parser import WhoisEntry, cast_date

class TestParser(unittest.TestCase):
    def test_com_expiration(self):
        data = """
            Status: ok
            Updated Date: 14-apr-2008
            Creation Date: 14-apr-2008
            Expiration Date: 14-apr-2009
            
            >>> Last update of whois database: Sun, 31 Aug 2008 00:18:23 UTC <<<
        """
        w = WhoisEntry.load('urlowl.com', data)
        expires = w.expiration_date.strftime('%Y-%m-%d')
        self.assertEquals(expires, '2009-04-14')

    def test_cast_date(self):
        dates = ['14-apr-2008', '2008-04-14']
        for d in dates:
            r = cast_date(d).strftime('%Y-%m-%d')
            self.assertEquals(r, '2008-04-14')

    def test_com_allsamples(self):
        """
        Iterate over all of the sample/whois/*.com files, read the data,
        parse it, and compare to the expected values in sample/expected/.
        Only keys defined in keys_to_test will be tested.
        
        To generate fresh expected value dumps, see NOTE below.
        """
        keys_to_test = ['domain_name', 'expiration_date', 'updated_date', 'creation_date', 'status']
        fail = 0
        for path in glob('test/samples/whois/*.com'):
            # Parse whois data
            domain = os.path.basename(path)
            whois_fp = open(path)
            data = whois_fp.read()
            
            w = WhoisEntry.load(domain, data)
            results = {}
            for key in keys_to_test:
                results[key] = w.get(key)

            # Load expected result
            expected_fp = open(os.path.join('test/samples/expected/', domain))
            expected_results = simplejson.load(expected_fp)
            
            # NOTE: Toggle condition below to write expected results from the parse results
            # This will overwrite the existing expected results. Only do this if you've manually
            # confirmed that the parser is generating correct values at its current state.
            if False:
                expected_fp = open(os.path.join('test/samples/expected/', domain), 'w')
                expected_results = simplejson.dump(results, expected_fp)
                continue
            
            # Compare each key
            for key in results:
                result = results.get(key)
                expected = expected_results.get(key)
                if expected != result:
                    print "%s \t(%s):\t %s != %s" % (domain, key, result, expected)
                    fail += 1
            
        if fail:
            self.fail("%d sample whois attributes were not parsed properly!" % fail)


if __name__ == '__main__':
    unittest.main()
