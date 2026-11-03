import unittest
from unittest.mock import patch
import sys
sys.path.insert(0,'.')
from core import normalize_url,resolve_public,UnsafeTarget,RobotsParser,check

class Tests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_url('Schuengel-Ing.de'),'https://schuengel-ing.de')
        for url in ('https://user:secret@example.com','http://example.com:2222','example.com/path','file:///etc/passwd'):
            with self.assertRaises(ValueError): normalize_url(url)
    @patch('core.socket.getaddrinfo')
    def test_ssrf_block(self,dns):
        dns.return_value=[(2,1,6,'',('127.0.0.1',0)),(2,1,6,'',('8.8.8.8',0))]
        with self.assertRaises(UnsafeTarget): resolve_public('example.com')
    def test_robots(self):
        p=RobotsParser();p.feed('<html><meta content="nofollow, noindex" name="robots"></html>')
        self.assertTrue(p.noindex)
    @patch('core.resolve_public',return_value=['8.8.8.8'])
    @patch('core.fetch')
    def test_status(self,fetch,_dns):
        clean={'ips':['8.8.8.8'],'http_status':200,'noindex':False,'response_ms':180,'tls_days':35,'final_url':'https://example.com','redirects':0,'error':None}
        fetch.return_value=clean
        self.assertEqual(check('https://example.com')['status'],'healthy')
        fetch.return_value={**clean,'noindex':True}
        self.assertEqual(check('https://example.com')['status'],'critical')
        fetch.return_value={**clean,'tls_days':10}
        self.assertEqual(check('https://example.com')['status'],'warning')
        fetch.return_value={**clean,'http_status':503}
        self.assertEqual(check('https://example.com')['status'],'critical')

if __name__=='__main__': unittest.main()
