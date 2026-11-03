"""DNS/HTTP checks. Connections are pinned to validated public IPs."""
import http.client
from html.parser import HTMLParser
import ipaddress
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

TIMEOUT = 8
MAX_BODY = 512_000
MAX_REDIRECTS = 5
USER_AGENT = 'Sitewatch/1.0 (contact: digital-service@berendsohn.com)'

class UnsafeTarget(ValueError):
    pass

def valid_host(host):
    if not host or len(host)>253 or '.' not in host:
        return False
    try:
        host=host.encode('idna').decode('ascii').lower()
    except UnicodeError:
        return False
    labels=host.split('.')
    return all(0<len(x)<=63 and x[0].isalnum() and x[-1].isalnum() and
               all(c.isascii() and (c.isalnum() or c=='-') for c in x) for x in labels)

def normalize_url(raw):
    raw=raw.strip()
    if not raw or any(c.isspace() for c in raw):
        raise ValueError('Ungueltige URL')
    parsed=urlsplit(raw if '://' in raw else 'https://'+raw)
    if parsed.scheme not in ('http','https') or parsed.username or parsed.password or parsed.port not in (None,80,443):
        raise ValueError('Nur HTTP(S) ohne Zugangsdaten und Sonderport erlaubt')
    host=(parsed.hostname or '').encode('idna').decode('ascii').lower()
    if not valid_host(host) or parsed.path not in ('','/') or parsed.query or parsed.fragment:
        raise ValueError('Bitte nur eine Domain bzw. Startseiten-URL angeben')
    return f'{parsed.scheme}://{host}'

def resolve_public(host):
    host=host.encode('idna').decode('ascii').lower()
    if not valid_host(host):
        raise UnsafeTarget('Ungueltiger Host')
    infos=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
    ips=sorted({x[4][0] for x in infos if x[0]==socket.AF_INET})
    if not ips:
        raise OSError('Kein A-Record')
    if any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise UnsafeTarget('Nicht oeffentliche Ziel-IP gesperrt')
    return ips

class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self,host,ip,port=80):
        super().__init__(host,port,timeout=TIMEOUT)
        self.pinned_ip=ip
    def connect(self):
        self.sock=socket.create_connection((self.pinned_ip,self.port),self.timeout)

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,ip,port=443):
        super().__init__(host,port,timeout=TIMEOUT,context=ssl.create_default_context())
        self.pinned_ip=ip
    def connect(self):
        sock=socket.create_connection((self.pinned_ip,self.port),self.timeout)
        try:
            self.sock=self._context.wrap_socket(sock,server_hostname=self.host)
            self.cert_not_after=self.sock.getpeercert()['notAfter']
        except Exception:
            sock.close()
            raise

class RobotsParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.noindex=False
    def handle_starttag(self,tag,attrs):
        if tag.lower()!='meta': return
        d=dict((k.lower(),(v or '').lower()) for k,v in attrs)
        if d.get('name') in ('robots','googlebot') and 'noindex' in d.get('content','').replace(' ','').split(','):
            self.noindex=True

def fetch(url):
    start=time.monotonic()
    first_ips=None
    hops=0
    while True:
        u=urlsplit(url)
        if u.scheme not in ('http','https') or u.username or u.password or u.port not in (None,80,443) or not valid_host(u.hostname):
            raise UnsafeTarget('Unsichere Weiterleitung gesperrt')
        host=u.hostname.encode('idna').decode('ascii').lower()
        ips=resolve_public(host)
        if first_ips is None: first_ips=ips
        port=u.port or (443 if u.scheme=='https' else 80)
        conn=PinnedHTTPS(host,ips[0],port) if u.scheme=='https' else PinnedHTTP(host,ips[0],port)
        path=(u.path or '/')+('?' + u.query if u.query else '')
        try:
            conn.request('GET',path,headers={'Host':host,'User-Agent':USER_AGENT,'Accept':'text/html','Accept-Encoding':'identity','Connection':'close'})
            resp=conn.getresponse()
            status=resp.status
            headers={k.lower():v for k,v in resp.getheaders()}
            cert_days=None
            if u.scheme=='https':
                cert_days=max(0,int((ssl.cert_time_to_seconds(conn.cert_not_after)-time.time())//86400))
            if status in (301,302,303,307,308) and headers.get('location'):
                hops+=1
                if hops>MAX_REDIRECTS: raise OSError('Zu viele Weiterleitungen')
                url=urljoin(url,headers['location'])
                continue
            body=resp.read(MAX_BODY+1)
            parser=RobotsParser()
            if 'text/html' in headers.get('content-type','').lower():
                parser.feed(body[:MAX_BODY].decode('utf-8','replace'))
            xr=headers.get('x-robots-tag','').lower().replace(' ','')
            blocked=parser.noindex or any('noindex' in item.split(':')[-1].split(',') for item in xr.split(';'))
            return {'ips':first_ips,'http_status':status,'noindex':blocked,
                    'response_ms':int((time.monotonic()-start)*1000),'tls_days':cert_days,
                    'final_url':url[:2000],'redirects':hops,
                    'error':'HTML ueber 512 KB abgeschnitten' if len(body)>MAX_BODY else None}
        finally:
            conn.close()

def check(url):
    host=urlsplit(url).hostname
    result={'ips':[],'http_status':None,'noindex':False,'response_ms':None,'tls_days':None,
            'final_url':None,'redirects':0,'error':None}
    try:
        result['ips']=resolve_public(host)
        result.update(fetch(url))
    except (OSError,ValueError,ssl.SSLError,http.client.HTTPException) as exc:
        result['error']=f'{type(exc).__name__}: {str(exc)[:250]}'
    if result['http_status'] is None or not 200<=result['http_status']<300 or result['noindex'] or result['tls_days']==0:
        result['status']='critical'
    elif result['tls_days'] is not None and result['tls_days']<=14 or (result['response_ms'] or 0)>2000:
        result['status']='warning'
    else:
        result['status']='healthy'
    return result
