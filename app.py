"""Minimal single-admin WSGI API; protected by Basic Auth, HTTPS and Origin checks."""
import base64
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from urllib.parse import parse_qs
from core import normalize_url
from db import connect,init,seed

ROOT=Path(__file__).parent
HEADERS=[('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),
         ('Referrer-Policy','no-referrer'),('X-Frame-Options','DENY'),
         ('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")]

def password_hash(password,salt=None):
    salt=salt or os.urandom(16)
    return 'scrypt$'+salt.hex()+'$'+hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1).hex()

def authorized(environ):
    raw=environ.get('HTTP_AUTHORIZATION','')
    if not raw.startswith('Basic '): return False
    try:
        user,password=base64.b64decode(raw[6:],validate=True).decode('utf-8').split(':',1)
        algo,salt,hashvalue=os.environ['ADMIN_PASSWORD_HASH'].split('$')
        if algo!='scrypt': return False
        actual=password_hash(password,bytes.fromhex(salt)).split('$')[-1]
        return hmac.compare_digest(user,os.getenv('ADMIN_USER','admin')) and hmac.compare_digest(actual,hashvalue)
    except (ValueError,KeyError,UnicodeDecodeError,TypeError):
        return False

def respond(start,status,body,kind='application/json',extra=()):
    payload=body if isinstance(body,bytes) else json.dumps(body,ensure_ascii=False,default=str).encode()
    start(status,HEADERS+[('Content-Type',kind+'; charset=utf-8'),('Content-Length',str(len(payload)))]+list(extra))
    return [payload]

def input_json(environ,limit=16384):
    length=int(environ.get('CONTENT_LENGTH') or 0)
    if length<1 or length>limit: raise ValueError('Ungueltige Eingabegroesse')
    return json.loads(environ['wsgi.input'].read(length))

def application(environ,start_response):
    path=environ.get('PATH_INFO','/')
    method=environ.get('REQUEST_METHOD','GET')
    if path=='/healthz':
        try:
            with connect() as conn: conn.execute('SELECT 1')
            return respond(start_response,'200 OK',{'ok':True})
        except Exception:
            return respond(start_response,'503 Service Unavailable',{'ok':False})
    if not authorized(environ):
        return respond(start_response,'401 Unauthorized',{'error':'Anmeldung erforderlich'},extra=[('WWW-Authenticate','Basic realm="Sitewatch", charset="UTF-8"')])
    if method in ('POST','DELETE','PUT','PATCH') and environ.get('HTTP_ORIGIN')!=os.getenv('APP_ORIGIN','https://monitoring.berendsohn.com'):
        return respond(start_response,'403 Forbidden',{'error':'Ungueltiger Origin'})
    if path=='/' and method=='GET':
        return respond(start_response,'200 OK',(ROOT/'static'/'index.html').read_bytes(),'text/html')
    if path=='/app.js' and method=='GET':
        return respond(start_response,'200 OK',(ROOT/'static'/'app.js').read_bytes(),'application/javascript')
    if path=='/app.css' and method=='GET':
        return respond(start_response,'200 OK',(ROOT/'static'/'app.css').read_bytes(),'text/css')
    try:
        with connect() as conn:
            init(conn)
            seed(conn,str(ROOT/'urls.txt'))
            if path=='/api/summary' and method=='GET':
                counts=conn.execute('SELECT status,count(*) AS n FROM sites GROUP BY status').fetchall()
                last=conn.execute('SELECT max(checked_at) AS last FROM sites').fetchone()['last']
                return respond(start_response,'200 OK',{'counts':{r['status']:r['n'] for r in counts},'last':last})
            if path=='/api/sites' and method=='GET':
                params=parse_qs(environ.get('QUERY_STRING',''))
                page=max(1,min(10000,int(params.get('page',['1'])[0])))
                status=params.get('status',['all'])[0]
                if status not in ('all','healthy','warning','critical','pending'): raise ValueError('Ungueltiger Status')
                term=params.get('q',[''])[0].strip()[:120]
                clauses=[];values=[]
                if status!='all': clauses.append('status=%s');values.append(status)
                if term: clauses.append('(url ILIKE %s OR name ILIKE %s)');values.extend(['%'+term+'%','%'+term+'%'])
                where=' WHERE '+' AND '.join(clauses) if clauses else ''
                total=conn.execute('SELECT count(*) AS n FROM sites'+where,values).fetchone()['n']
                rows=conn.execute('SELECT * FROM sites'+where+''' ORDER BY CASE status WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 WHEN 'pending' THEN 2 ELSE 3 END, name LIMIT 50 OFFSET %s''',values+[50*(page-1)]).fetchall()
                return respond(start_response,'200 OK',{'items':rows,'total':total,'page':page,'page_size':50})
            if path=='/api/sites' and method=='POST':
                data=input_json(environ); url=normalize_url(str(data.get('url','')))
                name=str(data.get('name','')).strip()[:100] or url.split('//',1)[1]
                row=conn.execute('INSERT INTO sites(url,name) VALUES (%s,%s) ON CONFLICT(url) DO NOTHING RETURNING id',(url,name)).fetchone()
                return respond(start_response,'201 Created' if row else '409 Conflict',{'id':row['id']} if row else {'error':'Bereits vorhanden'})
            if path=='/api/import' and method=='POST':
                data=input_json(environ,limit=600000)
                lines=str(data.get('text','')).splitlines()
                if not 1<=len(lines)<=5000: raise ValueError('1 bis 5000 Zeilen erlaubt')
                added=skipped=0
                with conn.transaction():
                    for line in lines:
                        if not line.strip(): continue
                        parts=line.split(';',1)
                        try: url=normalize_url(parts[0])
                        except ValueError: skipped+=1;continue
                        name=(parts[1].strip()[:100] if len(parts)>1 else '') or url.split('//',1)[1]
                        if conn.execute('INSERT INTO sites(url,name) VALUES (%s,%s) ON CONFLICT(url) DO NOTHING RETURNING id',(url,name)).fetchone(): added+=1
                        else: skipped+=1
                return respond(start_response,'200 OK',{'added':added,'skipped':skipped})
            m=re.fullmatch(r'/api/sites/(\d+)',path)
            if m and method=='DELETE':
                row=conn.execute('DELETE FROM sites WHERE id=%s RETURNING id',(int(m[1]),)).fetchone()
                return respond(start_response,'200 OK' if row else '404 Not Found',{'deleted':bool(row)})
            m=re.fullmatch(r'/api/checks/(\d+)',path)
            if m and method=='GET':
                rows=conn.execute('SELECT checked_at,status,http_status,response_ms,error FROM checks WHERE site_id=%s ORDER BY checked_at DESC LIMIT 30',(int(m[1]),)).fetchall()
                return respond(start_response,'200 OK',{'items':rows})
        return respond(start_response,'404 Not Found',{'error':'Nicht gefunden'})
    except (ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        return respond(start_response,'400 Bad Request',{'error':str(exc)[:200]})
    except Exception:
        import logging
        logging.exception('API failure')
        return respond(start_response,'500 Internal Server Error',{'error':'Serverfehler; bitte Logs pruefen'})
