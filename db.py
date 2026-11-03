import os
import psycopg
from psycopg.rows import dict_row
from core import normalize_url

SCHEMA='''
CREATE TABLE IF NOT EXISTS sites (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 url TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', ips TEXT[] NOT NULL DEFAULT '{}',
 http_status INTEGER, noindex BOOLEAN, response_ms INTEGER, tls_days INTEGER,
 final_url TEXT, redirects INTEGER, error TEXT, checked_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS checks (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
 checked_at TIMESTAMPTZ NOT NULL DEFAULT now(), status TEXT NOT NULL,
 http_status INTEGER, response_ms INTEGER, error TEXT);
CREATE INDEX IF NOT EXISTS checks_site_time ON checks(site_id,checked_at DESC);
CREATE TABLE IF NOT EXISTS outbox (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 site_id BIGINT REFERENCES sites(id) ON DELETE SET NULL,
 url TEXT NOT NULL, details TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 sent_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS bootstrap (key TEXT PRIMARY KEY);
'''

def connect():
    return psycopg.connect(os.environ['DATABASE_URL'],row_factory=dict_row,autocommit=True)

def init(conn):
    with conn.transaction():
        for statement in SCHEMA.split(';'):
            if statement.strip(): conn.execute(statement)

def seed(conn,filename='urls.txt'):
    with conn.transaction():
        conn.execute('SELECT pg_advisory_xact_lock(839174)')
        if conn.execute("SELECT 1 FROM bootstrap WHERE key='seeded'").fetchone(): return 0
        with open(filename,encoding='utf-8-sig') as f:
            urls={normalize_url(x) for x in f if x.strip()}
        for url in sorted(urls):
            conn.execute('INSERT INTO sites(url,name) VALUES (%s,%s) ON CONFLICT(url) DO NOTHING',(url,url.split('//',1)[1]))
        conn.execute("INSERT INTO bootstrap(key) VALUES ('seeded')")
        return len(urls)

def apply_result(conn,site_id,result):
    with conn.transaction():
        old=conn.execute('SELECT id,url,status FROM sites WHERE id=%s FOR UPDATE',(site_id,)).fetchone()
        if old is None: return False
        conn.execute('''UPDATE sites SET status=%s,ips=%s,http_status=%s,noindex=%s,
          response_ms=%s,tls_days=%s,final_url=%s,redirects=%s,error=%s,checked_at=now() WHERE id=%s''',
          (result['status'],result['ips'],result['http_status'],result['noindex'],result['response_ms'],
           result['tls_days'],result['final_url'],result['redirects'],result['error'],site_id))
        conn.execute('INSERT INTO checks(site_id,status,http_status,response_ms,error) VALUES (%s,%s,%s,%s,%s)',
                     (site_id,result['status'],result['http_status'],result['response_ms'],result['error']))
        if (os.getenv('EMAIL_ENABLED','false').lower()=='true' and
            ((result['status']=='critical' and old['status']!='critical') or
             (result['status']=='warning' and old['status'] not in ('warning','critical')))):
            text=(f"Status: {result['status']}\nHTTP: {result['http_status']}\n"
                  f"Fehler: {result['error'] or '-'}\nNoindex: {result['noindex']}\n"
                  f"TLS Resttage: {result['tls_days']}\nAntwortzeit: {result['response_ms']} ms")
            conn.execute('INSERT INTO outbox(site_id,url,details) VALUES (%s,%s,%s)',(site_id,old['url'],text))
        return True
