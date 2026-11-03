import concurrent.futures
import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from core import check
from db import apply_result,connect,init,seed

logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')

def send_pending(conn):
    if os.getenv('EMAIL_ENABLED','false').lower()!='true':
        logging.info('EMAIL_ENABLED=false; alerts queued')
        return
    required=['SMTP_HOST','SMTP_USER','SMTP_PASSWORD','SMTP_FROM','ALERT_TO']
    if any(not os.getenv(k) for k in required):
        raise RuntimeError('SMTP-Konfiguration unvollstaendig')
    while True:
        with conn.transaction():
            row=conn.execute('SELECT * FROM outbox WHERE sent_at IS NULL ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED').fetchone()
            if row is None: break
            msg=EmailMessage()
            msg['Subject']='Sitewatch-Alarm: '+row['url'][:150]
            msg['From']=os.environ['SMTP_FROM']
            msg['To']=os.environ['ALERT_TO']
            msg.set_content(f"Auffaelligkeit bei {row['url']}\n\n{row['details']}\n\nDashboard: {os.getenv('APP_ORIGIN','https://monitoring.berendsohn.com')}")
            with smtplib.SMTP(os.environ['SMTP_HOST'],int(os.getenv('SMTP_PORT','587')),timeout=12) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                smtp.login(os.environ['SMTP_USER'],os.environ['SMTP_PASSWORD'])
                smtp.send_message(msg)
            conn.execute('UPDATE outbox SET sent_at=now() WHERE id=%s',(row['id'],))

def run():
    with connect() as conn:
        init(conn)
        count=seed(conn)
        logging.info('Seeded %d sites',count)
        if not conn.execute('SELECT pg_try_advisory_lock(839175) AS acquired').fetchone()['acquired']:
            logging.info('Another scan is still running')
            return
        try:
            sites=conn.execute('SELECT id,url FROM sites ORDER BY id').fetchall()
            logging.info('Checking %d sites',len(sites))
            with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
                futures={pool.submit(check,s['url']):s for s in sites}
                for future in concurrent.futures.as_completed(futures):
                    s=futures[future]
                    try:
                        apply_result(conn,s['id'],future.result())
                    except Exception:
                        logging.exception('Failed to save check for site id=%s',s['id'])
            logging.info('Scan completed')
            send_pending(conn)
        finally:
            conn.execute('SELECT pg_advisory_unlock(839175)')

if __name__=='__main__': run()
