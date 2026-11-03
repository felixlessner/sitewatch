"""Local-only generator for the Render ADMIN_PASSWORD_HASH secret."""
import getpass
import hashlib
import os
import sys
password=getpass.getpass('Neues Admin-Passwort: ')
if len(password)<16:
    sys.exit('Bitte mindestens 16 Zeichen verwenden.')
salt=os.urandom(16)
print('scrypt$'+salt.hex()+'$'+hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1).hex())
