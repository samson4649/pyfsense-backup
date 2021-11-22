#!/usr/bin/env python3

import urllib3
urllib3.disable_warnings()

import requests
import os
import sys
import time 
from bs4 import BeautifulSoup as bs 

is_debug=True

def debug(title,obj):
    global is_debug
    if is_debug:
        print(f'[DEBUG] {title}: {obj}')

def _error(msg):
    print(f'[ERROR] {msg}')

class CSRF:
    def __init__(self,s=None):
        self._raw = s
        if s:
            self._parse(s)

    def __str__(self):
        return f'CSRF(sid={self.sid} | ip={self.ip})'

    def _parse(self,s):
        _s = s.split(';')
        _c = []
        _c.append( _s[0].split(':')[1] )
        self.sid = _c[0]
        try:
            _c.append( _s[1].split(':')[1] )
            self.ip  = _c[1]
        except:
            pass
        return _c

    def Find(self,resp):
        soup  = bs(resp,features="lxml")
        forms = soup.find('form')
        self._raw = forms.find('input',{'name':'__csrf_magic'}).get('value') 
        self._parse(self._raw)

    def SID(self):
        return f'sid:{self.sid}'

    def IP(self):
        return f'ip:{self.ip}'

if "__main__" == __name__:
    import argparse
    parser = argparse.ArgumentParser(description='Download pfSense backup XML')
    parser.add_argument('--url','-u', required=True, help='URL of the pfSense web application')
    parser.add_argument('--creds','-c', required=False, help='File containing pfSense login info in <username>:<password> form')
    parser.add_argument('--creds-raw', required=False, help='pfSense login info in <username>:<password> form')
    parser.add_argument('--outfile','-o', required=True, help='Output file')
    parser.add_argument('--insecure', required=False, help='whether to skip verification of TLS')
    parser.add_argument('--debug', required=False, action='store_true', help='debug output')
    args = parser.parse_args()

    is_debug = args.debug

    if not args.creds and not args.creds_raw:
        args.creds_raw = 'admin:pfsense'

    elif args.creds and not args.creds_raw:
        try:
            with open(args.creds,'rb') as fd:
                for line in fd:
                    args.creds_raw = line.rstrip().decode()
        except FileNotFoundError as err:
            _error(str(err))
            sys.exit(9)

    username,password = args.creds_raw.split(':')
    debug("AUTH",f'username: {username}')
    debug("AUTH",f'password: {password}')
    
    outfile = 'backup.xml'
    
    base_url = args.url

    session = requests.Session()
    session.verify=False

    ### Phase 1 : Get login and parse CSRF token ###
    try:
        login = session.get( base_url + '/',timeout=(3,30))
    except requests.exceptions.ConnectTimeout:
        _error(f"Connection timeout: '{base_url}' is unreachable (possibly due to temp ban for multiple failed logins)")
        sys.exit(1)
    cookiejar = login.cookies
    
    csrf = CSRF()
    csrf.Find(login.text)
    
    headers = {"content-type":"application/x-www-form-urlencoded"}
    data = {
            "__csrf_magic": csrf.SID(),
            "usernamefld": username,
            "passwordfld": password,
            "login": "Sign In"
    }
    
    debug('DATA Payload', data)
    debug('Headers', headers)
    debug('Cookies', cookiejar._cookies)
    
    time.sleep(1)
    debug("SLEEP","1")



    ### Phase 2 : Post login and update new CSRF ###
    resp = session.post( base_url + '/',
            headers = headers,
            cookies = cookiejar,
            data = data
        )
    
    cookiejar = resp.cookies
    csrf = CSRF()
    csrf.Find(resp.text)
    
    data = {
            "__csrf_magic": csrf.SID(),
            "backuparea": "",
            "donotbackuprrd": "yes",
            "encrypt_password": "",
            "encrypt_password_confirm": "",
            "download": "Download configuration as XML",
            "restorearea": "",
            "conffile": "",
            "decrypt_password": ""
    }
    
    debug('DATA Payload', data)
    debug('Headers', headers)
    debug('Cookies', cookiejar._cookies)

    if resp.history[0].__dict__['status_code'] == 200:
        _error("Login failed - expected redirect but got response code 200")
        sys.exit(0)
    
    time.sleep(1)
    debug("SLEEP","1")
    
    ### Phase 3 : Post request for backup file and download ###
    resp = session.post( base_url + '/diag_backup.php',
                headers = headers,
                cookies = cookiejar,
                data = data
            )



    ### Phase 4 : Save backup to file ###
    print()
    xml_header = b'<?xml version="1.0"?>'
    if resp.content[:len(xml_header)] != xml_header: 
        _error("There has been an error - 'resp.content' does not contain xml headers. Exiting...")
        sys.exit(9)
    debug("writing to file", args.outfile )
    bytes_written = open( args.outfile,'wb').write( resp.content )
    debug("write complete", bytes_written )
    
    
