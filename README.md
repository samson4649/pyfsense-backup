# pfSense Backup tool

### Warning
The data pulled from these backups will have sensative information stored in them. e.g. admin login credentials. Though its advised to seperate the user that performs the backup there is still the ability for a malicious actor to use data in the backup to escalate privileges.

### Description
Python tool used to login to the web interface and backup the running pfsense configuration as you would through the webui. 

### Setup
It would be best to setup an account with backup only webui access.

### Usage

```bash
usage: backup.py [-h] --url URL [--creds CREDS] [--creds-raw CREDS_RAW] --outfile OUTFILE [--insecure INSECURE] [--debug]

Download pfSense backup XML

optional arguments:
  -h, --help                            show this help message and exit
  --url URL, -u URL                     URL of the pfSense web application
  --creds CREDS, -c CREDS               File containing pfSense login info in <username>:<password> form
  --creds-raw CREDS_RAW	                pfSense login info in <username>:<password> form
  --outfile OUTFILE, -o OUTFILE         Output file
  --insecure INSECURE                   whether to skip verification of TLS
  --debug                               debug output
```

### Note: CSRF
This tool reads and sends the required CSRF data to validate forms on post. 


