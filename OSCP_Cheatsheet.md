# OSCP
OSCP Exam Cheatsheet.

# Index

- [Introduction](#introduction) 

# Content

### PREPARATION
Kali Wordlists: `/usr/share/wordlists`  
SecLists: https://github.com/danielmiessler/SecLists


### RECON
Scan network range for valid IPs/hostnames:  
```bash
i="0"
while [ $i -lt "255" ]
do nslookup 10.11.1.$i 10.11.1.220 | grep -v "NXDOMAIN" | grep name
	i=$[ $i+1 ]
done
```

Nmap port scans:
(NOTE: Heavy scanning may result in ports being filtered/closed - wait <15 minutes to be unbanned)
```bash
$ nmap 10.11.1.71 --top-ports 20 --open	# Top 20 TCP ports scan on initial box
$ nmap 10.11.1.71 -p- -sV		# Complete TCP port scan + service banner grab on each box:
```

Services enum:
* SSH (22): Fingerprint server/OS, SSH key
* HTTP (80|8080): Curl for HTTP header
* Telnet (23):
* SMTP (25):
* Service (port):

For each service, check available Nmap scripts:
```bash
$ ls -l /usr/share/nmap/scripts/*ssh*
```

Summarise your recon findings on the target:
* IP / DNS?
* OS?
* Ports (TCP / UDP)?
* Services / Applications?
* Which is the best entry point so far?
* Prioritised list of attack options:
	* Explore the web application.
	* Search for vulnerabilities in the known services & applications.
	* Brute force SSH with common & weak credentials.


### DEEPER RECON (SERVICE-LEVEL) - WEBAPP EXAMPLE

Scripts:
```bash
$ curl -i -L 10.11.1.71 							# Follow re-directs
$ curl 10.11.1.71 -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//' 	# Internal/external links
$ gobuster -u http://10.11.1.71 \						# Directory brute-forcing
	-w /usr/share/seclists/Discovery/Web_Content/common.txt \
	-s '200,204,301,302,307,403,500' -e
```

Things to check:
* robots.txt
* social media
* source code (if app is based on open-source code)





