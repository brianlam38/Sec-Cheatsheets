# OSCP Tips

## Services | Things to try

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

## Web Stuff

ColdFusion
* https://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers

WEBDAV
* `$ davtest -url 10.11.1.13`


## Reverse Shell Tips

If reverse shell hangs / dies, try a different port.
* A firewall may be blocking / disconnecting you on the port.
* E.g. 443 doesn't work, try 80 or 8080 (see your Nmap results).
