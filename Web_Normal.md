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

**Summary**  

**Exploitation**  

**Mitigation**
