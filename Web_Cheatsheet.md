Web Application Security Cheatsheet
===================================

## Table of Contents

_Published 16th April 2018_

- [Session Management](#session-management)  
- [Authentication - OAuth](#authentication-oath) 
- [Authentication - SAML](#authentication-saml)  
- [XML - XML External Entities (XXE)](#xml---xml-external-entities)  
- [XML - XML External Entities (XXE)](#xml---xml-external-entities)  
- [Advanced XSS - Single Origin Policy (SOP)](#advanced-xss---same-origin-policy)  
- [Advanced XSS - Content Security Policy (CSP)](#advanced-xss---content-security-policy)

## Content

### Session Management
---

### Authentication - OAuth
---

### Authentication - SAML
---

**Reference Text**  
<a href="https://blog.netspi.com/attacking-sso-common-saml-vulnerabilities-ways-find/">Common SAML Implementation Mistakes</a>  
<a href="http://research.aurainfosec.io/bypassing-saml20-SSO/">SAML Raider guide</a>

**SAML Components**  
_Relay State_: a token to reference state information maintained by the Service Provider (SP).  
_SAMLResponse_: the response from the Identity Provider (IDP) containing the base64 encoded Assertion to the SP.

**Generic PoC (COMP6843)**  
1.	Intercept requests between the Service Provider (SP) and Identity Provider (IDP) and grab SAML Assertion.
2.	View SAML Assertion and change the values accordingly.
3.	Forward the payload and profit.

**Remediation**  
<a href="https://www.owasp.org/index.php/Authentication_Cheat_Sheet">OWASP Auth Cheatsheet</a><br>  
<a href="https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet">OWASP SAML Security Cheatsheet</a>

### XML – XML External Entities
---

**Basic XXE Test**
```xml
<!DOCTYPE test [<!ENTITY example "Hello World"> ]>
<test>
  <hello>&example;</hello>
</userInfo>
```
**XML Components**  
_XML DTD (XML Document Type Declaration)_ is used to define the structure of the XML document, with a list of legal elements.  
* Provides a way for applications to share data using a common structure, to verify that the data received is valid.  
* Allows creation of Entities.  

**Exploits**  
Local File Inclusion  
* subtext  

External File Inclusion  
* subtext  

XXE Out of Bounds attack (XXE OOB)  
* subtext

### PHP Un-serialize
---

**Summary**  
__Serialisation__ is converting an object into a stream of bytes, in order to store/transmit the object and then de-serialise it when needed.

**PHP Object Injection**  
Allows an attacker to perform __code / sql injection__, __path traversal__ and __denial of service__ attacks due to user-input not being properly sanitised before being passed to the `unseralize()` PHP function.  

Since PHP allows object serialisation, attackers can pass in a malicious string to a vulnerable `unserialize()` call, resulting in arbitrary PHP object injection.

See more: <a href="https://www.owasp.org/index.php/PHP_Object_Injection">PHP Object Injection</a>  

### Advanced XSS - Same Origin Policy
---

### Advanced XSS - Content Security Policy
---  

**CSP Summary**  

CSP is a security standard introduced to prevent attacks resulting from execution of malicious content in a trusted page. It allows website owners to declare approved origins of content that browsers should allow to load on that website.    

Example: `script-src userscripts.example.com`  
* Means only `userscripts.example.com` can provide scripts to be executed. INLINE SCRIPTS WON’T WORK.

**CSP Components**  

`none`: matches nothing  
`self`: matches the current origin, but NOT its subdomains  
`unsafe-inline`: allows inline JavaScript and CSS.  
`unsafe-eval`: allows text-to-JavaScript mechanisms like eval  

**CSP Bypass / Exploits**  

_Misconfigurations_: example write-up on Twitter CSP Bypass (misconfiguration)  
_JSONP_: including controlled JavaScript on the domain.  
_Polyglots_: CSP Bypass using Polyglot jpeg/javascript


