### Session Management
---

### Authentication - OAuth
---

### Authentication - SAML
---

**Reference Text**  
* <a href="https://blog.netspi.com/attacking-sso-common-saml-vulnerabilities-ways-find/">Common SAML Implementation Mistakes</a>
* <a href="http://research.aurainfosec.io/bypassing-saml20-SSO/">SAML Raider guide</a>

**SAML Components**  
* Relay State: a token to reference state information maintained by the Service Provider (SP).
* SAMLResponse: the response from the Identity Provider (IDP) containing the base64 encoded Assertion to the SP.

**Generic PoC (COMP6843)**  
1.	Intercept requests between the Service Provider (SP) and Identity Provider (IDP) and grab SAML Assertion.
2.	View SAML Assertion and change the values accordingly.
3.	Forward the payload and profit.

**Remediation**  
* <a href="https://www.owasp.org/index.php/Authentication_Cheat_Sheet">OWASP Auth Cheatsheet</a><br>
* <a href="https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet">OWASP SAML Security Cheatsheet</a>

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
* XML DTD (XML Document Type Declaration) is used to define the structure of the XML document, with a list of legal elements. 

... Provides a way for applications to share data using a common structure, to verify that the data received is valid.  
... Allows creation of Entities.  

**Exploits**
* Local File Inclusion
* External File Inclusion
* XXE Out of Bounds attack (XXE OOB)

### PHP Un-serialize
---

### Advanced XSS - Same Origin Policy (SOP)
---

### Advanced XSS - Content Security Policy (CSP)
---
* CSP is a security standard introduced to prevent attacks resulting from execution of malicious content in a trusted page.
* It allows website owners to declare approved origins of content that browsers should allow to load on that website.
* Example: `script-src userscripts.example.com`
... Means only `userscripts.example.com` can provide scripts to be executed. INLINE SCRIPTS WON’T WORK.

**CSP Components**
* `none`: matches nothing
* `self`: matches the current origin, but NOT its subdomains
* `unsafe-inline`: allows inline JavaScript and CSS.
* `unsafe-eval`: allows text-to-JavaScript mechanisms like eval

**CSP Bypass / Exploits**
* Misconfigurations: example write-up on Twitter CSP Bypass (misconfiguration)
* JSONP: including controlled JavaScript on the domain.
* Polyglots: CSP Bypass using Polyglot jpeg/javascript


