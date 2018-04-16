### <font color="#d84e1c">Session Management</font>
---

### Authentication - OAuth
---

### Authentication - SAML
---

**Reference Text**
* <a href="https://blog.netspi.com/attacking-sso-common-saml-vulnerabilities-ways-find/">Common SAML Implementation Mistakes</a>
* <a href="http://research.aurainfosec.io/bypassing-saml20-SSO/">SAML Raider guide</a>

**SAML Components**
* Relay State: [insert notes]
* SAMLResponse: [insert notes]

**PoC (COMP6843)**
1.	Intercept a SAML request between the Service Provider (SP) and Identity Provider (IDP)
2.	Decode the base64 encoded SAML response.
3.	View the SAML response and change the values accordingly.
4.	Encode base to base64 and send through the payload.
5.	Profit

**Remediation**
* <a href="https://www.owasp.org/index.php/Authentication_Cheat_Sheet">OWASP Auth Cheatsheet</a><br>
* <a href="https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet">OWASP SAML Security Cheatsheet</a>

### XML – XML External Entities
---
```xml
<!DOCTYPE lolTest [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
```
