Recon and Advanced Asset Discovery
===================================

Recon is super important like holy shit dont start breaking into things before you do your recon.  

Recon will help you prioritise what you should focus on for penetration testing.

## Sub-domain Enumeration

1. Find free wordlists online (GOOGLE: top wordlists, most popular wordlists)
2. Build upon the damn wordlists
3. Brute-force subdomain discovery using the wordlists + BENCHMARK WORDLIST PERFORMANCE!!!
  * `Sublist3r` is kinda shitty and slow but eh.
  * `host [domain name]` to quickly check if a domain exists by performing DNS lookups.
4. Use a tool such as `AltDNS` to discover additional sub-subdomains using subdomains you have found already.

## Network Mapping

**Port Scanning**  
Nmap to find open ports and services run by the application.

Typical Ports/Servces:
* HTTPS: 443 | HTTP: port 80/8080
*   FTP: 20/21
*   SSH: 22
*  SMTP: 25


##
