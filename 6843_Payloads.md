# 6843 CMDS + PAYLOADS
Copy pasta some quick access commands + payloads for CTF challenges + exam.

### Common 6843 words
---
```
noone
sketch
sketchy
```

### Recon: Subdomain Bruteforcing
---
**Aquatone**
```
ssh ec2-user@tehec2instanceidduh.aws.etc.etc        // get in
cd /home/ec2-user/sec_tools/RECON/aquatone          // go to aquatone
aquatone-discover --domain [ ns.agency ]            // run subdomain bruteforcing
cat ~/aquatone/example.com/hosts.txt                // show discovered subdomains
```

### Recon: Directory Bruteforcing
---
**GoBuster**
```
cd /Users/brianlam/go/src/gobuster                  // go to gobuster sources
go run main.go -u https://ns.agency -w ~/1_RECON/_WORDLISTS/Directories_Common.wordlist    // run dir bruteforcing
```


