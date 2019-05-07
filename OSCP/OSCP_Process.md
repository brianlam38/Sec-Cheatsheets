# OSCP Process

## STAGE 0: INITIAL RECON

Full Nmap TCP and UDP port-scans during the BOF box.
```bash
$ nmap -sV [target] -p-
$ nmap -sU [target] -p-
```

## STAGE 1: ENUMERATION - MACHINE LEVEL 1

Nmap -A default ports:
```bash
$ nmap -A [target]
$ nmap -A -sU [target]
```

For each service discovered:
* Make a list of potential vectors

## STAGE 2: ENUMERATION - SERVICE LEVEL

- [ ] Surface-level dive into each service - Searchsploit/Google the service version for exploits.
- [ ] Don't do a deep-dive / go into a rabbit hole.
- [ ] Make a list of possible attack-vectors from the surface-level dive.

## STAGE 3: ENUMERATION - MACHINE LEVEL 2

This is where no possible attack-vectors have been found. Further enumeration may be needed.

* Perform a full Nmap TCP port-scan.
* Perform a full Nmap UDP port-scan.
* Make a list of possible attack-vectors from new services un-convered that could not be found with the basic scan.

## STAGE 4: EXPLOITATION TO USER

* For each possible attack-vector in the list, run the exploit code.
* Hopefully you have a shell by now. If not, try alternate exploit code and do further service enumeration.

## STAGE 5: ENUMERATION - PRIVILEGE ESCALATION 1

* Navigate around the file-system and try to understand what it contains.
  * Look for any non-standard / suspicious folders.
  * Usually the user's folder may contain the path to privesc.
* Copy Linux/Windows privilege escalation scripts via. file transfer methods into /temp.
* Run each script and observe output from top-to-bottom.
* Make a list of possible attack-vectors from the script.

## STAGE 6: EXPLOITATION TO ROOT/SYSTEM

* For each possible attack-vector in the list, run exploit code or perform commands outlined in exploit guides.
* Hopefully you have a shell by now. If not, try alternative exploit code and do further enumeration of the system.

## STAGE 7: ENUMERATION - PRIVILEGE ESCALATION 2

* Use a manual privilege escalation guide and follow each step to see if you can get any ideas to privesc.
