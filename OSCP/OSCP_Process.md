# OSCP Process

## STAGE 0: INITIAL RECON

Full Nmap TCP and UDP port-scans during the BOF box / while working on other machines.
```bash
$ nmap [target] -p-       # do nmap -sV on the individual ports later
$ nmap -sU [target] -p-
```

## STAGE 1: ENUMERATION - MACHINE LEVEL 1

Nmap -A default ports:
```bash
$ nmap -A [target]
$ nmap -A -sU [target]
```

For each service discovered, make a list of potential vectors.

## STAGE 2: ENUMERATION - SERVICE LEVEL

Surface-level dive into each service.
* Don't do a deep-dive / go into a rabbit hole.

Searchsploit/Google the service version for exploits.

For each service, make a list of possible further vectors using exploit info.

## STAGE 3: ENUMERATION - MACHINE LEVEL 2

__Ideally, a full TCP/UDP port scan should have been done while working on other machines__

This is where no possible attack-vectors have been found. Further enumeration may be needed.
* Perform a full Nmap TCP port-scan.
* Perform a full Nmap UDP port-scan.

Make a list of possible attack-vectors from new services un-convered that could not be found with the basic scan.

## STAGE 4: EXPLOITATION TO USER

For each possible attack-vector in the list, run the exploit code.

Hopefully you have a shell by now. If not, try:
1. Alternate exploit code
2. Alternate bind / reverse shell
3. Alternate port used for shell connection
4. Go through recon notes in previous steps - you may have missed something

## STAGE 5: ENUMERATION - PRIVILEGE ESCALATION 1

Manually navigate around the file-system and try to understand what it contains.
  * Look for any non-standard / suspicious folders.
  * Usually the user's folder may contain the path to privesc.

Copy Linux/Windows privilege escalation scripts via. file transfer methods into /temp.
* Run each script and observe output from top-to-bottom.
* Make a list of possible vectors from the script.

Manually go through privesc steps in guides - automated scripts might have missed something.
* Make a list of possible vectors from manually stepping through privesc enum.

## STAGE 6: EXPLOITATION TO ROOT/SYSTEM

For each possible attack-vector in the list, run exploit code or perform commands outlined in exploit guides.

Hopefully you have a shell by now. If not, try:
1. Alternate exploit code.
2. Further enumeration of the system to find suspicious files / config files with creds.
3. __Look back at enum notes from USER... can you exploit something that you couldn't previously access?__
