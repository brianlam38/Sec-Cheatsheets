# OSCP Exam Process

## OpenVPN issues

Issues usually occur if you connect to OSCP network using different devices / network connections i.e. mobile hotspot + home wireless.

Reset all connections with OpenVPN:
```bash
$ sudo killall openvpn
```

## Exam Restrictions

READ THE "METASPLOIT RESTRICTIONS" SECTION CAREFULLY: https://support.offensive-security.com/oscp-exam-guide/

You can use:
* exploit/multi/handler
* msfvenom __(excluding meterpreter payload)__
* pattern_create and pattern_offset on all machines in the exam.

Anything else having to do with msf (meterpreter, auxiliary, post, exploit, scan) is limited to one machine only.


## Exam Approach

Overview:
* 1 x 25 points (Buffer Overflow)
* 1 x 10 points (Metasploit box)
* 2 x 20 points
* 1 x 25 points

Approaches - there are a number of ways to get the passing 70 points:
1. Buffer Overflow box
2. Metasploit box
3. WITHOUT LABS:
    * 35pts + (1 x root) + (1 x low_priv) + (1 x low_priv)
    * 35pts + (2 x root)
    * After 35pts: You need to get root on a 20pt box
    * After 55pts: You need to get 2 x low_priv shells || 1 x root shells
 4. WITH LABS
    * 35pts + (1 x root) + (1 x low_priv) + 5pts LAB
    * 35pts + (3 x low_priv) + 5pts LAB

Tips:
* !! STICK TO PROCESS !!
* Keep notes on steps that you have taken + info gathered so far on machines. It helps you keep track of where you are.
* Enumerate ALL services even if you think you see an attack vector:
    * Build a prioritised list of of attack vectors, spanning all ports then proceed to attack.
* Take 10-15 minute breaks every 3 hours
* Have pre-compiled exploits
* Have pre-formatted exam report (with steps etc.)

If you can't get low-level priv:
* Enumerate more / Google a way to enumerate the service differently.
* Think of what has been enumerated and how you can chain to get shell or sesnsitive info.
* Read the exploit you're sending and see if it needs to be edited.


## Exam Machine Approach

STAGE 1: ENUMERATION - MACHINE LEVEL 1

* Nmap -A default TCP ports
* Nmap -A default UDP ports
* For each service discovered (from top-to-bottom), Searchsploit/Google the service version for exploits.

STAGE 2: ENUMERATION - SERVICE LEVEL

* Surface-level dive into each service.
* Don't do a deep-dive / go into a rabbit hole.
* Make a list of possible attack-vectors from the surface-level dive.

STAGE 3: ENUMERATION - MACHINE LEVEL 2

This is where no possible attack-vectors have been found. Further enumeration may be needed.

* Perform a full Nmap TCP port-scan.
* Perform a full Nmap UDP port-scan.
* Make a list of possible attack-vectors from new services un-convered that could not be found with the basic scan.

STAGE 4: EXPLOITATION TO USER

* For each possible attack-vector in the list, run the exploit code.
* Hopefully you have a shell by now. If not, try alternate exploit code and do further service enumeration.

STAGE 5: ENUMERATION - PRIVILEGE ESCALATION 1

* Navigate around the file-system and try to understand what it contains.
  * Look for any non-standard / suspicious folders.
  * Usually the user's folder may contain the path to privesc.
* Copy Linux/Windows privilege escalation scripts via. file transfer methods into /temp.
* Run each script and observe output from top-to-bottom.
* Make a list of possible attack-vectors from the script.

STAGE 6: EXPLOITATION TO ROOT/SYSTEM

* For each possible attack-vector in the list, run exploit code or perform commands outlined in exploit guides.
* Hopefully you have a shell by now. If not, try alternative exploit code and do further enumeration of the system.

STAGE 7: ENUMERATION - PRIVILEGE ESCALATION 2

* Use a manual privilege escalation guide and follow each step to see if you can get any ideas to privesc.


## Documenting Properly

"Include full code with comments + screenshots + walk-through explanation how I built the code to fully exploit the machine like it was explained in the course videos."

**EXAM PROOFS**

1. Interactive shell
2. `Type` or `Cat` of the proof.txt file from their __ORIGINAL LOCATION__ / same directory
3. WINDOWS - must have shell running with permissions of one of the following:
  * SYSTEM user
  * Administrator user
  * User with administrator privileges
4. LINUX - must have a root shell

**PROOF SCREENSHOT REQUIREMENTS**

A single screenshot must have:
1. `ipconfig` or `ifconfig` information
2. Contents of local.txt or proof.txt

**CONTROL PANEL SUBMISSION**

A control panel key submission must have:
1. Local.txt
2. Proof.txt
3. Submitted __BEFORE__ end of the exam


