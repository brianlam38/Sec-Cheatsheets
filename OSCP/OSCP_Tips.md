# OSCP Exam Tips

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

__POSSIBLY ENUMERATE ALL BOXES FIRST AND THEN DETERMINE IF ITS BETTER TO TAKE THE 25PT BOX FIRST__
Approaches - there are a number of ways to get the passing 70 points:
1. Buffer Overflow box
2. Metasploit box
3. WITHOUT LABS:
    * 25pts (bof) + 25pts (hard) + 10pts (metasploit) + 1 low_priv (med)
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

## Submission Checklist

[x] Exam and lab report in PDF format.
* OSCP-OS-XXXXX-Exam-Report.pdf
* OSCP-OS-XXXXX-Lab-Report.pdf  

[x] PDF has been archived into a password-protected .7z file.
* `7z a OSCP-OS-XXXXX-Exam-Report.7z -pOS-XXXXX OSCP-OS-XXXXX-Exam-Report.pdf` 

[x] Submit .7z file via. https://upload.offsec.com  

[x] Email your upload link along with your OSID to: OSCP@offensive-security.com
