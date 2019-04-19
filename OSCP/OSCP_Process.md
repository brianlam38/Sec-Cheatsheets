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
