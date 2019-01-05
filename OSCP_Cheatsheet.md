# OSCP
OSCP Exam Cheatsheet.

# Index

- [Introduction](#introduction) 

# Content

### ============================================================
### Preparation
### ============================================================

Kali Wordlists: `/usr/share/wordlists`  
SecLists: https://github.com/danielmiessler/SecLists


### ============================================================
### Recon
### ============================================================

Scan network range for valid IPs/hostnames:  
```bash
i="0"
while [ $i -lt "255" ]
do nslookup 10.11.1.$i 10.11.1.220 | grep -v "NXDOMAIN" | grep name
	i=$[ $i+1 ]
done
```

Top 20 TCP ports scan on initial box:  
```bash
$ nmap 10.11.1.71 --top-ports 20 --open
```

Complete TCP port scan + service banner grab on each box:
```bash
$ nmap 10.11.1.71 -p- -sV
```

Service Enum
```bash
$
$
$
```


### ============================================================
### Recon
### ============================================================
