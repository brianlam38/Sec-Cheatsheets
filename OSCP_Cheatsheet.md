# OSCP
OSCP Exam Cheatsheet.

# Index

- [Introduction](#introduction) 

# Content

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

Top TCP ports scan on initial box:  
```bash
$ nmap 10.11.1.71 --top-ports 50 --open
```

Complete TCP port scan on each box:
```bash
$ nmap 10.11.1.71 -p- -sV
```
