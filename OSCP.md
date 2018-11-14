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

Netcat
```bash
=BASICS=
nc -nlvp [port]          # set up listener
nc -nv [IP] [port]       # banner grabbing OR connect to remote port

=FILE TRANSFER=
nc -nlvp [port] > incoming.exe                # Box A: listen & redirect data to incoming.exe
nc -nv [Box A IP] [port] < /path/to/wget.exe  # Box B: connect to B and send wget.exe

=BIND SHELL=

```
