![Vulmap Logo](https://raw.githubusercontent.com/vulmon/Vulmap/master/Vulmap-Windows/vulmap-logo.png)

Vulmap is an open-source online local vulnerability scanner project. It consists of online local vulnerability scanning programs for Windows and Linux operating systems. These scripts can be used for defensive and offensive purposes. It is possible to make vulnerability assessments using these scripts. Also, they can be used for privilege escalation by pentesters/red teamers.

Vulmap can be used to, scan vulnerabilities on the localhost, see related exploits, and download them. Scripts basically, scan the localhost to gather installed software information and ask vulmon.com API if there are any vulnerabilities and exploits related to installed software. If vulnerabilities exist, Vulmap gives CVE ID, risk score, vulnerability's detail link, if exists related exploit ids, and exploit titles. Exploits can be downloaded with Vulmap also.

**The main idea of Vulmap is getting real-time vulnerability data from Vulmon instead of relying on a local vulnerability database. Even the most recent vulnerabilities can be detected with this approach.** Also, its exploit download feature aids privilege escalation processes. Pentesters and red teamers can download exploits from Exploit DB from the command prompt. To use this feature only thing needed is the id of exploits.

Since most Linux installations have Python, Vulmap Linux is developed with Python while Vulmap Windows is developed with PowerShell to make it easy to run it on most Windows versions. Vulmap Linux is compatible with Python 2.x, 3.x, and dpkg package management system. Vulmap Windows is compatible with PowerShell v3 and higher.

Use the below links to get detailed information about vulmap:

- [Vulmap Windows](https://github.com/vulmon/Vulmap/tree/master/Vulmap-Windows) - Powershell script for Windows systems

[![usage gif](https://raw.githubusercontent.com/vulmon/Vulmap/master/Vulmap-Windows/uc.gif)](https://www.youtube.com/watch?v=y39w9WYYnmI)

- [Vulmap Linux](https://github.com/vulmon/Vulmap/tree/master/Vulmap-Linux) - Python script for Linux systems

![Screenshot from terminal](https://raw.githubusercontent.com/vulmon/Vulmap/master/Vulmap-Linux/screenshot.png)

## To-Do:
* Operating system level vulnerabilities will be detected at Windows
* Other Linux package management systems will be supported
* macOS script will be developed
* Android and iOS scripts will be developed

## Main Contributors
* [Yavuz Atlas](https://github.com/yavuzatlas)
* [Fatih Özel](https://github.com/ozelfatih)
* [Hakan Bayır](https://github.com/HakanBayir)

## Conferences
* [DEF CON](https://www.defcon.org/html/defcon-27/dc-27-demolabs.html#Vulmap)
* [Black Hat](https://www.blackhat.com/asia-20/arsenal/schedule/index.html#vulmap-online-local-vulnerability-scanners-project-19251)
