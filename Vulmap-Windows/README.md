# Vulmap Windows
Online local vulnerability scanner for Windows systems. Finds installed software on the host, asks their vulnerabilities to vulmon.com API and print vulnerabilities with available exploits. All found exploits can be downloaded by Vulmap.

Vulmap Windows is part of [Vulmap Online Local Vulnerability Scanners Project](https://github.com/vulmon/Vulmap)
## Screenshots
![Screenshot from terminal](https://raw.githubusercontent.com/vulmon/Vulmap/master/Vulmap-Windows/bir.jpg)

![Screenshot-2 from terminal](https://raw.githubusercontent.com/vulmon/Vulmap/master/Vulmap-Windows/iki.jpg)

## Recommended Platform
Compatible with PowerShell v3 and higher


## Usage

Parameter                     | Description
------------------------------| -------------
-DefaultMode                  | Conducts a vulnerability scanning. Default mode.
-OnlyExploitableVulns         | Conducts a vulnerability scanning and only shows vulnerabilities that have exploits.
-DownloadExploit <exploit_id> | Downloads given exploit.
-DownloadAllExploits          | Scans the computer and downloads all available exploits.


### Examples

* Default mode. Conducts a vulnerability scanning:
```
PS> Invoke-Vulmap
```

* Conducts a vulnerability scanning and only shows vulnerabilities that have exploits:
```
PS> Invoke-Vulmap -OnlyExploitableVulns
```

* Downloads given exploit:
```
PS> Invoke-Vulmap -DownloadExploit EDB9386
```

* Scans the computer and downloads all available exploits:
```
PS> Invoke-Vulmap -DownloadAllExploits
```




