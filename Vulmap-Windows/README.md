# Vulmap Windows
Online local vulnerability scanner for Windows systems. Finds installed software on the host, asks their vulnerabilities to vulmon.com API and print vulnerabilities with available exploits. All found exploits can be downloaded by Vulmap.

Vulmap Windows is part of [Vulmap Online Local Vulnerability Scanners Project](https://github.com/vulmon/Vulmap)
## Screenshots
![Screenshot from terminal](https://raw.githubusercontent.com/vulmon/Vulmap/master/Vulmap-Windows/bir.jpg)

![Screenshot-2 from terminal](https://raw.githubusercontent.com/vulmon/Vulmap/master/Vulmap-Windows/iki.jpg)


## Usage

Recommended usage is pasting the code at https://github.com/vulmon/Vulmap/blob/master/Vulmap-Windows/vulmap-windows.ps1 or the command below to powershell terminal:

```
iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/vulmon/Vulmap/master/Vulmap-Windows/vulmap-windows.ps1')
```

If you don't have access to powershell but CMD, the command below can be used on CMD:

```
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/vulmon/Vulmap/master/Vulmap-Windows/vulmap-windows.ps1')"
```
[![usage gif](https://raw.githubusercontent.com/vulmon/Vulmap/master/Vulmap-Windows/uc.gif)](https://www.youtube.com/watch?v=y39w9WYYnmI)

Parameter                     | Description
------------------------------| -------------
-OnlyExploitableVulns         | Conducts a vulnerability scanning and only shows vulnerabilities that have exploits.
-DownloadExploit <exploit_id> | Downloads given exploit.
-DownloadAllExploits          | Scans the computer and downloads all available exploits.
-ReadFromFile                 | Uses software inventory file rather than scanning local computer.
-SaveInventoryFile            | Saves software inventory file. Enabled automatically when Mode is 'CollectInventory'.
-InventoryInFile              | Input JSON file name referred by SaveInventoryFile. Default is 'inventory.json'.
-InventoryOutFile             | Output JSON file name referred by ReadFromFile. Default is 'inventory.json'.
-Proxy                        | Defines an HTTP proxy. (-Proxy http://localhost:8080)


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

* Collects software inventory but does not conduct a vulnerability scanning. Software inventory will be saved as 'inventory.json' in default:
```
PS> Invoke-Vulmap -Mode CollectInventory
```

* Collects software inventory and save it with given file name. Does not conduct a vulnerability scanning:
```
PS> Invoke-Vulmap -Mode CollectInventory -InventoryOutFile pc0001.json
```

* Conducts a vulnerability scanning and saves software inventory to inventory.json file:
```
PS> Invoke-Vulmap -SaveInventoryFile
```

* Conducts a vulnerability scanning and saves software inventory to given file name:
```
PS> Invoke-Vulmap -SaveInventoryFile -InventoryOutFile pc0001.json
```

* Conducts a vulnerability scanning based on software inventory from file. Software inventory will be loaded from 'inventory.json' in default:
```
PS> Invoke-Vulmap -ReadFromFile
```

* Conducts a vulnerability scanning based on software inventory file loaded from given file name:
```
PS> Invoke-Vulmap -ReadFromFile -InventoryInFile pc0001.json
```

* Conducts a vulnerability scanning through an HTTP proxy:
```
PS> Invoke-Vulmap -Proxy http://127.0.0.1:8080
```


## Recommended Platform
Compatible with PowerShell v3 and higher
