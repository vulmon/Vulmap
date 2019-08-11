# Vulmap Linux
Online local vulnerability scanner for Linux systems. Find installed packages on the host, ask their vulnerabilities to [vulmon.com](http://vulmon.com) API and print vulnerabilities with available exploits. All found exploits can be downloaded by **Vulmap**.

Vulmap Linux is part of [Vulmap Local Vulnerability Scanners Project](https://github.com/vulmon/Vulmap-Local-Vulnerability-Scanners)

## Screenshots
![Screenshot from terminal](https://raw.githubusercontent.com/vulmon/Vulmap-Local-Vulnerability-Scanners/master/Vulmap-Linux/screenshot.png)

![Screenshot-2 from terminal](https://raw.githubusercontent.com/vulmon/Vulmap-Local-Vulnerability-Scanners/master/Vulmap-Linux/screenshot-all-download-exploit.png)

## Recommended Platform and Python Version
Vulmap currently only supports linux platforms and ![Python2](https://camo.githubusercontent.com/91573a399273230bbd7a6391aff545172fe49fb5/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f507974686f6e2d322d79656c6c6f772e737667) ![Python3](https://img.shields.io/badge/Python-3-blue)
* The recommended version for Python 2 is 2.7.x OR python3, python3.6.x, python3.7.x

* Compatible with Linux distros uses **dpkg**

## Installation
```
git clone https://github.com/vulmon/Vulmap-Local-Vulnerability-Scanners.git
```

Run in default mode
```
python vulmap-linux.py
python3 vulmap-linux.py
```

## Usage
Default mode. Check vulnerabilities of installed packages.

Short Form | Long Form      | Description
-----------| ---------------| -------------
-v         | --verbose      | Enable the verbose mode and display results in realtime
-d         | --download     | <exploit_id> to download a specific exploit
-a         | --all-download | Download all found exploits 
-h         | --help         | Show the help message and exit

### Examples
* To list all the basic options and switches use -h switch:
```
python vulmap-linux.py -h
python3 vulmap-linux.py -h
```
* Run in default mode:
```
python vulmap-linux.py
python3 vulmap-linux.py
```
* Enable the verbose mode:
```
python vulmap-linux.py -v
python3 vulmap-linux.py -v
```
* To download of all found exploits:
```
python vulmap-linux.py -a
python3 vulmap-linux.py -a
```
* To download a specific exploit:
```
python vulmap-linux.py -d <exploit_id>
python3 vulmap-linux.py -d <exploit_id>

e.g
python vulmap-linux.py -d EDB20
python3 vulmap-linux.py -d EDB8310
```

## Version
Current version is 2.2

## License
Vulmap is licensed under the GNU GPL license. Take a look at the [LICENSE](https://github.com/vulmon/Vulmap-Local-Vulnerability-Scanners/blob/master/LICENSE) for more information.
