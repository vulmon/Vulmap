# Vulmap Linux
Host-based vulnerability scanner. Find installed packages on the host, ask their vulnerabilities to [vulmon.com](http://vulmon.com) API and print vulnerabilities with available exploits. All found exploits can be downloaded by **Vulmap**.

Vulmap Linux is part of [Vulmap Local Vulnerability Scanners Project](https://github.com/vulmon/Vulmap-Local-Vulnerability-Scanners)

## Screenshots
![Screenshot from terminal](https://raw.githubusercontent.com/ozelfatih/vulmap/master/screenshot.png)

![Screenshot-2 from terminal](https://raw.githubusercontent.com/ozelfatih/vulmap/master/screenshot-all-download-exploit.png)

## Recommended Platform and Python Version
Vulmap currently only supports linux platforms and ![Python2](https://camo.githubusercontent.com/91573a399273230bbd7a6391aff545172fe49fb5/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f507974686f6e2d322d79656c6c6f772e737667)
* The recommended version for Python 2 is 2.7.x

* Compatible with Linux distros uses **dpkg**

## Installation
```
git clone https://github.com/ozelfatih/vulmap.git
```

Run in default mode
```
python vulmap.py
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
python vulmap.py -h
```
* Run in default mode:
```
python vulmap.py
```
* Enable the verbose mode:
```
python vulmap.py -v
```
* To download of all found exploits:
```
python vulmap.py -a
```
* To download a specific exploit:
```
python vulmap.py -d <exploit_id>

python vulmap.py -d EDB20
python vulmap.py -d EDB8310
```

## Version
Current version is 1.0

## License
Vulmap is licensed under the GNU GPL license. Take a look at the [LICENSE](https://github.com/ozelfatih/vulmap/blob/master/LICENSE) for more information.
