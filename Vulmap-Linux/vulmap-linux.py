#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#==========================================================================
# LIBRARIES
#==========================================================================
import json
import string
import urllib
import argparse
import subprocess
#==========================================================================
# GLOBAL VARIABLES
#==========================================================================
tempList = []
productList = []
data = []
__version__ = 1.0
#==========================================================================
# CLASSES
#==========================================================================
class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

class ApiRequest:
	def __init__(self, product, version, mode):
		global data
		self.product = product
		self.version = version
		self.mode = mode

		apistart = "http://vulmon.com/scannerapi?api=start&dev=1"
		urllib.urlopen(apistart)
		self.url = "http://vulmon.com/scannerapi?product=" + self.product + "&version=" + self.version + "&dev=1"

		try:
			data = json.load(urllib.urlopen(self.url))
		except Exception, e:
			print e

	def vulnerabilityCheck(self):
		if self.mode == "exploit":
			if data["totalHits"]:
				for k in range(0,len(data["results"])):
					try:
						if data["results"][k]["exploits"]:
							print bcolors.FAIL + "[>] " + bcolors.ENDC + "Product: " + self.product + " " + self.version
							for j in range(0, len(data["results"][k]["exploits"])):
								exploit_url = data["results"][k]["exploits"][j]["url"]
								title = data["results"][k]["exploits"][j]["title"]

								edb_id = exploit_url.split("=")
								url = 'http://vulmon.com/downloadexploit?qid=' + edb_id[1] + "&dev=1"
								urllib.urlretrieve(url, ("Exploit_" + edb_id[1] + "_" + self.product + "_" + self.version))

								print bcolors.FAIL + "[+] " + bcolors.ENDC + "Title: " + title
								print bcolors.FAIL + "[!] Exploit ID: " + edb_id[1] + bcolors.ENDC
					except Exception, e:
						continue
					print ""
		else:
			if data["totalHits"]:
				print bcolors.OKGREEN + "[*] " + bcolors.ENDC + "Vulnerability Found!"
				print bcolors.OKGREEN + "[>]" + bcolors.ENDC + " Product: " + self.product + " " + self.version
				for i in range(0, len(data["results"])):
					print bcolors.OKGREEN + "[+]" + bcolors.ENDC + " CVEID: " + data["results"][i]["CVEID"] + "	" + "Score: " + str(data["results"][i]["CVSSv2BaseScore"]) + "	" + "URL: " + data["results"][i]["url"]
					try:
						if data["results"][i]["exploits"]:
							print bcolors.FAIL + "	[*] " + bcolors.ENDC +"Available Exploits!!!"
							for j in range(0, len(data["results"][i]["exploits"])):
								exploit_url = data["results"][i]["exploits"][j]["url"]
								edb_id = exploit_url.split("=")
								print bcolors.FAIL + "	[!]" + bcolors.ENDC + " Exploit ID: " + edb_id[1] + " URL: " + str(data["results"][i]["exploits"][j]["url"]) + " (" + data["results"][i]["exploits"][j]["title"] +")"
								#url = 'http://vulmon.com/downloadexploit?qid=' + edb_id[1] + "&dev=1"
								#print bcolors.FAIL + "\t[!]" + bcolors.ENDC + " Click Exploit Download: " + url
					except Exception, e:
						continue
				print ""
			else:
				if self.mode == "verbose":
					print bcolors.WARNING + "[-]" + bcolors.ENDC + " Product: " + self.product + " " + self.version

#==========================================================================
# FUNCTIONS
#==========================================================================
def banner():
	print ">_||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||_<"
	print "                                                               	   "
	print "  ██╗        ██╗   ██╗██╗   ██╗██╗     ███╗   ███╗ █████╗ ██████╗   "
	print "  ╚██╗       ██║   ██║██║   ██║██║     ████╗ ████║██╔══██╗██╔══██╗  "
	print "   ╚██╗      ██║   ██║██║   ██║██║     ██╔████╔██║███████║██████╔╝  "
	print "   ██╔╝      ╚██╗ ██╔╝██║   ██║██║     ██║╚██╔╝██║██╔══██║██╔═══╝   "
	print "  ██╔╝███████╗╚████╔╝ ╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║██║       "
	print "  ╚═╝ ╚══════╝ ╚═══╝   ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝       "
	print "===================================================================="
	print "\                       Vulmon Mapper v1.0                         /"
	print " \                        www.vulmon.com                          /"
	print "  \==============================================================/\n"

def args():
	global args

	desc = "Host-based vulnerability scanner. Find installed packages on the host, ask their vulnerabilities to vulmon.com API and print vulnerabilities with available exploits. All found exploits can be downloaded by Vulmap."

	parser = argparse.ArgumentParser('vulmap.py', description=desc)

	parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Verbose mode', dest='verbose', required=False)
	parser.add_argument('-a', '--all-download', action='store_true', default=False, help='Download all found exploits', dest='exploit', required=False)
	parser.add_argument('-d', '--download', type=str, default=False, help='Download a specific exploit ./%(prog)s -d EDB16372', dest='exploit_ID', required=False)
	parser.add_argument('--version', action='version', version='%(prog)s version ' + str(__version__))
	args = parser.parse_args()

def linuxSystemInfo():
	distro = "cat /etc/*release | grep ID"	
	kernel = "uname -mrs"

	action = subprocess.Popen(distro, shell = True, stdout = subprocess.PIPE)
	distroResults = action.communicate()[0].split('\n')

	action2 = subprocess.Popen(kernel, shell = True, stdout = subprocess.PIPE)
	kernelResults = action2.communicate()[0].split(" ")

	for i in range(0, len(distroResults)-1):
		split = distroResults[i].split("=")
		if split[0] == 'ID':
			ID = str(split[1]).strip('"')
		if split[0] == 'VERSION_ID':
			VERSION = str(split[1]).strip('"')
	print "[*] Distro Information"
	print "[>] DISTRO ID: " + ID + " VERSION: " + VERSION + "\n"
	print "[*] Kernel Information"
	print "[>] SYSTEM: " + kernelResults[0] + " VERSION: " + kernelResults[1] + " ARCHITECTURE: " + kernelResults[2]

def getProductList():
	global productList
	dpkg = "dpkg-query -W -f='${Package} ${Version}\n'"
	action = subprocess.Popen(dpkg, shell = True, stdout = subprocess.PIPE)
	results = action.communicate()[0]
	tempList = results.split("\n")

	for i in range(0,len(tempList)-1):
		productList.append(tempList[i].split(" "))
		productList[i][0] = (string.replace(productList[i][0], '-','_').replace(':','_').replace('.','_')).lower()

def exploitDownload(exploit_ID):
	try:
		apistart = "http://vulmon.com/scannerapi?api=start&dev=1"
		urllib.urlopen(apistart)
		url = "http://vulmon.com/downloadexploit?qid=" + exploit_ID + "&dev=1"
		urllib.urlretrieve(url, ("Exploit_" + exploit_ID))
		print "[Info] Specific exploit downloading..."
		print bcolors.FAIL + "[*] " + bcolors.ENDC + "Exploit Downloaded!"
		print bcolors.FAIL + "[!] Make use of exploit file: Exploit_" + exploit_ID + bcolors.ENDC
		print bcolors.OKGREEN + "[STATUS] EXPLOIT DOWNLOADED." + bcolors.ENDC
	except Exception, e:
		print e
#==========================================================================
# MAIN PROGRAM
#==========================================================================
if __name__ == '__main__':
	banner()
	args()
	getProductList()

	if args.exploit_ID:
		exploitDownload(args.exploit_ID)
	else:
		linuxSystemInfo()
		for i in range(0,len(productList)):
			product = str(productList[i][0])
			version = str(productList[i][1])

			if args.verbose:
				if i == 0:
					print "[Info] Verbose mode. Check vulnerabilities of installed packages..."
				response = ApiRequest(product, version, "verbose")
				response.vulnerabilityCheck()
			elif args.exploit:
				if i == 0:
					print "[Info] All exploit download mode starting..."
				response = ApiRequest(product, version, "exploit")
				response.vulnerabilityCheck()
			else:
				if i == 0:
					print "[Info] Default mode. Check vulnerabilities of installed packages..."
				response = ApiRequest(product, version, "default")
				response.vulnerabilityCheck()
