#!/usr/bin/env python
# -*- coding: UTF-8 -*-

#https://github.com/vulmon
#https://github.com/ozelfatih
#https://vulmon.com


#==========================================================================
# LIBRARIES
#==========================================================================
from __future__ import print_function
import subprocess
import urllib2
import urllib
import json
import argparse
import platform

#==========================================================================
# GLOBAL VARIABLES
#==========================================================================
productList = []
exploit_sum = 0
__version__ = 2.1

#==========================================================================
# FUNCTIONS
#==========================================================================
def args():
	global args

	description = "Host-based vulnerability scanner. Find installed packages on the host, ask their vulnerabilities to vulmon.com API and print vulnerabilities with available exploits. All found exploits can be downloaded by Vulmap."

	parser = argparse.ArgumentParser('vulmap.py', description=description)
	parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Verbose mode', dest='verbose', required=False)
	parser.add_argument('-a', '--all-download', action='store_true', default=False, help='Download all found exploits', dest='exploit', required=False)
	parser.add_argument('-d', '--download', type=str, default=False, help='Download a specific exploit ./%(prog)s -d EDB16372', dest='exploit_ID', required=False)
	parser.add_argument('--version', action='version', version='%(prog)s version ' + str(__version__))
	args = parser.parse_args()
	

def sendRequest(queryData):
	product_list = '"product_list": ' + queryData

	os = platform.uname()[1]
	arc = platform.uname()[4]

	json_request_data = '{'
	json_request_data += '"os": "' + os + '",'
	json_request_data += '"arc": "' + arc + '",'
	json_request_data += product_list 
	json_request_data +=  '}'

	url = 'https://vulmon.com/scannerapi_vv211'
	body = 'querydata=' + json_request_data
	headers = {'Content-Type': 'application/x-www-form-urlencoded'}

	request = urllib2.Request(url, body, headers)

	result = urllib2.urlopen(request, timeout=5)
	response = json.loads(result.read())

	return response

def outResults(q):
	global exploit_sum

	queryData = q[:-1]
	queryData += ']'
	response = sendRequest(queryData)

	if response['status_message'] == 'success':
		for i in range(0, len(response["results"])):
			if args.verbose:
				print(bcolors.OKGREEN + "[*] " + bcolors.ENDC + "Vulnerability Found!")

				print(bcolors.OKGREEN + "[>] " + bcolors.ENDC + "Product: " + response['results'][i]['query_string'])

				for j in range(0, response['results'][i]['total_hits']):
					try:
						print(bcolors.OKGREEN + '[+] ' + bcolors.ENDC + 'CVEID: ' + response['results'][i]['vulnerabilities'][j]['cveid'] + '	Score: ' + str(response['results'][i]['vulnerabilities'][j]['cvssv2_basescore']) + '	URL: ' + response['results'][i]['vulnerabilities'][j]['url'])
						if response['results'][i]['vulnerabilities'][j]['exploits']:

							print(bcolors.FAIL + '	[*]' + bcolors.ENDC + ' Available Exploits!')

							for z in range(0, len(response['results'][i]['vulnerabilities'][j]['exploits'])):

								exploit_sum += 1

								edb = response['results'][i]['vulnerabilities'][j]['exploits'][z]['url'].split("=")
							
								print(bcolors.FAIL + "	[!] " + bcolors.ENDC + "Exploit ID: EDB" + edb[2] + "	URL: " + response['results'][i]['vulnerabilities'][j]['exploits'][z]['url'] + " (" + response['results'][i]['vulnerabilities'][j]['exploits'][z]['title'] + ")")
					except Exception as e:
						continue
					print(bcolors.OKGREEN + '[+] ' + bcolors.ENDC + 'CVEID: ' + response['results'][i]['vulnerabilities'][j]['cveid'] + '	Score: ' + str(response['results'][i]['vulnerabilities'][j]['cvssv2_basescore']) + '	URL: ' + response['results'][i]['vulnerabilities'][j]['url'])
				print("\n")

			elif args.exploit:
				for j in range(0, response['results'][i]['total_hits']):
					try:
						if response['results'][i]['vulnerabilities'][j]['exploits']:

							print(bcolors.OKGREEN + "[*] " + bcolors.ENDC + "Exploit Found!")
							print(bcolors.OKGREEN + "[>] " + bcolors.ENDC + "Product: " + response['results'][i]['query_string'])

							for z in range(0, len(response['results'][i]['vulnerabilities'][j]['exploits'])):

								exploit_sum += 1

								edb = response['results'][i]['vulnerabilities'][j]['exploits'][z]['url'].split("=")
							
								print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + "Title: " + response['results'][i]['vulnerabilities'][j]['exploits'][z]['title'])
								print(bcolors.FAIL + "[!] Exploit ID: EDB" + edb[2] + bcolors.ENDC + "\n")

								getExploit("EDB" + edb[2])
					except Exception as e:
						continue
			else:
				print(bcolors.OKGREEN + "[*] " + bcolors.ENDC + "Vulnerability Found!")

				print(bcolors.OKGREEN + "[>] " + bcolors.ENDC + "Product: " + response['results'][i]['query_string'])

				for j in range(0, response['results'][i]['total_hits']):
					try:
						print(bcolors.OKGREEN + '[+] ' + bcolors.ENDC + 'CVEID: ' + response['results'][i]['vulnerabilities'][j]['cveid'] + '	Score: ' + str(response['results'][i]['vulnerabilities'][j]['cvssv2_basescore']) + '	URL: ' + response['results'][i]['vulnerabilities'][j]['url'])
						if response['results'][i]['vulnerabilities'][j]['exploits']:

							print(bcolors.FAIL + '	[*]' + bcolors.ENDC + ' Available Exploits!')

							for z in range(0, len(response['results'][i]['vulnerabilities'][j]['exploits'])):

								exploit_sum += 1

								edb = response['results'][i]['vulnerabilities'][j]['exploits'][z]['url'].split("=")
							
								print(bcolors.FAIL + "	[!] " + bcolors.ENDC + "Title: " + response['results'][i]['vulnerabilities'][j]['exploits'][z]['title'] + "	URL: " + response['results'][i]['vulnerabilities'][j]['exploits'][z]['url'])
					except Exception as e:
						continue
					print(bcolors.OKGREEN + '[+] ' + bcolors.ENDC + 'CVEID: ' + response['results'][i]['vulnerabilities'][j]['cveid'] + '	Score: ' + str(response['results'][i]['vulnerabilities'][j]['cvssv2_basescore']) + '	URL: ' + response['results'][i]['vulnerabilities'][j]['url'])
				print("\n")

	else:
		pass

def getExploit(exploit_ID):
	url = 'https://vulmon.com/downloadexploit?qid=' + exploit_ID
	urllib.urlretrieve(url, ("Exploit_" + exploit_ID))

	if args.exploit_ID:
		print(bcolors.OKBLUE + "[Info] " + bcolors.ENDC + "Exploit Mode. Exploit downloading...\n")

		print(bcolors.OKGREEN + "[>] Filename: " + bcolors.ENDC + "Exploit_" + exploit_ID)
		print(bcolors.OKGREEN + "[STATUS] Exploit Downloaded!" + bcolors.ENDC)

def getProductList():
	global productList

	dpkg = "dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'"

	action = subprocess.Popen(dpkg, shell = True, stdout = subprocess.PIPE)
	results = action.communicate()[0]
	tempList = results.split('\n')

	for i in range(0,len(tempList)-1):
		productList.append(tempList[i].split(" "))

def vulnerabilityScan():
	print(bcolors.OKBLUE + "[Info] " + bcolors.ENDC + "Vulnerability scan started...")

	if args.verbose:
		print(bcolors.OKBLUE + "[Info] " + bcolors.ENDC + "Verbose Mode. Check vulnerabilities of installed packages...\n")
	elif args.exploit:
		print(bcolors.OKBLUE + "[Info] " + bcolors.ENDC + "All Exploit Mode. All exploit download mode starting...\n")
	else:
		print(bcolors.OKBLUE + "[Info] " + bcolors.ENDC + "Default Mode. Check vulnerabilities of installed packages...\n")

	count = 0

	for element in productList:

		if count == 0:
			queryData = '['
		queryData += '{'
               	queryData += '"product": "' + element[0] + '",'
               	queryData += '"version": "' + element[1] + '",'
		queryData += '"arc": "' + element[2] + '"'                	
		queryData += '},'

		count += 1

		if count == 100:
			count = 0
			outResults(queryData)
	outResults(queryData)

def banner():
	print("|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||")
	print("                                                               	  ")
	print("  ██╗        ██╗   ██╗██╗   ██╗██╗     ███╗   ███╗ █████╗ ██████╗  ")
	print("  ╚██╗       ██║   ██║██║   ██║██║     ████╗ ████║██╔══██╗██╔══██╗ ")
	print("   ╚██╗      ██║   ██║██║   ██║██║     ██╔████╔██║███████║██████╔╝ ")
	print("   ██╔╝      ╚██╗ ██╔╝██║   ██║██║     ██║╚██╔╝██║██╔══██║██╔═══╝  ")
	print("  ██╔╝███████╗╚████╔╝ ╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║██║      ")
	print("  ╚═╝ ╚══════╝ ╚═══╝   ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝      ")
	print("===================================================================")
	print("\                       Vulmon Mapper v2.1                        /")
	print(" \                        www.vulmon.com                         / ")
	print("  \=============================================================/\n")

#==========================================================================
# CLASS
#==========================================================================
class bcolors:
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'

#==========================================================================
# MAIN PROGRAM
#==========================================================================
if __name__ == '__main__':
	banner()
	args()

	if args.exploit_ID:
		getExploit(args.exploit_ID)
	else:
		getProductList()
		vulnerabilityScan()
		print(bcolors.OKBLUE + "[Info] " + bcolors.ENDC + "Total Exploits: " + str(exploit_sum) + "\n")
