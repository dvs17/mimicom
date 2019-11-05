# mimicom
Credits to https://github.com/SecureAuthCorp/impacket and https://github.com/skelsec/pypykatz

Be sure to have the latest versions installed:

https://github.com/SecureAuthCorp/impacket/

https://github.com/skelsec/pypykatz

and thanks to https://github.com/cleomenes88 for writing the json parser

*Edit path to impacket WMIEXEC and SMBCLIENT in file*

wmiexec = "/PATH/TO/wmiexec.py"

smbclient = "/PATH/TO/smbclient.py"

Usage:

python mimicom.py -u USERNAME -p PASSWORD -d DOMAIN -t TARGET-IP


python mimicom.py -u USERNAME -p LM:HASH -d DOMAIN -t TARGET-IP
