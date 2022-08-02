import os
import subprocess
import time
import nm_config
from nm_config import *
import fileinput
import subprocess

def setup():
	print("\n\nOpening default config file\n")
	time.sleep(1.5)
	


	temp = input("Type in new SCADA IP: ")
	
	if (temp == ""):
		temp = "no scada ip found"
	
	
	f = open('nm_config.py', 'r')
	filedata = f.read()
	f.close()
	
	newdata = filedata.replace(nm_config.scada_ip, temp)
	
	f = open('nm_config.py', 'w')
	f.write(newdata)
	f.close()

	f = open('nm_config.py', 'r')
	filedata = f.read()
	f.close()
	
	macaddr = subprocess.getoutput("arp -n "+ temp +" | awk '/ether/ {print$3}'")
	
	if (macaddr == ""):
		macaddr = "no scada mac"
	
	newdata = filedata.replace(nm_config.scada_mac, macaddr)
	
	f = open('nm_config.py', 'w')
	f.write(newdata)
	f.close()


#Write to Modbus Client IP Variable
	temp = input("Type in Modbus Client IP: ")
	
	if (temp == ""):
		temp = "no modbus client ip found"
	
	f = open('nm_config.py', 'r')
	filedata = f.read()
	f.close()
	
	newdata = filedata.replace(nm_config.modcli_ip, temp)
	
	f = open('nm_config.py', 'w')
	f.write(newdata)
	f.close()

#Write to Modbus Client MAC Variable
	f = open('nm_config.py', 'r')
	filedata = f.read()
	f.close()
	
	macaddr = subprocess.getoutput("arp -n "+ temp +" | awk '/ether/ {print$3}'")
	
	if (macaddr == ""):
		macaddr = "no modbus client mac"
	
	newdata = filedata.replace(nm_config.modcli_mac, macaddr)
	
	f = open('nm_config.py', 'w')
	f.write(newdata)
	f.close()

#Write to Modbus Port Variable
	f = open('nm_config.py', 'r')
	filedata = f.read()
	f.close()
	
	newdata = filedata.replace(nm_config.mod_port, "502")
	
	f = open('nm_config.py', 'w')
	f.write(newdata)
	f.close()

if subprocess.getoutput("python3 --version | grep 3.9") == "":
	print("Python 3.9 not detected... Installing packages\n\n")
	time.sleep(1.5)
	os.system("sudo apt install scapy build-essential python3.9 python3.9-dev libnetfilter-queue-dev")

	os.system("python3.9 -m pip install netfilterqueue")
	
	setup()

else:
	print("Python 3.9 detected... Installing packages")
	time.sleep(1.5)
	os.system("sudo apt install scapy build-essential libnetfilter-queue-dev")

	os.system("python3 -m pip install netfilterqueue")
	
	setup()
	




