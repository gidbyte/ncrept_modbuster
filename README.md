# ncrept_modbuster
ModbusTCP Python3.9 Script for MITM, DoS, and Replay Attacks

For use with Kali Linux to demonstrate ModbusTCP data stream manipulation using Python

Package Requirements
---------------------
- python3.9, scapy, netfilterqueue(will be installed by nm_setup.py if not already installed), iptables, ettercap, msfconsole

Steps before Using
---------------------
1. Run "sudo apt-get update" 
2. Run "git clone https://github.com/gidbyte/ncrept_modbuster"
3. Run "cd ncrept_modbuster"
4. Run nm_setup.py using python3
5. Ensure that your scada & modbus client ips & mac addresses are loaded into the nm_config.py file (You can enter them manually if needed)
6. You're ready to run! Type "sudo python3 ncrept_modbuster.py" or "sudo python3.9 ncrept_modbuster.py" to run
