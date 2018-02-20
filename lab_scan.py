#!/bin/python
# - *- coding: utf- 8 - *-
import nmap
import sys

def scan_ip_porta(ips):
	i=1
	nm = nmap.PortScanner()
	print("Scanning...")
	nm.scan(hosts = ips, arguments='-v')
	allhosts = nm.all_hosts()
	del allhosts[0]
	del allhosts[0]
	hosts_list = [(x, nm[x]['status']['state'])for x in allhosts]
	for host, status,in hosts_list:
		if(status=="down"):
			print('{0}:\033[31m {1}\033[0;0m ({2})'.format(host, status, i ))
		else:

			print('{0}:\033[32m {1}\033[0;0m ({2})'.format(host, status, i))
			print("Portas abertas: " ,(nm[host]['tcp'].keys()))
			print('')
		i+=1

def fast_scan_ip(ips):
	i=1
	nm = nmap.PortScanner()
	print("Scanning...")
	nm.scan(hosts = ips, arguments='-v -sn')
	allhosts = nm.all_hosts()
	del allhosts[0]
	del allhosts[0]
	hosts_list = [(x, nm[x]['status']['state'])for x in allhosts]
	for host, status,in hosts_list:
		if(status=="down"):
			print('{0}:\033[31m {1}\033[0;0m ({2})'.format(host, status, i ))
		else:
			print('{0}:\033[32m {1}\033[0;0m ({2})'.format(host, status, i))
		i+=1

#---------------------------------------------------------------------------------
lab = sys.argv[1].upper()
i = 2
argumentos= sys.argv
del argumentos[0]
del argumentos[0]

if("-sn" in argumentos):

	if(lab == "E100"):
		fast_scan_ip("172.16.0.129/26")
	elif(lab == "E101"):
		fast_scan_ip("172.16.0.193/26")
	elif(lab == "E102"):
		fast_scan_ip("172.16.1.1/26")
	elif(lab == "E103"):
		fast_scan_ip("172.16.1.65/26")
	elif(lab == "E104"):
		fast_scan_ip("172.16.1.129/26")
	elif(lab == "E105"):
		fast_scan_ip("172.16.1.193/26")
	elif(lab == "E007"):
		fast_scan_ip("172.16.0.65/26")
	elif(lab == "PROJETOS"):
		fast_scan_ip("172.16.2.1/26")
	elif(lab == "E003"):
		fast_scan_ip("172.16.0.1/26")
	else:
		print("Laboratório não encontrado, digite: 'LAB argumentos' ")
	
else:

	if(lab == "E100"):
		scan_ip_porta("172.16.0.129/26")
	elif(lab == "E101"):
		scan_ip_porta("172.16.0.193/26")
	elif(lab == "E102"):
		scan_ip_porta("172.16.1.1/26")
	elif(lab == "E103"):
		scan_ip_porta("172.16.1.65/26")
	elif(lab == "E104"):
		scan_ip_porta("172.16.1.129/26")
	elif(lab == "E105"):
		scan_ip_porta("172.16.1.193/26")
	elif(lab == "E007"):
		scan_ip_porta("172.16.0.65/26")
	elif(lab == "PROJETOS"):
		scan_ip_porta("172.16.2.1/26")
	elif(lab == "E003"):
		scan_ip_porta("172.16.0.1/26")
	else:
		print("Laboratório não encontrado, digite: 'LAB argumentos' ")
	
	
