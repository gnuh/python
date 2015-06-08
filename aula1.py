#!/usr/bin/env python

import socket
def retBanner(ip, port):
	try:
		socket.setdefaulttimeout(1)
		s = socket.socket()
		s.connect((ip, port))
		banner = s.recv(1024)
		return banner
	except:
		return

def checkVulns(banner):
	f = open('vuln_banners.txt', 'r')
	for line in f.readlines():
		if line.strip('\n') in banner:
			print '[+] server is vulnerable: '+banner.strip('\n')

def main():
	portList = [21, 22, 80]
	for x in range(25, 28):
		ip = '192.168.0.'+str(x)
		for port in portList:
			print 'Checando IP: '+str(ip)+': '+str(port)
			banner = retBanner(ip, port)
			if banner:
				print '[+] '+ip+': '+banner
				checkVulns(banner)

if __name__== '__main__':
	main()