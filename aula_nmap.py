#!/usr/bin/env python

import nmap

def nmapScan(host, port):
	nm = nmap.PortScanner()
	nm.scan(host,port)
	state = nm[host]['tcp'][int(port)]['state']
	print "[*] "+host+ " tcp/"+port+" "+state

def main():
	host = raw_input('Host: ')
	port = raw_input('Port: ')
	if(host == None) | (port == None):
		print 'Error.'
		exit(0)
	nmapScan(host, port)

if __name__ == '__main__':
	main()