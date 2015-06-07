#!/usr/bin/env python

import optparse
from socket import *
from threading import *

screenLock = Semaphore(value=1)

def resolverHost(host, porta):
	try:
		conn = socket(AF_INET, SOCK_STREAM)
		conn.connect((host, porta))
		conn.send('ViolentPython\r\n')
		res = conn.recv(50)
		screenLock.acquire()
		print '[+]'+str(porta)+'/tcp OK \n'+str(res)
	except:
		screenLock.acquire()
		print '[-]'+str(porta)+'/tcp falha'
	finally:
		screenLock.release()
		conn.close()

def buscarPortas(host, portas):
	try:
		tIP = gethostbyname(host)
	except:
		print '[-] Nao pode resolver %d: Destino desconhecido' %host
		return

	try:
		tNome = gethostbyaddr(tIP)
		print '[+] Buscando em : '+tNome[0]
	except:
		print '[+] Buscando em : '+tIP

	setdefaulttimeout(1)

	if len(portas)>1:
		for porta in range(int(portas[0]), int(portas[1])):
			t = Thread(target=resolverHost, args=(host, int(porta)))
			t.start()
	else:
		for porta in portas:
			t = Thread(target=resolverHost, args=(host, int(porta)))
			t.start()

def main():
	prog = 'PortScan'
	parser = optparse.OptionParser("Uso do "+prog+" -H <HOST> -p <PORTA[s] '1-99999'>")
	parser.add_option('-H', dest='host', type='string', help='Especifique o HOST Ex: http://google.com')
	parser.add_option('-p', dest='porta', type='string', help="Especifique a porta Ex: '1-999999'")
	(options, args) = parser.parse_args()
	host = options.host
	portas = str(options.porta).split('-')
	if(host == None) | (portas[0] == None):
		print parser.usage
		exit(0)
	else:
		t = Thread(target=buscarPortas, args=(host, portas))
		t.start()
		


if __name__ == '__main__':
	main()