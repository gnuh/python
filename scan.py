#!/usr/bin/env python

import sys
from optparse import OptionParser

config_ = []

# cores
class cores:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# classe do programa
class prog:
	def __init__(self):
		self.info = []

	def bye(self, msg):
		self.info.append(msg)
		print self.info[0]
		exit(0)


# Tentativa de importar a biblioteca
try:
	import nmap
except:
	p = prog()
	p.bye('Modulo Nmap nao foi encontrado.\nSiga as intrucoes aqui LINK: http://xael.org/norman/python/python-nmap/')

# Func principal
def main():
	p = prog()
	parser = OptionParser('Uso: ./scan.py -g [GateWay]')
	parser.add_option('-g', '--gateway', dest='gateway',
						help='Gateway da rede local', metavar='gateway')
	(options, args) = parser.parse_args()
	if(options.gateway == None):
		p.bye(parser.usage)
	else:
		config_.append(options.gateway)
		init()

# Inicializar
def init():
	nm = nmap.PortScanner()
	nm.scan(hosts=config_[0]+'/24', arguments='-sP -T4')
	for ips in nm.all_hosts():
		print cores.OKBLUE+'[+]'+cores.OKGREEN+ips+' 	'+cores.ENDC+'('+cores.HEADER+nm[ips].hostname()+cores.ENDC+')'

# 
if __name__ == '__main__':
	main()