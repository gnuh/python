#!/usr/bin/env python

from optparse import OptionParser
import os
import urllib2
import urllib
from bs4 import BeautifulSoup

class core:
	def __init__(self):			# init
		self.conf = {'title': 'Clone Web', 'info': 'Site Cloner', 'file': './cloner.py'}
		self.parser = {}
		self.dir = []

	def options(self):			# definindo opcoes
		parser = OptionParser('Modo de Uso: '+self.conf['file']+ ' -u <URL> -d <DIR>')
		parser.add_option('-u', '--url', dest='url', help='Defina a pagina a ser clonada.', metavar='url')
		parser.add_option('-d', '--dir', dest='dir', help='Escolha a pasta para salvar o projeto', metavar='dir')

		return parser

	def get_page(self):			# buscar HTML
		try:
			req = urllib2.Request(self.parser['url'])
			response = urllib2.urlopen(req)

			return response.read()
		except:
			print '[-] falha'
			exit(0)

	def initializer(self):		# inicializador
		html = self.get_page()
		self.get_dir(html)
		for l in self.dir:
			print l

	def read_tag(self, html, tag, attr):	
		soup = BeautifulSoup(html)

		for link in soup.find_all(tag):
			if (link.get(attr) != None) and (link.get(attr) != '') :
				split = '/'.join(link.get(attr).split('/')[:-1])
				try:
					self.dir.index(split)
				except:
					self.dir.append(split)

	def get_dir(self, html): 	# buscar direitorios 
		self.read_tag(html, 'script', 'src') 	#scripts path
		self.read_tag(html, 'link', 'href') 	#css path
		self.read_tag(html, 'img', 'src')		#img path


	def main(self): 			# principal
		parser = self.options()
		(options, args) = parser.parse_args()
		if(options.url == None):
			print parser.usage
			exit(0)
		else:
			self.parser = {'url': options.url, 'dir': options.dir}
			self.initializer()

if __name__ == '__main__':
	core = core()
	core.main()
