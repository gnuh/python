#!/usr/bin/env python

import zipfile
import optparse
from threading import Thread

def crackIt(zFile, pw, i):
	try:
		zFile.extractall(pwd=pw)
		print '[+] Password Found: '+pw
	except Exception, e:
		print str(i)+' Failed: '+pw
		pass

def main():
	parser = optparse.OptionParser("ZipCrack usage method. zipcracker.py -f <zipfile> -d <dictionary>")
	parser.add_option('-f', dest='zname', type='string', help='specify zip file')
	parser.add_option('-d', dest='dname', type='string', help='specify dictionary file')
	(options, args) = parser.parse_args()
	if(options.zname == None) | (options.dname == None):
		print parser.usage
		exit(0)
	else:
		zname = options.zname
		dname = options.dname
	try:
		i=0
		zFile = zipfile.ZipFile(zname)
		passFile = open(dname)

		for line in passFile.readlines():
			i=i+1
			password = line.strip('\n')
			t = Thread(target=crackIt, args=(zFile, password, i))
			t.start()

	except Exception, e:
		print 'Error : '+str(e)	

if __name__ == '__main__':
	main()