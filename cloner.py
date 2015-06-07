#!/usr/bin/env python

#
# 06/06/2015 - Desenvolvidor por Magno Chiabai
#
# Rev: 0.1
#

import urllib2
import urllib
import optparse
import os
import errno
from os.path import expanduser
from bs4 import BeautifulSoup

#// config
prog = './cloner.py'
#// config project
project_img = []
project_script = []
project_css = []
project_link = []
project_info = []
project_title=''
#//

# Download files
def downloadFile(file):
	try:
		if file.find('http') < 0:
			file_name = file.split('/')[-1]
			if file_name > 3:
				url = project_info[2]+file
				file_path = project_info[0]+"/"+project_info[1]+"/"+file
				if not os.path.isfile(file_path): 
					create_dir(file)
					u = urllib2.urlopen(url)
					f = open(file_path, 'wb')
					meta = u.info()
					file_size = int(meta.getheaders("Content-Length")[0])
					print "Downloading: %s Bytes: %s" %(file_name, file_size)

					file_size_dl = 0
					block_sz = 8192
					while True:
						buffer = u.read(block_sz)
						if not buffer:
							break

						file_size_dl += len(buffer)
						f.write(buffer)
						status = r"%10d [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
						status = status + chr(8)*(len(status)+1)
						print status,

					f.close()
	except:
		pass

# create dir
def create_dir(path):
	url = []
	url.append(project_info[0]+"/")
	url.append(project_info[1]+"/")
	s = path.split("/")
	for i in range(0, len(s)-1):
		url.append(s[i]+"/")
		try:
			os.makedirs(''.join(url))
		except Exception, e:
			pass

# Setting up the directories
def setupProject():
	if len(project_info[1]) > 0:	
		try:
			os.makedirs(project_info[0]+ "/" +project_info[1])
			print "Creating directory: "+project_info[0]+ "/" +project_info[1]
		except Exception, e:
			print str(e)
	else:
		print "Invalid directory name."
		exit(0)

# writting files
def write_html(html, name):
	try:
		target = open(project_info[0] +"/"+ project_info[1] +"/"+name, 'a')
		target.write(html)
		target.close
	except Exception, e:
		print str(e)

# page loader
def loadPage(url):
	try:
		req = urllib2.Request(url)
		response = urllib2.urlopen(req)
		page = response.read()
		return page
	except:
		pass
		return '[-] Failed to load the page.'

# main func
def main():
	parser = optparse.OptionParser(prog+ ' -u url -d dir')
	parser.add_option('-u', dest='url', type='string', help='Specify the URL to read')
	parser.add_option('-d', dest='dir', type='string', help='Choose a directory')
	(options, args) = parser.parse_args()
	
	if(options.url == None) | (options.dir == None):
		print parser.usage
		exit(0)
	else:
		project_info.append(expanduser("~"))
		project_info.append(options.dir)
		project_info.append(options.url)
		html = loadPage(project_info[2])
		prepareProject(html)

		for i in range(0, len(project_link)):
			downloadFile(project_link[i])
		for i in range(0, len(project_img)):
			downloadFile(project_img[i])
		for i in range(0, len(project_script)):
			downloadFile(project_script[i])
		for i in range(0, len(project_css)):
			downloadFile(project_css[i])

		print "[+] The URL(%s) has been downloaded." %project_info[2]
	

def prepareProject(html):
	soup = BeautifulSoup(html)

	# setting title
	project_title = soup.title.string

	# getting site informations
	for link in soup.find_all('script'):
		project_script.append(link.get('src'))

	for link in soup.find_all('a'):
		project_link.append(link.get('href'))
		
	for link in soup.find_all('img'):
		project_img.append(link.get('src'))

	for link in soup.find_all('link'):
		project_css.append(link.get('href'))

	# Setup
	setupProject()

	# Create Index
	write_html(html, 'index.html')



if __name__ == '__main__':
		main()