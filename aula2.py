#!/usr/bin/env python

import sys
import os
if len(sys.argv)==2:
	filename = sys.argv[1]
	if not os.path.isfile(filename):
		print '[-] '+filename+' does not exists.'
		exit(0)
	if not os.access(filename, os.R_OK):
		print '[-] '+filename+' acess denied.'
		exit(0)
	print'[+] Reading Vuln from : ' +filename