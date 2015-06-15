#!/usr/bin/env python

import urllib
import urllib2

url = 'http://grupo2better.com.br/'

data = {'login': 'acesso', 'senha': 'senha123'}

data = urllib.urlencode(data)
request = urllib2.Request(url, data)
response = urllib2.urlopen(request)

page = response.read()

print page