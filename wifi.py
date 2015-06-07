#!/usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
import os
import sys
import time
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import argparse
import socket
import struct
import fcntl

ap_list = []

# 
W  = '\033[0m'  # branco (normal)
R  = '\033[31m' # vermelho
G  = '\033[32m' # verde
O  = '\033[33m' # laranja
B  = '\033[34m' # azul
P  = '\033[35m' # roxo
C  = '\033[36m' # azul_claro
GR = '\033[37m' # cinza
T  = '\033[93m' # laranja_claro

def packetHandler(pkt):
	if pkt.haslayer(Dot11):
		if pkt.type == 0 and pkt.subtype == 8:
			if pkt.addr2 not in ap_list:
				ap_list.append(pkt.addr2)
				print C+'MAC: '+T+pkt.addr2+C+' - SSID: '+T+pkt.info+O

def get_mon_iface():
    global monitor_on
    monitors, interfaces = iwconfig()
    if len(monitors) > 0:
        monitor_on = True
        return monitors[0]
    else:
        # Iniciar monitoramento na interface
        print '[+] Procurando a interface mais forte...'
        interface = get_iface(interfaces)
        monmode = start_mon_mode(interface)
        return monmode


def iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE)
    except OSError:
        sys.exit('[-] Falha ao executar o "iwconfig"')
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue
        if line[0] != ' ':
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search: 
                iface = line[:line.find(' ')]
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
    return monitors, interfaces


def get_iface(interfaces):
    scanned_aps = []

    if len(interfaces) < 1:
        sys.exit('['+R+'-'+W+'] Nao foi encontrado nenhuma rede Wireless, ative uma e tente novamente')
    if len(interfaces) == 1:
        for interface in interfaces:
            return interface

    # Buscar interface mais forte
    for iface in interfaces:
        count = 0
        proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            if ' - Address:' in line:
               count += 1
        scanned_aps.append((count, iface))
        print '[+] Redes descobertas '+G+iface+W+': '+T+str(count)+W
    try:
        interface = max(scanned_aps)[1]
        return interface
    except Exception as e:
        for iface in interfaces:
            interface = iface
            print '['+R+'-'+W+'] Minor error:',e
            print '    Iniciamento modo de monitoramento LIGADO '+G+interface+W
            return interface

def start_mon_mode(interface):
    print '[+]] Iniciando modo de monitoramento DESLIGADO '+interface
    try:
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode monitor' % interface)
        os.system('ifconfig %s up' % interface)
        return interface
    except Exception:
        sys.exit('[-] Falha ao iniciar modo de monitoramento')

def remove_mon_iface(mon_iface):
    os.system('ifconfig %s down' % mon_iface)
    os.system('iwconfig %s mode managed' % mon_iface)
    os.system('ifconfig %s up' % mon_iface)

def mon_mac(mon_iface):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    print O+'[+] '+R+'t'+G+'Byte'+W+O+' - Monitorando WiFi: '+mon_iface+' - '+mac+W
    return mac



def main():
    if os.geteuid():
        exit(R+'t'+G+'Byte '+O+'WiFi'+W+' - Execute como Root')
    DN = open(os.devnull, 'w')
    monitor_on = None
    mon_iface = get_mon_iface()
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)

    try:
       sniff(iface=mon_iface, prn=packetHandler)
    except Exception as msg:
        remove_mon_iface(mon_iface)
        print '\n[-] Fechando'
        sys.exit(0)

if __name__ == '__main__':
	main()