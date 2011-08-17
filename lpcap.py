#!/usr/bin/python
#! -*- coding: utf8 -*-

import LoCPcap as cpcap
from datetime import datetime
from threading import Thread
import struct
from protocol import *

class Packet(str):
    def decode(self, ptl):
        if ptl == 'arp':
            if len(self) < 14+28:
                raise Exception('packet size wrong')
            ether = decodeEther(self[:14])
            arp = decodeARP4(self[14:14+28])
            arp['ether'] = ether
            return arp
        return str.decode(self, ptl)

class LPcap(object):
    def __init__(self, device, snaplen = 65535,
                  promisc = False, to_ms = 0):
        self._p =cpcap.open(device, snaplen, promisc, to_ms)
        self.device = device
    def __del__(self):
        if hasattr(self, '_fp'):
            cpcap.freecode(self._fp)
        cpcap.close(self._p)
        del self._p
    def send(self, packet):
        cpcap.send(self._p, str(packet))
    def read(self):
        packet,stamp = cpcap.read(self._p)
        t = datetime.fromtimestamp(stamp['sec']+stamp['usec']/1000000.0)
        return (Packet(packet), t)
    def filter(self, code, optimize = True, netmask = 0):
        if hasattr(self, '_fp'):
            cpcap.freecode(self._fp)
        if code:
            self._fp = cpcap.filter(self._p, code, optimize, netmask)
    def geterr(self):
        return cpcap.geterr(self._p)
    @property
    def addr(self):
        if not hasattr(self, '_addr'):
            self._addr = self.getaddr(self.device)
        return self._addr
    @staticmethod
    def getaddr(interface):
        ip,mac = cpcap.getaddr(interface)
        ip = struct.pack('i', ip)
        return ip_from_bin(ip), mac_from_bin(mac)
    def loop(self, func):
        def doloop():
            while True:
                packet,t = self.read()
                func(packet, t)
        if hasattr(self, '_loop'):
            raise Exception('looping')
        self._loop = Thread(target = doloop)
        self._loop.start()









