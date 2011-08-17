#!/usr/bin/python
#! -*- coding: utf8 -*-

import struct

class DecodeError(Exception):
    pass

mac_from_bin = lambda m:':'.join(map(lambda x:'%02X'%ord(x), m))
mac_to_bin = lambda m:''.join(map(lambda x:chr(eval('0x'+x)), m.split(':')))
ip_from_bin = lambda i:'.'.join(map(lambda x:str(ord(x)), i))
ip_to_bin = lambda addr:''.join(map(lambda x:chr(int(x)), addr.split('.')))

def decodeEther(data):
    ether_type = {0x0200:'PUP',0x0500:'SPRITE',
                 0x0800:'IP',0x0806:'ARP',0x8035:'REVARP',
                 0x809B:'AT',0x80F3:'AARP',0x8100:'VLAN',
                 0x8137:'IPX',0x86dd:'IPV6',0x9000:'LOOPBACK'}
    if len(data) < 14:
        raise DecodeError('ether header length(14) wrong')
    dmac,smac,ptl = struct.unpack('>6s6sh', data[:14])
    if ptl not in ether_type:
        raise DecodeError('unkown ether type')
    return {'dmac':mac_from_bin(dmac),
             'smac':mac_from_bin(smac),
             'type':ether_type[ptl]}

def decodeARP4(data):
    op_type = {1:'REQUEST', 2:'REPLY', 3:'RREQUEST',
               4:'RREPLY', 8:'InREQUEST',
               9:'InREPLY', 10:'NAK'}
    if len(data) < 28:
        raise DecodeError('arp length(28) wrong')
    hdr,pro,hlen,plen,op,smac,sip,dmac,dip = struct.unpack(
                '>hhBBh6s4s6s4s', data)
    if op not in op_type:
        raise DecodeError('arp op code(%d) wrong'%op)
    return {'hrd':hdr, 'pro':pro, 'hlen':hlen, 'plen':plen,'op':op_type[op],
             'smac':mac_from_bin(smac), 'sip':ip_from_bin(sip),
             'dmac':mac_from_bin(dmac), 'dip':ip_from_bin(dip)}

def mkARP4(smac, sip, dmac, dip, op):
    eth = struct.pack('>6s6sh', mac_to_bin(dmac),
            mac_to_bin(smac), 0x0806)
    if op == 1: dmac = '00:00:00:00:00:00'
    arp = struct.pack('>hhBBh6s4s6s4s',
                1, 0x0800, 6, 4, op,
                mac_to_bin(smac), ip_to_bin(sip),
                mac_to_bin(dmac), ip_to_bin(dip)
                )
    return eth+arp











    
