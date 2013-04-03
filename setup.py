#!/usr/bin/env python

from distutils.core import setup, Extension

locpcap = Extension('locpcap',
                    sources=['cpcap/lpcap.c'],
                    libraries=['pcap']
                    )

setup(name='easyPacket',
      version='1.0',
      description='easyPacket',
      ext_modules=[locpcap],
      packages=['easyPacket']
      )
