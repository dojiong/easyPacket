#!/usr/bin/python
#! -*- coding: utf8 -*-

from distutils.core import setup, Extension

locpcap = Extension('LoCPcap',
                sources = ['lpcap.c'],
                libraries= ['pcap']
                )

setup (name = 'LoCPcap',
       version = '1.0',
       description = 'LoCPcap',
       ext_modules = [locpcap]
      )
