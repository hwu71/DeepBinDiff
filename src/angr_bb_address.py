#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep 10 13:41:43 2020

@author: hongwei
"""

import angr
binary_path = "/home/hongwei/Desktop/Codes/mram-patches/benchmarks/asterisk-11.1.2-cve-2013-2685/build/patched/res_format_attr_h264.so"
p = angr.Project(binary_path, load_options={'auto_load_libs': False})
cfg = p.analyses.CFGEmulated(keep_state=True)
functions = cfg.kb.functions
print("Function:")
for function in functions:
    print(hex(function))
    #print(cfg.kb.functions[function].block_addrs)
    block_addrs = cfg.kb.functions[function].block_addrs
    for block_addr in block_addrs:
        print("\t",hex(block_addr))
