#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
draw cfg according to function addresses
'''
import angr
import os
import angrutils
#import graphviz
#import re
ground_truth_dict = dict({
    "jasper_jpc_dec_process_sot_original": 
        {0x404445, 0x41443a},
    "jasper_jpc_dec_process_sot_patched": 
        {0x414445, 0x414458, 0x41443a, 0x414760},
    "BrakeFlasher_AVR_Vuln_rx_message_routine_original":
        {0x400051, 0x4000f8},
    "BrakeFlasher_AVR_Patched_rx_message_routine_patched":
        {0x400051, 0x4000ee},
    "cwebp_ReadJPEG_original":
        {0x404848, 0x404b5c, 0x404b77, 0x404979},
    "cwebp_ReadJPEG_patched":
        {0x404898, 0x404c8c, 0x4048cc, 0x404b5c, 0x404b7b, 0x404b82, 0x4049e0},
    "file-fits_fits_decode_header_original":
        {0x406d18},
    "file-fits_fits_decode_header_patched":
        {0x404ba0, 0x404bba, 0x406f9f},
    "gzip_treat_file_original":
        {0x405810},
    "gzip_treat_file_patched":
        {0x405810},
    "tidy_prvTidyReportMarkupVersion_original":
        set(),
    "tidy_prvTidyReportMarkupVersion_patched":
        {0x429f7e, 0x42a01d, 0x42a01b},
    "libgmp.so.10.0.1___gmpn_pown_original":
        {0x450f35, 0x450f82, 0x450e8f, 0x451358, 0x450fed, 0x450ff4,0x451045,
         0x450dc0, 0x450faa, 0x451008, 0x451728},
    "libgmp.so.10.0.1___gmpn_powm_patched":
        {0x450f35, 0x450f6d, 0x450f79, 0x451328, 0x450fca, 0x45101b,
         0x450dc0, 0x450f8a, 0x450fde, 0x451708},
    "libfreetype.so.6.8.0_Ins_SHZ.isra.41_original":
        {0x4235c5, 0x4235e0, 0x423557},
    "libfreetype.so.6.8.0_Ins_SHZ.isra.41_patched":
        {0x4235b5, 0x423557}
        
    })

def draw_func_graph(binary_path, func_addr, label):
    binary_name = os.path.split(binary_path)[1]
    #out_file_name = "%s_%s_cfg" % (binary_name, label)
    b = angr.Project(binary_path, load_options = {"auto_load_libs": False})
    cfg = b.analyses.CFGFast()
    for addr,func in b.kb.functions.items():
        if addr == func_addr:
            #plot_func_graph(b, func.graph, "%s_cfg" % binary_name, asminst=True, vexinst=False)
            out_file_name = "%s_%s_%s" % (binary_name, func.name, label)
            angrutils.plot_cfg(cfg, out_file_name, asminst=True, vexinst=False, func_addr={addr:True}, debug_info=False, remove_imports=True, remove_path_terminator=True, format="dot" )
            break
    return out_file_name

def find_and_insert_color(lines, node_set, color):
    color_pattern = '\t\tcolor='+color+',fontcolor='+color+','
    for block_addr in node_set:
        for index, line in enumerate(lines):
            if line.find('<TD >'+hex(block_addr)+'<') != -1:
                #line = color_pattern + line
                lines.insert(index, color_pattern)
                break
        #lines.insert(index, color_pattern)
    return lines
    
'''
node in both set: purple
node only in added_blocks: red
node only in ground truth: blue
purple = red + blue
'''
def visulize_helper(binary_path, func_addr, label, _added_blocks):
    #dot_file = 'BrakeFlasher_AVR_Patched_rx_message_routine_patched_cfg.dot'
    #result = [0x400051, 0x4000ee]
    path = draw_func_graph(binary_path, func_addr, label)
    dot_file = path+".dot"
    
    added_blocks = set(_added_blocks)
    # Check key existence before accessing
    ground_truth = ground_truth_dict[path] if path in ground_truth_dict else set()
    # purple, intersection
    intersection = {node for node in added_blocks if node in ground_truth}
    # red, only in added blocks
    only_in_added_blocks = added_blocks - intersection
    # blue, only in ground truth
    only_in_ground_truth = ground_truth - intersection
    with open(dot_file, "r") as file:
        lines = file.readlines()
    
    lines = find_and_insert_color(lines, intersection, color='purple')
    lines = find_and_insert_color(lines, only_in_added_blocks, color='red')
    lines = find_and_insert_color(lines, only_in_ground_truth, color='blue')
    
    with open(dot_file, "w") as file:
        file.writelines(lines)
    
    '''
    graph = graphviz.Source.from_file(dot_file)
    graphviz.render()
    '''