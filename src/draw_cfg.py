'''
draw cfg according to function names
'''

import sys
import nose
import angr
import os
from angrutils import *
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

from angrutils import plot_func_graph



'''
def draw_cfg(binary_path):
    #binary_path = os.path.join(build_location, binary_name)
    binary_name = os.path.split(binary_path)[1]
    b = angr.Project(binary_path, load_options = {"auto_load_libs": False})
    #main = b.loader.main_object.get_symbol("main")
    #start_state = b.factory.blank_state(addr=main.rebased_addr)
    #cfg = b.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state)
    cfg = b.analyses.CFGFast()
    print(len(cfg.functions), len(cfg.graph.nodes()))
    plot_cfg(cfg, binary_name+"_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)
'''    
def draw_func_graph(binary_path, func_name,label):
    binary_name = os.path.split(binary_path)[1]
    out_file_name = "%s_%s_%s_cfg" % (binary_name, func_name, label)
    b = angr.Project(binary_path, load_options = {"auto_load_libs": False})
    cfg = b.analyses.CFGFast()
    for addr, func in b.kb.functions.items():
        if func.name == func_name:
            #plot_func_graph(b, func.graph, "%s_cfg" % binary_name, asminst=True, vexinst=False)
            plot_cfg(cfg, out_file_name, asminst=True, vexinst=False, func_addr={addr:True}, debug_info=False, remove_imports=True, remove_path_terminator=True, format="dot" )
    
    return out_file_name
'''
binary_path_1 = os.path.join(os.getcwd(), 'CWE_119')
binary_path_2 = os.path.join(os.getcwd(), 'CWE_119_patched')
b1 = angr.Project(binary_path_1, load_options = {"auto_load_libs": False})
b2 = angr.Project(binary_path_2, load_options = {"auto_load_libs": False})
#bindiff = b1.analyses.BinDiff(b2)
#identical_functions = bindiff.identical_functions
#differing_functions = bindiff.differing_functions
#unmatched_functions = bindiff.unmatched_functions
#identical_blocks = bindiff.identical_blocks
#differing_blocks = bindiff.differing_blocks


main_1 = b1.loader.main_object.get_symbol("main")
start_state_1 = b1.factory.blank_state(addr=main_1.rebased_addr)
cfg_1 = b1.analyses.CFGEmulated(fail_fast=True, starts=[main_1.rebased_addr], initial_state=start_state_1)

main_2 = b2.loader.main_object.get_symbol("main")
start_state_2 = b2.factory.blank_state(addr=main_2.rebased_addr)
cfg_2 = b2.analyses.CFGEmulated(fail_fast=True, starts=[main_2.rebased_addr], initial_state=start_state_2)


plot_cfg(cfg_1, "CWE_119_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)
plot_cfg(cfg_2, "CWE_119_patched_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)
'''
        
def main():
    # Usage: python draw_cfg.py --path <binary_path>
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--path', required=True, help='Input bin file path')
    #parser.add_argument('--outputDir', required=True, help='Specify the output directory') 
    parser.add_argument('--func_name', required=True, help='Input the function name')
    parser.add_argument('--label', required=True, help='Input original or patched')
    binary_path = parser.parse_args().path
    func_name = parser.parse_args().func_name
    label= parser.parse_args().label
    #outputDir = parser.parse_args().outputDir
    #draw_cfg(binary_path, outputDir)
    #draw_cfg(binary_path)
    draw_func_graph(binary_path, func_name, label)
    
if __name__ == "__main__":
    main()
    