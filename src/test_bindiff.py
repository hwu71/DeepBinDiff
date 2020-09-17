import angr
import sys
import os
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
#import logging
#logging.getLogger('angr').setLevel('DEBUG')
#build_location = os.path.join(os.getcwd(),'..','build')

def bindiff(binary_path_1, binary_path_2, outputDir):
    #binary_path_1 = os.path.join(build_location, binary_name_1)
    #binary_path_2 = os.path.join(build_location, binary_name_2)
    b1 = angr.Project(binary_path_1, load_options = {"auto_load_libs": False})
    b2 = angr.Project(binary_path_2, load_options = {"auto_load_libs": False})
    b1_cfg = b1.analyses.CFGFast()
    b2_cfg = b2.analyses.CFGFast()
    bin_diff = b1.analyses.BinDiff(b2)
    
    
    b1_matched_pairs_in_function_dic = {} # Only count once according to func1 
    b2_matched_pairs_in_function_dic = {}
    #b1_to_b2_matched_pairs_dic = {}
    b1_all_blocks_in_function_dic = {}
    b2_all_blocks_in_function_dic = {}
    b1_matched_blocks_in_function_dic = {}
    b2_matched_blocks_in_function_dic = {}
    
    b1_functions = b1_cfg.kb.functions
    b2_functions = b2_cfg.kb.functions
    
    # Initilization for b1
    for b1_function in b1_functions:
        b1_matched_pairs_in_function_dic[b1_function] = []
        b1_all_blocks_in_function_dic[b1_function] = set(hex(addr) for addr in b1_functions[b1_function].block_addrs)
        b1_matched_blocks_in_function_dic[b1_function] = set()
    
    # Initilization for b2
    for b2_function in b2_functions:
        b2_matched_pairs_in_function_dic[b2_function] = []
        b2_all_blocks_in_function_dic[b2_function] = set(hex(addr) for addr in b2_functions[b2_function].block_addrs)
        b2_matched_blocks_in_function_dic[b2_function] = set()

    # Get matched_pairs_in_function_dic
    for matched_function_pair in bin_diff.function_matches:
        func_addr_1 = matched_function_pair[0]
        func_addr_2 = matched_function_pair[1]
        
        #print(hex(addr_1)+","+hex(addr_2))
        function_diff = bin_diff.get_function_diff(func_addr_1, func_addr_2)
        #print(hex(func_addr_1),": block_matches")
        #print(function_diff.block_matches)
        for matched_block_pair in function_diff.block_matches:
            bb_addr_1 = matched_block_pair[0].addr
            bb_addr_2 = matched_block_pair[1].addr
            
            # add to b1 to b2 matched pair dic
            #b1_to_b2_matched_pairs_dic[func_addr_1] = func_addr_2
            
            # append to the pair list
            b1_matched_pairs_in_function_dic[func_addr_1].append([hex(bb_addr_1), hex(bb_addr_2)])
            b2_matched_pairs_in_function_dic[func_addr_2].append([hex(bb_addr_1), hex(bb_addr_2)])
            
            # add to the b1_matched_blocks_in_function_dic set
            b1_matched_blocks_in_function_dic[func_addr_1].add(hex(bb_addr_1))
            
            # add to the b2_matched_blocks_in_function_dic set
            b2_matched_blocks_in_function_dic[func_addr_2].add(hex(bb_addr_2))
    
            
    # Print out the b1 result
    with open(outputDir + '/b1_matched_pairs_within_functions_angr', 'w') as f:
        for b1_function in b1_matched_pairs_in_function_dic:
            b1_matched_pairs_in_function_dic[b1_function].sort()
            print(hex(b1_function), b1_functions[b1_function].name, "Matched pairs:   ", b1_matched_pairs_in_function_dic[b1_function], file=f)
            #print(b1_matched_pairs_in_function_dic[b1_function], file=f)
            
            b1_unmatched_set = b1_all_blocks_in_function_dic[b1_function] - b1_matched_blocks_in_function_dic[b1_function]
            #print(hex(b1_function), b1_functions[b1_function].name)
            print(hex(b1_function), b1_functions[b1_function].name, "Unmatched blocks:", b1_unmatched_set, "\n", file = f)
            
    # Print out b2 result
    with open(outputDir + '/b2_matched_pairs_within_functions_angr', 'w') as f:
        for b2_function in b2_matched_pairs_in_function_dic:
            
            b2_matched_pairs_in_function_dic[b2_function].sort()
            print(hex(b2_function), b2_functions[b2_function].name, "Matched pairs:   ", b2_matched_pairs_in_function_dic[b2_function], file=f)
            #print(b2_matched_pairs_in_function_dic[b2_function], file=f)
            
            b2_unmatched_set = b2_all_blocks_in_function_dic[b2_function] - b2_matched_blocks_in_function_dic[b2_function]
            #print(hex(b1_function), b1_functions[b1_function].name)
            print(hex(b2_function), b2_functions[b2_function].name, "Unmatched blocks:", b2_unmatched_set,"\n", file = f)
            
        
    print("Done.")
    

    
def main():
    
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')
    
    parser.add_argument('--input2', required=True, help='Input bin file 2')

    parser.add_argument('--outputDir', required=True, help='Specify the output directory') 
    
    args = parser.parse_args()
    filepath1 = args.input1
    filepath2 = args.input2
    outputDir = args.outputDir
    
   
    bindiff(filepath1,filepath2,outputDir)


if __name__ == "__main__":
    main()

    
