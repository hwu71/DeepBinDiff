#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import angr
# list all matched pair within functions in binary 1
def analyzer(binary_path_1, binary_path_2, outputDir, matched_pairs_with_addr):
    
    b1 = angr.Project(binary_path_1, load_options = {"auto_load_libs": False})
    b2 = angr.Project(binary_path_2, load_options = {"auto_load_libs": False})
    b1_cfg = b1.analyses.CFGFast()
    b2_cfg = b2.analyses.CFGFast()
    
    b1_matched_pairs_in_function_dic = {} # Only count once according to func1 
    b2_matched_pairs_in_function_dic = {}
    b1_all_blocks_in_function_dic = {}
    b2_all_blocks_in_function_dic = {}
    b1_matched_blocks_in_function_dic = {}
    b2_matched_blocks_in_function_dic = {}
    b1_functions = b1_cfg.kb.functions
    b2_functions = b2_cfg.kb.functions
    
    print("Convert addr to function_addr ...")
    
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
        
        
    for matched_block_pair in matched_pairs_with_addr:
        # Get bb addrs
        bb_addr_1 = int(matched_block_pair[0], 16)
        bb_addr_2 = int(matched_block_pair[1], 16) 
        node1 = b1_cfg.model.get_any_node(bb_addr_1)
        node2 = b2_cfg.model.get_any_node(bb_addr_2)
        if (node1 != None and node2 != None):
            # Get func addrs
            func_addr_1 = node1.function_address
            func_addr_2 = node2.function_address
            
            # Append to the pair list
            b1_matched_pairs_in_function_dic[func_addr_1].append([hex(bb_addr_1), hex(bb_addr_2)])
            b2_matched_pairs_in_function_dic[func_addr_2].append([hex(bb_addr_1), hex(bb_addr_2)])
            
            # Add to the b1_matched_blocks_in_function_dic set
            b1_matched_blocks_in_function_dic[func_addr_1].add(hex(bb_addr_1))
            
            # Add to the b2_matched_blocks_in_function_dic set
            b2_matched_blocks_in_function_dic[func_addr_2].add(hex(bb_addr_2))
            
    print("Writing result of function_addr ...")
    # Print out the b1 result
    with open(outputDir + '/b1_matched_pairs_within_functions_deepbindiff', 'w') as f:
        for b1_function in b1_matched_pairs_in_function_dic:
            
            b1_matched_pairs_in_function_dic[b1_function].sort()
            print(hex(b1_function), b1_functions[b1_function].name, "Matched pairs:   ", b1_matched_pairs_in_function_dic[b1_function], file=f)
            #print(b1_matched_pairs_in_function_dic[b1_function], file=f)
            
            b1_unmatched_set = b1_all_blocks_in_function_dic[b1_function] - b1_matched_blocks_in_function_dic[b1_function]
            #print(hex(b1_function), b1_functions[b1_function].name)
            print(hex(b1_function), b1_functions[b1_function].name, "Unmatched blocks:", b1_unmatched_set, "\n", file = f)
            
    # Print out b2 result
    with open(outputDir + '/b2_matched_pairs_within_functions_deepbindiff', 'w') as f:
        for b2_function in b2_matched_pairs_in_function_dic:
            
            b2_matched_pairs_in_function_dic[b2_function].sort()
            print(hex(b2_function), b2_functions[b2_function].name, "Matched pairs:   ", b2_matched_pairs_in_function_dic[b2_function], file=f)
            #print(b2_matched_pairs_in_function_dic[b2_function], file=f)
            
            b2_unmatched_set = b2_all_blocks_in_function_dic[b2_function] - b2_matched_blocks_in_function_dic[b2_function]
            #print(hex(b1_function), b1_functions[b1_function].name)
            print(hex(b2_function), b2_functions[b2_function].name, "Unmatched blocks:", b2_unmatched_set,"\n", file = f)
        
        
    print("Done.")
        
        
        
    '''
    p = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = p.analyses.CFGFast()
    functions = cfg.kb.functions
    matched_pairs_in_function_dic = {}
    
    # Initilize to a emplty list
    with open(outputDir + 'matched_pairs_within_functions', 'w') as f:
        for function in functions:
           #print(hex(function))
           #print(cfg.kb.functions[function].block_addrs)
           #block_addrs = cfg.kb.functions[function].block_addrs
           #for block_addr in block_addrs:
           #    print("\t",hex(block_addr))
           matched_pairs_in_function_dic[function] = []
        
        
        for pair in matched_pair_with_addr:
            bb_addr = int(pair[0],16)
            node = cfg.model.get_any_node(bb_addr)
            if(node != None):
                func_addr = node.function_address
                matched_pairs_in_function_dic[func_addr].append(pair)
                #print(hex(bb_addr), hex(func_addr))
        
        
        for key in matched_pairs_in_function_dic:
            #print(hex(key),":",matched_pairs_in_function_dic[key],"\n", file = f)
            matched_pairs_in_function_dic[key].sort()
            print(hex(key), cfg.kb.functions[key].name, file=f)
            print(matched_pairs_in_function_dic[key],"\n", file=f)
    '''
