import sys
import os
import numpy as np
# from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import utility
# import time

import preprocessing


if sys.platform != "win32":
    embedding_file = "./vec_all"
    func_embedding_file = "./func_vec_all"
    node2addr_file = "./data/DeepBD/nodeIndexToCode"
    func2addr_file = "./data/DeepBD/functionIndexToCode"
    bin_edgelist_file = "./data/DeepBD/edgelist"
    bin_features_file = "./data/DeepBD/features"
    func_features_file = "./data/DeepBD/func.features"
    ground_truth_file = "./data/DeepBD/addrMapping"
else:
    embedding_file = ".\\vec_all"
    func_embedding_file = ".\\func_vec_all"
    node2addr_file = ".\\data\\DeepBD\\nodeIndexToCode"
    func2addr_file = ".\\data\\DeepBD\\functionIndexToCode"
    bin_edgelist_file = ".\\data\\DeepBD\\edgelist"
    bin_features_file = ".\\data\\DeepBD\\features"
    func_features_file = ".\\data\\DeepBD\\func.features"
    ground_truth_file = ".\\data\\DeepBD\\addrMapping"

# whether use deepwalk to create embeddings for each function or not 
# Set to false as default, which can get better result for now.
EBD_CALL_GRAPH = False 


def pre_matching(bin1_name, bin2_name, outputDir, toBeMergedBlocks={}):
    # if sys.platform != "win32":


    tadw_command = "python3 ./src/performTADW.py --method tadw --input " + bin_edgelist_file + " --graph-format edgelist --feature-file " + bin_features_file + " --output vec_all"
    os.system(tadw_command)
    
    ebd_dic, _ = utility.ebd_file_to_dic(embedding_file)

    node_in_bin1, _node_in_bin2, bb_list = utility.readNodeInfo(node2addr_file)
    #print (type(bb_list))
    
        
    bin1_mat = []
    bin2_mat = []
    node_map = {}
    for idx, line in ebd_dic.items():
        if idx < node_in_bin1:
            bin1_mat.append(line)
            node_map[str(idx)] = len(bin1_mat) - 1
        else:
            bin2_mat.append(line)
            node_map[str(idx)] = len(bin2_mat) - 1


    bin1_mat = np.array(bin1_mat)
    bin2_mat = np.array(bin2_mat)
    sim_result = utility.similarity_gpu(bin1_mat, bin2_mat)
    
    print("Perform matching...")
    matched_pairs, inserted, deleted = utility.matching(node_in_bin1, ebd_dic, sim_result, node_map, toBeMergedBlocks)

    print("matched pairs: ")
    print(matched_pairs)
    
    print("Convert index to addr ...")
    # Hongwei: convert index to addr 
    index_to_addr_dic = {}
    for bb_info in bb_list:
        bb_index = bb_info[0]
        bb_start_addr = hex(int(bb_info[1],16))
        index_to_addr_dic[bb_index] = bb_start_addr 
        
    matched_pairs_with_addr = []
    for pair in matched_pairs:
        addr1 = index_to_addr_dic[pair[0]]
        addr2 = index_to_addr_dic[pair[1]]
        matched_pairs_with_addr.append([addr1,addr2])
    
    print("Writing result: matched pairs with addr ...")    
    with open(outputDir + 'matched_pairs_with_addr', 'w') as f:  
        for pair in matched_pairs_with_addr:
            print(pair[0],pair[1],file=f)
            
    #print("matched pairs with address:")
    #print(matched_pairs_with_addr)
    return matched_pairs_with_addr
    
    #print("matched paris in address: ")
    #for pair in matched_pairs:
    #    addr_1 = 

    # print("Inserted blocks: ")
    # print(inserted)

    # print("Deleted blocks: ")
    # print(deleted)

   


# if __name__ == '__main__' :
#     # here is cross-platform configurations. 
#     # actually I can do this in more elegant way, but it is enough for testing.
    
#     # np.set_printoptions(threshold=np.inf, suppress=True)  # set numpy options
#     sys.exit(two_level_matching('yes_830_o1', 'yes_830_o3'))
