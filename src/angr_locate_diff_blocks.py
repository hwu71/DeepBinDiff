#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep 24 20:15:38 2020

@author: hongwei
"""
import angr
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import networkx as nx
#import similarity_angr 
import sys
#import matplotlib.pyplot as plt
from visualize_helper import *
import pyvex
from collections import Counter

def angrLocateDiffFunctions(b1_cfg, b2_cfg):
    '''
    p1 = angr.Project(filepath1, load_options={'auto_load_libs': False})
    p2 = angr.Project(filepath2, load_options={'auto_load_libs': False})
    

    b1_cfg = p1.analyses.CFGFast()
    print("First binary done")
    
    b2_cfg = p2.analyses.CFGFast()
    print("Second binary done")
    '''
    diff_functions = []
    b1_functions = b1_cfg.kb.functions
    b2_functions = b2_cfg.kb.functions

    for func_addr_1 in b1_functions:
        function_1 = b1_functions[func_addr_1]
        for func_addr_2 in b2_functions:
            function_2 = b2_functions[func_addr_2]
            if (len(function_1.block_addrs) > 1 and len(function_2.block_addrs) > 1) and (function_1.name == function_2.name) and (function_1.size != function_2.size):
                print("The two functions (%s) don't match: 0x%x(%d,%d), 0x%x(%d,%d)" % 
                    (function_1.name, func_addr_1, function_1.size, len(function_1.block_addrs),
                     func_addr_2, function_2.size, len(function_2.block_addrs)))
                diff_functions.append((func_addr_1,func_addr_2, function_1.name))

    #print("The two binaries have total of {} nodes.".format(len(cfg1.graph.nodes) + len(cfg2.graph.nodes)))
    return diff_functions

def getFuncAddr(cfg, func_name):
    functions = cfg.kb.functions
    for func_addr in functions:
        function = functions[func_addr]
        if(function.name == func_name):
            return func_addr
    return None
def cal_block_size(p, block_addr):
    total_size = 0
    
    capstone=p.factory.block(block_addr).capstone
    #print(capstone)
    for ins in capstone.insns:
        opcode = str(ins).split('\t')[1]
        if(opcode == 'call'):
            total_size += 5
        elif(opcode.startswith("j")):
            total_size += 2
        else:
            total_size += ins.size
       #print(ins.size)
    return total_size
def get_irsb_tags(p, block_addr):
    irsb=p.factory.block(block_addr).vex
    tags = [stmt.tag for stmt in irsb.statements]
    return tags
def export_graph(p, graph):
    
    G = nx.DiGraph()
    
    bc = nx.betweenness_centrality(graph)

    '''# Dummy node
    G.add_nodes_from([ (0,{"size":-1,
                           "successors": 1,
                           "predecessors": 0,
                           "#instructions": 0,
                           "opcodes": None,
                           "betweenness": 0})])
    '''
    # Add nodes from angr cfg
    G.add_nodes_from([ (node.addr, {"size": cal_block_size(p, node.addr), 
                                     "successors": len(node.successors()),
                                     "predecessors": len(node.predecessors()),
                                     "#instructions": p.factory.block(node.addr).vex.instructions,
                                     "opcodes": [str(ins).split('\t')[1] for ins in p.factory.block(node.addr).capstone.insns],
                                     "irsb_tags": get_irsb_tags(p, node.addr),
                                     #"operations": p1.factory.block(node.addr).vex.operations,
                                     "betweenness": bc[node],
                                     }) 
                       for node in graph.nodes()])
    
    # Add edges from angr cfg
    G.add_edges_from([ (edge[0].addr, edge[1].addr, {"from": G.nodes()[edge[0].addr], 
                                                       "to": G.nodes()[edge[1].addr]}) for edge in graph.edges() ])

    '''
    # Find the addr of the root node
    root = 0
    for n,d in G.in_degree():
        if d == 0:
            root = n
            break
    
    # Add an edge from dummy node to root node
    G.add_edges_from([ (0, root, {"from": G.nodes()[0], "to": G.nodes()[root]})])
     '''  

    return G
def my_node_subst_cost(node1, node2):
    '''if(node1["size"] == node2["size"] == -1):
        return 0
    elif(node1["size"] == -1 or node2["size"] == -1):
        return sys.maxsize
    '''
    bt_flag = (abs(node1['betweenness'] - node2['betweenness'])/max(node1['betweenness'],
            node2['betweenness'])) if (max(node1['betweenness'],node2['betweenness']) != 0) else 0 
    #node1['size'] == node2['size'] \
    #and node1['opcodes'] == node2['opcodes']\

    if node1['successors'] == node2['successors'] \
        and node1['predecessors'] == node2['predecessors']\
        and node1['#instructions'] == node2['#instructions']\
        and node1['irsb_tags'] == node2['irsb_tags']\
        and bt_flag < 0.2:
            return 0
    else :
        return sys.maxsize
'''
def my_node_del_cost(node):
    return node.size

def my_node_ins_cost(node):
    return node.size

def my_edge_subst_cost(edge1, edge2):
    if my_node_subst_cost(edge1["from"], edge2["from"]) == 0 and my_node_subst_cost(edge2["to"],edge2["to"]) == 0:
        return 0
    else:
        return sys.maxsize
   
def my_edge_del_cost(edge):
    node_1 = edge[0]
    node_2 = edge[1]
    return (node_1.size + node_2.size)

def my_edge_ins_cost(edge):
    node_1 = edge[0]
    node_2 = edge[1]
    return (node_1.size + node_2.size)

'''
def SecondRoundComparison(p1, p2, G1, G2, matched_nodes, added_nodes_1, added_nodes_2):
    # second round comparison
    for node_pair in matched_nodes:
        node_1 = G1.nodes()[node_pair[0]]
        node_2 = G2.nodes()[node_pair[1]]
        irsb_1 = p1.factory.block(node_pair[0]).vex
        irsb_2 = p2.factory.block(node_pair[1]).vex
        # the collection of Opcodes list
        if(Counter(node_1['opcodes'])!=Counter(node_2['opcodes'])):
            print("Incorrect match: 0x%x, 0x%x, %s, %s" % (node_pair[0], node_pair[1], 
                                          node_1['opcodes'],
                                          node_2['opcodes']))
            added_nodes_1.append(node_pair[0])
            added_nodes_2.append(node_pair[1])
            matched_nodes.remove(node_pair)
        
        # TODO: Call/Jump target
        
        # TODO: constants in arithmetic statements/ get statements
    return matched_nodes, added_nodes_1, added_nodes_2
def angrLocateDiffBlocks(p1, p2, b1_cfg, b2_cfg, diff_function_pair):
    #b1_target_function_addr = diff_function_pair[0]
    #b2_target_function_addr = diff_function_pair[1]
    b1_target_function = b1_cfg.kb.functions[diff_function_pair[0]]
    b2_target_function = b2_cfg.kb.functions[diff_function_pair[1]]
    graph_1 = b1_target_function.graph
    graph_2 = b2_target_function.graph
    #G1, G2 = export_graph(p1, p2, graph_1, graph_2)
    G1 = export_graph(p1, graph_1)
    G2 = export_graph(p2, graph_2)
    final_added_nodes_1 = []
    final_added_nodes_2 = []
    final_matched_nodes = []
    
    '''
    for path in similarity_angr.optimize_edit_paths(graph_1,graph_2,
                                                    node_subst_cost = my_node_subst_cost, 
                                                    #node_del_cost = my_node_del_cost,
                                                    #node_ins_cost = my_node_ins_cost,
                                                    edge_subst_cost = my_edge_subst_cost,
                                                    #edge_del_cost = my_edge_del_cost,
                                                    #edge_ins_cost = my_edge_ins_cost,
                                                    timeout = 60):
    '''
    for path in nx.similarity.optimize_edit_paths(G1,G2,
                                                    node_subst_cost = my_node_subst_cost, 
                                                    #node_del_cost = my_node_del_cost,
                                                    #node_ins_cost = my_node_ins_cost,
                                                    #edge_subst_cost = my_edge_subst_cost,
                                                    #edge_del_cost = my_edge_del_cost,
                                                    #edge_ins_cost = my_edge_ins_cost,
                                                    #roots = (0,0),
                                                    timeout = 30):
        print("\nNew path:")
        (node_path, edge_path, cost) = path
        
        added_nodes_1 = []
        added_nodes_2 = []
        matched_nodes = []
        for node_pair in node_path:
            if (node_pair[1]==None):
                added_nodes_1.append(node_pair[0])
                #print("0x%x, None" % (node_pair[0]))
            elif (node_pair[0] == None):
                #print("None, 0x%x" % (node_pair[1]))
                added_nodes_2.append(node_pair[1])
            else:
                matched_nodes.append(node_pair)
                node_1 = G1.nodes()[node_pair[0]]
                node_2 = G2.nodes()[node_pair[1]]
                '''print("0x%x, 0x%x, %f, %f" % (node_pair[0], node_pair[1], 
                                              node_1['betweenness'],
                                              node_2['betweenness']))
                '''
        print(cost)
        matched_nodes, added_nodes_1, added_nodes_2 = SecondRoundComparison(p1,
                       p2, G1, G2, matched_nodes, added_nodes_1, added_nodes_2)
        
                
        
        # Print out the results
        print("\nAdded nodes according to node path: ")
        print("\nB1:")
        for node in added_nodes_1:
            print(hex(node), G1.nodes()[node])
        print("\nB2:")
        for node in added_nodes_2:
            print(hex(node), G2.nodes()[node]) 
        
        #print("\nB1:", [hex(node) for node in added_nodes_1])
        #print("B2:", [hex(node) for node in added_nodes_2])
        
        '''
        b1_added_edges = []
        b2_added_edges = []
        for edge_pair in edge_path:
            if(edge_pair[1] == None):
                b1_added_edges.append(edge_pair[0])
            elif(edge_pair[0] == None):
                b2_added_edges.append(edge_pair[1])
        
        b1_added_edges_nodes_1 = set(edge[0] for edge in b1_added_edges)
        b1_added_edges_nodes_2 = set(edge[1] for edge in b1_added_edges) 
        b2_added_edges_nodes_1 = set(edge[0] for edge in b2_added_edges)
        b2_added_edges_nodes_2 = set(edge[1] for edge in b2_added_edges)
        
        print("\n added nodes according to edge path: ")
        #print("b1:")
        for node_addr in b1_added_edges_nodes_1:
            if node_addr in b1_added_edges_nodes_2:
                print("b1: 0x%x" % node_addr)
        
        for node_addr in b2_added_edges_nodes_1:
            if node_addr in b2_added_edges_nodes_2:
                print("b2: 0x%x" % node_addr)
        '''
        final_added_nodes_1 = added_nodes_1
        final_added_nodes_2 = added_nodes_2
        final_matched_nodes = matched_nodes
    return final_added_nodes_1, final_added_nodes_2, final_matched_nodes
        
    
def main():
    # example:
    # python3 src/deepbindiff.py --input1 input/ls_6.4 --input2 input/ls_8.30 --outputDir output/

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')
    
    parser.add_argument('--input2', required=True, help='Input bin file 2')
    
    parser.add_argument('--func_name', required=False, default=None, help='Input target function name')

    parser.add_argument('--func_addr_1', required=False, default=None, help='Input target function addr 1')
    parser.add_argument('--func_addr_2', required=False, default=None, help='Input target function addr 2')
    
    args = parser.parse_args()
    filepath1 = args.input1
    filepath2 = args.input2
    target_func_name = args.func_name
    func_addr_1 = args.func_addr_1
    func_addr_2 = args.func_addr_2
    
    p1 = angr.Project(filepath1, load_options={'auto_load_libs': False})
    p2 = angr.Project(filepath2, load_options={'auto_load_libs': False})
    
    b1_cfg = p1.analyses.CFGFast()
    print("First binary done")
    
    b2_cfg = p2.analyses.CFGFast()
    print("Second binary done")
    
    if(target_func_name == None):
        angrLocateDiffFunctions(b1_cfg, b2_cfg)
    else:
        #func_addr_1 = getFuncAddr(b1_cfg, target_func_name)
        #func_addr_2 = getFuncAddr(b2_cfg, target_func_name)
        if(func_addr_1 != None and func_addr_2 != None):
            func_addr_1 = int(func_addr_1, base=16)
            func_addr_2 = int(func_addr_2, base=16)
            added_nodes_1, added_nodes_2, matched_nodes = angrLocateDiffBlocks(p1, p2, b1_cfg, b2_cfg, (func_addr_1, func_addr_2))
            print("\nB1:", [hex(node) for node in added_nodes_1])
            print("B2:", [hex(node) for node in added_nodes_2])
            # Draw cfg
            # binary 1: original
            
            visulize_helper(filepath1, func_addr_1, label = "original", _added_blocks=added_nodes_1)
            # binary 2: original
            visulize_helper(filepath2, func_addr_2, label = "patched", _added_blocks=added_nodes_2)
            

if __name__ == "__main__":
    main()