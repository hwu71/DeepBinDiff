import angr
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

def angrLocateDiffFunctions(p1, p2):
    '''
    p1 = angr.Project(filepath1, load_options={'auto_load_libs': False})
    p2 = angr.Project(filepath2, load_options={'auto_load_libs': False})
    '''

    b1_cfg = p1.analyses.CFGFast()
    print("First binary done")
    
    b2_cfg = p2.analyses.CFGFast()
    print("Second binary done")
    
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
                diff_functions.append((func_addr_1,func_addr_2))

    #print("The two binaries have total of {} nodes.".format(len(cfg1.graph.nodes) + len(cfg2.graph.nodes)))
    return diff_functions

def main():
    # example:
    # python3 src/deepbindiff.py --input1 input/ls_6.4 --input2 input/ls_8.30 --outputDir output/

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')
    
    parser.add_argument('--input2', required=True, help='Input bin file 2')

    args = parser.parse_args()
    filepath1 = args.input1
    filepath2 = args.input2
    p1 = angr.Project(filepath1, load_options={'auto_load_libs': False})
    p2 = angr.Project(filepath2, load_options={'auto_load_libs': False})
    diff_functions = angrLocateDiffFunctions(p1, p2)
    


if __name__ == "__main__":
    main()