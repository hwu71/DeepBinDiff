import angr
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

def angrCalculateNode(filepath1, filepath2):
    prog1 = angr.Project(filepath1, load_options={'auto_load_libs': False})
    prog2 = angr.Project(filepath2, load_options={'auto_load_libs': False})

    #print("Analyzing the binaries to generate CFGs...")
    # Modified by Hongwei
    cfg1 = prog1.analyses.CFGFast()
    #cg1 = cfg1.functions.callgraph
    print("First binary done")
    # Modified by Hongwei
    cfg2 = prog2.analyses.CFGFast()
    #cg2 = cfg2.functions.callgraph
    print("CFGs Generated!")

    #nodelist1 = list(cfg1.graph.nodes)
    #edgelist1 = list(cfg1.graph.edges)

    #nodelist2 = list(cfg2.graph.nodes)
    #edgelist2 = list(cfg2.graph.edges)
    print("The two binaries have total of {} nodes.".format(len(cfg1.graph.nodes) + len(cfg2.graph.nodes)))
    return 

def main():
    # example:
    # python3 src/deepbindiff.py --input1 input/ls_6.4 --input2 input/ls_8.30 --outputDir output/

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--input1', required=True, help='Input bin file 1')
    
    parser.add_argument('--input2', required=True, help='Input bin file 2')

    args = parser.parse_args()
    filepath1 = args.input1
    filepath2 = args.input2
    angrCalculateNode(filepath1, filepath2)


if __name__ == "__main__":
    main()