#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Sep 30 13:13:26 2020

@author: hongwei
"""

import networkx as nx

G1 = nx.read_gpickle("G_original.gpickle")
G2 = nx.read_gpickle("G_patched.gpickle")

print(len(G1.nodes()), len(G1.edges()))
print(len(G2.nodes()), len(G2.edges()))