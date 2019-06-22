# -*- coding: utf-8 -*-


# Store the edge corresponding indexed by hash.


import os
import sys
import pandas as pd
import time
import struct

def Take4stElem(elem):
    return elem[4]

def HexStringToInt(elem):
    if type(elem) == 'str':
        return int(elem, 16)
    return elem

def main():

    time_start = time.time()

    node_relate_file = sys.argv[1];
    edge_relate_file = sys.argv[2];
    #node_relate_file = 'readelf_node_relation.txt'
    #edge_relate_file = 'readelf_node_relation'
    f_ret = open(edge_relate_file, 'wb')

    '''
    #head_addr tail_addr head_id tail_id hash edge_num_all_call
    data = []
    f = open(node_relate_file)
    for line in f.readlines():
        row = line.split(' ')
        for i in range(6):
            row[i] = int(row[i], 16)
        data.append(row)

    data.sort(key=Take4stElem)

    for i in range(len(data)):
        last_hash = data[i][4]
        for j in range(len(data)):
            # head node addr  or  tail node addr
            if data[i][0] == data[j][0] or data[i][1] == data[j][0]:
                # print child edge hash of head node
                if data[i][4] != data[j][4]:
                    print('%04x %04x %x' % (data[i][4], data[j][4], data[j][5]))
    
    '''


    data = pd.read_csv(node_relate_file, sep=' ', skipfooter=1, encoding="utf-8", engine='python', header=None)
    data.columns = ['head_addr', 'tail_addr', 'head_id', 'tail_id', 'hash', 'call_num', 'mem_num']
    #data = data.applymap(HexStringToInt)
    data = data.sort_values(by='hash', axis=0, ascending=True)

    dict_neighbour = {}

    num = len(data)
    for i in range(num):
        print('\r%d/%d time=%ds' % (i, num, time.time() - time_start), end='')
        # head node addr  or  tail node addr
        #rows = data.query(("head_addr == '%d' or head_addr == '%d'") % (data.iloc[i][0], data.iloc[i][1]))
        #last_hash = data.iloc[i][4]

        for k in range(2):
            hash_parent = data.iloc[i][k]
            if hash_parent in dict_neighbour:
                rows = dict_neighbour[hash_parent]
            else:
                rows = data.query(("head_addr == '%d'") % hash_parent)            
                if not len(rows):
                    continue                
                dict_neighbour[hash_parent] = rows#.copy()

            for j in range(len(rows)):
                # print child edge hash of head node
                if data.iloc[i][4] != rows.iloc[j][4]:
                    # edge_hash neighbour_edge_hash call_num mem_num
                    #print('%04s %04s %x' % (data.iloc[i][4], rows.iloc[j][4], rows.iloc[j][5]))
                    #f_ret.write('%d %d %d\n' % (data.iloc[i][4], rows.iloc[j][4], rows.iloc[j][5]))
                    bytes = struct.pack('HHHH', data.iloc[i][4], rows.iloc[j][4], rows.iloc[j][5], rows.iloc[j][6])
                    f_ret.write(bytes)
    #'''

    #save file format
    #hash1 hash_raletion_edge1 edge_num_raletion_edge1
    #hash1 hash_raletion_edge2 edge_num_raletion_edge2
    #hash2 hash_raletion_edge3 edge_num_raletion_edge3
    #...

    f_ret.close()
    print(time.time() - time_start)


if __name__ == "__main__":
    main()