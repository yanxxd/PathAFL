#!/usr/bin/env python
# coding: utf-8

#import ptvsd

try:
    # Enable the debugger. Raises exception if called more than once.
	#ptvsd.enable_attach(secret="IDA")
	#ptvsd.wait_for_attach()
	#break_into_debugger()
    pass
except:
    pass

import sys
import time
import datetime
import ctypes
import math
import random

import idc
import idaapi
import idautils
from idaapi import PluginForm, plugin_t


# num of edge in one func
g_num_edge = 0
# num of call in one func
g_num_call = 0
# num of edge in all func
g_dict_func_edge = {} 
# offset of set random instruction
g_off_set_random = 0x16
# size of ins block
g_size_ins_block = 0x38
# offset of random in mov ins
g_off_random = 3
# MAPSIZE bits of afl-fuzz
g_map_size = 16
# offset of x from head
g_off_x = 7
# offset of z from head
g_off_z = 3
# offset of y from head of instrument fun 
g_off_y = []

def IsInstrumentIns(ea):
    '''
    is ea instrument instruction?
    '''
    if idc.__EA64__: # 64bit
        '''
.text:0000000000412450 48 8D 64 24 80    lea     rsp, [rsp-80h]
.text:0000000000412455 53                push    rbx
.text:0000000000412456 51                push    rcx
.text:0000000000412457 68 30 E2 00 00    push    0E230h                 // z
.text:000000000041245C 48 C7 C1 00 00 00+mov     rcx, 0                 // x
.text:0000000000412463 48 C7 C3 19 D6 00+mov     rbx, 0D619h
.text:000000000041246A E8 51 44 00 00    call    __afl_maybe_log_fun_3
.text:000000000041246F 59                pop     rcx
.text:0000000000412470 59                pop     rcx
.text:0000000000412471 5B                pop     rbx
.text:0000000000412472 48 8D A4 24 80 00+lea     rsp, [rsp+80h] 
        '''
        if 0x6851538024648D48 == idc.Qword(ea) and 0xC748 == idc.Word(ea+0xc) and 0xC748 == idc.Word(ea+0x13) and 0x0000008024A48D48 == idc.Qword(ea+0x22):
            return True
    else: # 32bit
        '''
        52                push    edx
        51                push    ecx
        50                push    eax
        B9 8A 7D 00 00    mov     ecx, 7D8Ah
        E8 53 10 00 00    call    __afl_maybe_log
        58                pop     eax
        59                pop     ecx
        5A                pop     edx
        '''
        if 0xB9505152 == idc.Dword(ea) and 0x5A595800 == idc.Dword(ea+12):
            return True

    return False


def SetInstrumentParam():
    global g_size_ins_block
    global g_off_set_random
    global g_off_random
    global g_off_x
    global g_off_z
    global g_off_y
    
    if idc.__EA64__: # 64bit
        g_size_ins_block = 0x2A
        g_off_set_random = 0x13
        g_off_random = 3
        g_off_x = 15
        g_off_z = 8
        g_off_y = [0x22, 0x45]
    else: # 32bit
        g_size_ins_block = 0x10
        g_off_set_random = 3
        g_off_random = 1


def GetBBLRidAddr(ea):
    '''
    Get bbl random value addr.
    '''
    global g_off_set_random
    global g_off_random
    return ea + g_off_random + g_off_set_random


def GetBBLRid(ea):
    '''
    Get bbl random value.
    '''
    return idc.Dword(GetBBLRidAddr(ea))


def FixFmulY(head, y, bFun):
    # fix y
    global g_off_y
    for off in g_off_y:
        if bFun:
            idc.PatchByte(head+off+7, y)
        else:
            idc.PatchByte(head+off, y)
    return


def GetY(head):
    global g_off_y
    return idc.Byte(head+g_off_y[0])


def FixFmulXZ(head, x, z):
    # fix x z
    global g_off_x
    global g_off_z
    idc.PatchDword(head+g_off_x, x)
    idc.PatchDword(head+g_off_z, z)
    return


def FixFsingleZ(head, z):
    FixFmulXZ(head, 0xFF, z)
    return


def GetXZ(head):    
    global g_off_x
    global g_off_z
    return idc.Dword(head+g_off_x), idc.Dword(head+g_off_z)


def IsSanFunc(fun):
    '''
    Is sanitizer function?
    @fun int or str
    '''
    if isinstance(fun, int) or isinstance(fun, long):
        fun_name = idc.GetFunctionName(fun)
    elif isinstance(fun, str):
        fun_name = fun.lower()
    else:
        return False

    if fun_name.find('asan') >= 0 or fun_name.find('sanitizer') >= 0 \
        or fun_name.find('lsan') >= 0 or fun_name.find('ubsan') >= 0:
        return True
    return False


def LookForInsChildBbls(head, edges, stack):
    """
    looks for instrumented child bbls.
    @edges = {}   # dict struct.  head -> of (head, ..., head)
    @stack      stack of search address, avoid recusion loops
    ## return   bbl sequence of all child edges.
    """
    # seqs = {}   # head -> [bbl1, bbl2, ...]
    bbls_child = set()

    # avoid recusion loops
    if head in stack:
        return bbls_child
    stack.append(head)
    
    if head not in edges:
        return bbls_child

    for b in edges[head]:
        if IsInstrumentIns(b):
            bbls_child.add(b)
        else:
            if b == head:   # stuck in dead recursion
                continue
            bbls_child_t = LookForInsChildBbls(b, edges, stack)
            bbls_child.update(bbls_child_t)

    return bbls_child


def GetFunEdgesAndBbls(function_ea):
    """
    Get bbls of function.
    @function_ea - function address
    @return - bbls of function
    """
    bbl = [] # bbl info [head, tail, call_num, mem_num]
    SingleBBS = {}  # head -> pred_bbl
    MultiBBS = {}   # head -> [pred_bbls]
    bbls = {}   # head -> bbl
    bbls2 = {}  # tail -> bbl
    edges_s = set() # set of (tail, head)
    edges_d = {}    # dict struct.  head -> of (head, ..., head)
    edges_count = 0
    edges_s_t = set()   # tmp edges set
    edges_d_t = {}      # tmp edges dict.


    if not IsInstrumentIns(function_ea):
        return bbls, edges_d, edges_count, SingleBBS, MultiBBS

    f_start = function_ea
    f_end = idc.FindFuncEnd(function_ea)

    boundaries = set((f_start,))    # head of bbl    
    
    for head in idautils.Heads(f_start, f_end):
        # If the element is an instruction
        if head == idaapi.BADADDR:
            raise Exception("Invalid head for parsing")
        if not idc.isCode(idc.GetFlags(head)):
            continue

        # Get the references made from the current instruction
        # and keep only the ones local to the function.
        refs = idautils.CodeRefsFrom(head, 0)
        refs_filtered = set()
        for ref in refs:
            if ref > f_start and ref < f_end:   # can't use ref>=f_start, avoid recusion
                refs_filtered.add(ref)
        refs = refs_filtered

        if refs:
            # If the flow continues also to the next (address-wise)
            # instruction, we add a reference to it.
            # For instance, a conditional jump will not branch
            # if the condition is not met, so we save that
            # reference as well.
            next_head = idc.NextHead(head, f_end)
            if next_head != idaapi.BADADDR and idc.isFlow(idc.GetFlags(next_head)):
                refs.add(next_head)
                
            # Update the boundaries found so far.
            boundaries.update(refs)
            for r in refs:  # enum all of next ins
                # If the flow could also come from the address
                # previous to the destination of the branching
                # an edge is created.
                if isFlow(idc.GetFlags(r)):
                    prev_head = idc.PrevHead(r, f_start)
                    if prev_head == 0xffffffffL:
                        #edges_s_t.add((head, r))
                        #raise Exception("invalid reference to previous instruction for", hex(r))
                        pass
                    else:
                        edges_s_t.add((prev_head, r))
                edges_s_t.add((head, r))

    #end of for head in idautils.Heads(chunk[0], chunk[1]):
        
    last_head = 0
    # NOTE: We can handle if jump xrefs to chunk address space.

    # get bbls. head of bbl is first ins addr, tail of bbl is last ins addr.
    for head in idautils.Heads(f_start, f_end):
        mnem = idc.GetMnem(head)
        if head in boundaries:
            if len(bbl) > 0:
                if bbl[0] == head:
                    continue
                if True:    # IsInstrumentIns(bbl[0]):
                    bbl[1] = last_head
                    bbls[bbl[0]] = bbl
                    bbls2[bbl[1]] = bbl
            bbl = [head, 0, 0, 0]
        #elif self.GetInstructionType(head) == self.BRANCH_INSTRUCTION:
        elif mnem.startswith('j'):
            if len(bbl) > 0 and bbl[0] == head + idc.ItemSize(head):
                continue
            if True:    # IsInstrumentIns(bbl[0]):
                bbl[1] = head # head + idc.ItemSize(head))
                bbls[bbl[0]] = bbl
                bbls2[bbl[1]] = bbl
            bbl = [head + idc.ItemSize(head), 0, 0, 0]
        else:
            last_head = head
        if mnem.startswith('call'):
            bbl[2] += 1
        
        #if 2 == idc.GetOpType(head, 0):      # 2  Memory Reference
        #    bbl[3] += 1
        #if 2 == idc.GetOpType(head, 1):      # 2  Memory Reference
        #    bbl[3] += 1

    # add last basic block
    if len(bbl) and bbl[0] != f_end: # and IsInstrumentIns(bbl[0]):
        bbl[1] = f_end
        bbls[bbl[0]] = bbl
        bbls2[bbl[1]] = bbl
 
    # edges set -> dict
    for e in edges_s_t:
        if e[0] in bbls2:
            bbl_head = bbls2[e[0]][0]
            if bbl_head in edges_d_t:
                edges_d_t[bbl_head].append(e[1])
            else:
                edges_d_t[bbl_head] = [e[1]]
        else:
            print('edge (%x, %x) can not find head bbl.' % (e[0], e[1])) # a small case. e1 flow e0.

    # revise edges. head bbl and tail bbl of edges must be instrumented.
    for e0 in edges_d_t:
        if not IsInstrumentIns(e0): # e0 don't instrumented, skip.
            continue

        for e1 in edges_d_t[e0]:
            if IsInstrumentIns(e1):      # e0 e1 both instrumented, add edge.
                if e0 in edges_d:
                    edges_d[e0].append(e1)
                else:
                    edges_d[e0] = [e1]
                edges_count += 1
            else:
                # e1 don't instrumented, recursively looks for instrumented child bbls
                bbls_t = LookForInsChildBbls(e1, edges_d_t, [])
                for b in bbls_t: # add edge                
                    if e0 in edges_d:
                        edges_d[e0].append(b)
                    else:
                        edges_d[e0] = [b]
                    edges_count += 1

    # revise bbls. bbl must be instrumented.
    for b in bbls.keys():
        if not IsInstrumentIns(b):
            # if bbls[b][1] in bbls2:     # avoid multi del
                # bbls2.pop(bbls[b][1])   
            bbls.pop(b)

    
    #print('bbls:')
    #i = 0
    #for b in bbls:
    #    i += 1
    #    print('%04d %x, %x' % (i, b, bbls[b][1]))

    #print('edges_d:')
    #i = 0
    #for e0 in edges_d:
    #    for e1 in edges_d[e0]:
    #        i += 1
    #        print('%04d %x, %x' % (i, e0, e1))


    for e0 in edges_d:
        if e0 not in bbls:
            print('error:%x have no head' % (e0))   # error
            continue
        for e1 in edges_d[e0]:
            if e1 in MultiBBS:
                MultiBBS[e1].append(bbls[e0])   # add Pred
            elif e1 in SingleBBS:
                MultiBBS[e1] =  [SingleBBS[e1], bbls[e0]]   # add Pred
                SingleBBS.pop(e1)                           # remove from SingleBBS
            else:
                SingleBBS[e1] = bbls[e0]       # add Pred
            
    # del bbls which don't instrumented

    return bbls, edges_d, edges_count, SingleBBS, MultiBBS


def HandleFunc(func):
    
    global g_off_set_random
    global g_size_ins_block

    bbls, edges, SingleBBS, MultiBBS = GetFunEdgesAndBbls(func)
    i = 0
    print('bbls:')
    for b in bbls:
        i += 1
        print('%04d %x, %x' % (i, b, bbls[b]))
    i = 0
    print('edges:')
    for e in edges:
        i += 1
        print('%04d %x, %x' % (i, e[0], e[1]))
        
    i = 0
    print('SingleBBS:')
    for k in SingleBBS:
        i += 1
        print('%04d %x, %x' % (i, k, SingleBBS[k]))
    i = 0
    print('MultiBBS:')
    for k in MultiBBS:
        i += 1
        for v in MultiBBS[k]:
            print('%04d %x, %x' % (i, k, v))
    return

    #for ins in idautils.FuncItems(start):
    #    print(idc.GetDisasm(ins))   
    ea = func
    end = idc.GetFunctionAttr(func, idc.FUNCATTR_END)
    for ea in idautils.Heads(func, end):
        if IsInstrumentIns(ea):
            #print(idc.GetFunctionName(start))
            #print(hex(ea), idc.GetDisasm(ea))
            #idc.SetColor(ea+0x13, CIC_ITEM, 0x0000FF)

            #bbls = GetFunBbls(func)
            bbl_heads = ()
            #for bbl in bbls:
                #bbl_heads.append(bbl[0])
             
            write_head = [0]
            call_stack = []
            #FindChildNode(func, ea+g_off_set_random, ea+g_size_ins_block, call_stack, 0)
            FindChildNode2(func, bbl_heads, ea+g_off_set_random, ea+g_size_ins_block, call_stack, 0, write_head)
            #ea += g_size_ins_block
    pass
    

def tow_search(l, n):
    low = 0
    hight = len(l)
    while low < hight:
        mid = (low + hight) // 2
        if l[mid] <= n and (mid == len(l)-1 or mid < len(l)-1 and l[mid+1] > n):
            return l[mid]
        elif l[mid] < n:
            low = mid
        elif l[mid] > n:
            hight = mid
    return -1


def AssignUniqRandomKeysToBBs(bbls, MultiBBS, max):
    '''
    AssignUniqRandomKeysToBBs
    @bbls
    @max: max value. (2^n - 1)
    '''
    rids = set()
    coll_addrs = set()
    count_rid_coll = 0
    rid_cur = max

    # patch MultiBBS with big rid
    for bbl in MultiBBS:
        idc.PatchDword(GetBBLRidAddr(bbl), rid_cur)
        rids.add(rid_cur)
        rid_cur -= 1
    print('patch MultiBBS with rid > %d' % rid_cur)

    for head in bbls:
        if head in MultiBBS:  # don't patch MultiBBS
            continue
        rid = GetBBLRid(head)
        if rid in rids:
            count_rid_coll += 1
            coll_addrs.add(head)
        else:
            rids.add(rid)
    print('%d/%d coll' % (count_rid_coll, len(bbls)))

    for addr in coll_addrs:
        while rid_cur >= 0: 
            if rid_cur not in rids:
                rids.add(rid_cur)
                idc.PatchDword(GetBBLRidAddr(addr), rid_cur)
                rid_cur -= 1
                break
            rid_cur -= 1

        if rid_cur < 0:
            print('%d rid coll after fixed', len(bbls) - max -1)
            break
    if rid_cur >= 0:
        print('fixed rid coll success!')


def GetCFG():    
    SingleBBS = {}  # head -> pred_bbl
    MultiBBS = {}   # head -> [pred_bbls]
    bbls = {}   # head -> bbl
    # bbls2 = {}  # tail -> bbl
    edges = {}  # dict struct.  head -> of (head, ..., head)   #set()   # set of (tail, head) or (head, head)
    edges_count = 0

    #bbls_t, edges_t, count, SingleBBS_t, MultiBBS_t = GetFunEdgesAndBbls(0x08F7790)  # deubg
    #exit()

    for func in idautils.Functions():
        if IsSanFunc(func):
            continue
        print('%x %s') % (func, idc.GetFunctionName(func))
        bbls_t, edges_t, count, SingleBBS_t, MultiBBS_t = GetFunEdgesAndBbls(func)
        bbls.update(bbls_t)
        # bbls2.update(bbls2_t)
        edges.update(edges_t) # union
        edges_count += count
        SingleBBS.update(SingleBBS_t)
        MultiBBS.update(MultiBBS_t)
    return  bbls, edges, edges_count, SingleBBS, MultiBBS


def CalcFmul(MultiBBS, max_value):

    global g_map_size

    y = 0
    Params={}       # head -> (x, z)
    Hashes = set()
    bOk = False

    count_solv_best = 0
    count_unsolv_best = 0
    y_best = 0
    Params_best = {}

    Params_Fun = {} # functions which no direct caller
    for head in MultiBBS:
        if  0 == len(MultiBBS[head]):
            # a function which no direct caller. set x z random
            Params_Fun[head] = (0, random.randint(0, g_map_size))


    for y in range(0, 2):
        Hashes = set()
        Params={}
        Solv = set()
        Unsolv = set()
        for head in MultiBBS:
            if  0 == len(MultiBBS[head]):
                # a function which no direct caller. set x z random
                continue

            cur = GetBBLRid(head)
            bFindXZ = False
            for x in range(1, g_map_size+1):
                for z in range(0, g_map_size * 2):
                    tmpHashSet = set()
                    for pred_bbl in MultiBBS[head]:
                        pred = GetBBLRid(pred_bbl[0])
                        edgeHash = ((cur >> x) + (pred >> y) + z) & max_value
                        if edgeHash in tmpHashSet:
                            break
                        tmpHashSet.add(edgeHash)
                        #print('edgeHash=%x (%x >> %d) ^ (%x >> %d) + %x' % (edgeHash, cur, x, pred, y, z))

                    if len(tmpHashSet) == len(MultiBBS[head]) and tmpHashSet & Hashes == set():
                        Solv.add(head)
                        Params[head] = (x, z)
                        Hashes.update(tmpHashSet)
                        bFindXZ = True
                        break

                if bFindXZ:
                    break
            
            if not bFindXZ: 
                if  head in idautils.Functions(): # if head is function, skip collison. set x z random
                    print('%x function coll' % head)
                    Params[head] = (0, random.randint(0, g_map_size * 8))
                else:
                    print('%x' % head)
                    Unsolv.add(head)
                    #if len(Unsolv) >= 10 and float(len(Unsolv))/len(MultiBBS) >= 0.02:   # this y is failed, next
                        #break
            
        print('Solv=%d Unsolv=%d y=%d' % (len(Solv), len(Unsolv), y))
        if len(Unsolv) < 10 or float(len(Unsolv))/len(MultiBBS) < 0.02:              # success
            bOk = True
            break
        elif len(Solv) > count_solv_best:
            count_solv_best = len(Solv)
            count_unsolv_best = len(Unsolv)
            y_best = y
            Params_best = Params

    if bOk:
        Params.update(Params_Fun)
        return     y, Hashes, Params
    else:
        Params_best.update(Params_Fun)
        print('Result: Solv=%d Unsolv=%d y=%d' % (count_solv_best, count_unsolv_best, y_best))
        return     y_best, Hashes, Params_best
    return 0, set(), {}


def InstruFsingleAndSaveEdgeInfo(SingleBBS, Hashes, bbls, max, f):
    
    hash = max
    for k in SingleBBS:
        while hash >= 0: 
            if hash not in Hashes:
                Hashes.add(hash)
                FixFsingleZ(k, hash)
                f.write(("%d %d 0 0 %d %d %d\n") % ( SingleBBS[k][0], k, hash, bbls[k][2], bbls[k][3]))
                hash -= 1
                break
            hash -= 1

        if hash < 0:
            print('edges hash coll after fixed')
            break
    if hash >= 0:
        print('fixed hash coll success!')


def SaveMultiBBSEdgeInfo(MultiBBS, bbls, max, f):
    
    y = 0
    for func in idautils.Functions():
        if idc.GetFunctionName(func).find('afl_maybe_log') >= 0:
            y = GetY(func)
            break

    for k in MultiBBS:
        cur = GetBBLRid(k)
        x, z = GetXZ(k)
        for bbl in MultiBBS[k]: #[head, tail, call_num, mem_num]
            pre = GetBBLRid(bbl[0])
            # print(k, bbl[0], x, y, z, max)
            hash = ((cur >> x) ^ (pre >> y) + z) & max
            f.write(("%d %d 0 0 %d %d %d\n") % ( bbl[0], k, hash, bbls[k][2], bbls[k][3]))


def main():
    
    idaapi.msg("Loading CollAFL_Node_Extract\n")
    idb_path = idc.GetIdbPath()
    save_path = idb_path[:-4] + '_node_relation.txt'
    f = open(save_path, 'w')
    print(save_path)
    time_start = time.time()
        
    global g_map_size
        
    # bbl info [head, tail, call_num, mem_num]
    SingleBBS = {}  # head -> pred_bbl
    MultiBBS = {}   # head -> [pred_bbls]
    bbls = {}   # head -> bbl
    # bbls2 = {}  # tail -> bbl
    edges = {}  # dict struct.  head -> of (head, ..., head)    #set()   # set of (tail, head) or (head, head). only call function is (head, head)
    bbl_heads = []    # head of bbl

    max_value = int(math.pow(2, g_map_size))-1
    SetInstrumentParam()
    
    #HandleFunc(0x414E40)
    #return    

    #1: (BBS, SingleBBS, MultiBBS, Preds) = GetCFG()
    bbls, edges, edges_count, SingleBBS, MultiBBS = GetCFG()
    bbl_heads = list(bbls.keys())
    bbl_heads.sort()
    print(str(time.time() - time_start) + 's ' + 'GetCFG')  

    # all functions ->  MultiBBS
    for func in idautils.Functions():
        if IsSanFunc(func) or not IsInstrumentIns(func):
            continue        
        
        MultiBBS[func] = [] # all functions as Multi Preds BBL
        refs = idautils.CodeRefsTo(func, 0)
        for r in refs:
            head = tow_search(bbl_heads, r)
            if head > 0 and r >= bbls[head][0] and r <= bbls[head][1]:
                #edges.add((head, func))   # (head, head)                
                if head in edges:
                    edges[head].append(func)
                else:
                    edges[head] = [func]
                edges_count += 1
                MultiBBS[func].append(bbls[head])   # add Pred
    

    print('bbls=%d edges=%d SingleBBS=%d MultiBBS=%d' % (len(bbls), edges_count, len(SingleBBS), len(MultiBBS)))
    #for head in bbls:
    #    if head not in SingleBBS and head not in MultiBBS:
    #        print('%x' % head)
    print(str(time.time() - time_start) + 's ' + 'functions -> MultiBBS')  
        

    #2: Keys = AssignUniqRandomKeysToBBs(BBS)
    print('AssignUniqRandomKeysToBBs')  
    AssignUniqRandomKeysToBBs(bbls, MultiBBS, max_value)

    #3-4 Fixate algorithms. Preds and Keys are common arguments
    #3: (Hashes, Params, Solv, Unsolv) = CalcFmul(MultiBBS)
    # 0, set(), {}       # head -> (x, z)
    print('CalcFmul')  
    y, Hashes, Params = CalcFmul(MultiBBS, max_value);
    if 0 == len(Hashes) or 0 == len(Params):
        print('CalcFmul error!')
        return
    print(str(time.time() - time_start) + 's ' + 'CalcFmul')  

    #4: (HashMap, FreeHashes) = CalcFhash(Hashes, Unsolv)
    pass

    #5-7 Instrument program with coverage tracking.
    #5: InstrumentFmul(Solv, Params)
    # fix y
    print('InstrumentFmul')  
    for func in idautils.Functions():
        fun_name = idc.GetFunctionName(func)
        if fun_name.find('afl_maybe_log_fun') >= 0:
            FixFmulY(func, y, True)
        elif fun_name.find('afl_maybe_log') >= 0:
            FixFmulY(func, y, False)
    # fix x z
    for head in Params:
        FixFmulXZ(head, Params[head][0], Params[head][1])
    print(str(time.time() - time_start) + 's ' + 'fix fmul')  

    #6: InstrumentFhash(Unsolv, HashMap)
    pass

    #7: InstrumentFsingle(SingleBBS, FreeHashes)
    print('InstruFsingleAndSaveEdgeInfo')  
    InstruFsingleAndSaveEdgeInfo(SingleBBS, Hashes, bbls, max_value, f)
    print(str(time.time() - time_start) + 's ' + 'fix fsingle')  
    
    print('SaveMultiBBSEdgeInfo')  
    SaveMultiBBSEdgeInfo(MultiBBS, bbls, max_value, f)
    
    f.write('analyse time: ' + str(time.time() - time_start) + 's\n')
    f.close()
    print('analyse time: ' + str(time.time() - time_start) + 's\n')


if __name__ == "__main__":    
    main()


