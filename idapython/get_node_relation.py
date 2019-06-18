#!/usr/bin/env python
# coding: utf-8

import ptvsd

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

IDA_ENABLED = False
try:
    import idc
    import idaapi
    import idautils
    from idaapi import PluginForm, plugin_t
    IDA_ENABLED = True
except ImportError as e:
    class PluginForm:
        def __init__(self):
            pass
    class plugin_t:
        def __init__(self):
            pass
    class idaapi:
        PLUGIN_UNL=None
        PLUGIN_OK=None
        def __init__(self):
            pass
    print(e.message)
    IDA_ENABLED = False


g_time_start = time.time()
idb_path = idc.GetIdbPath()
save_path = idb_path.split('.')[0] + '_node_relation.txt'
g_f = open(save_path, 'w')
print(save_path)


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

g_ins_1 = 0xFFFFFF6824A48D48  # ins of AFL
g_ins_2 = 0x244C894824148948  # ins of AFL


def Find__afl_maybe_log(start, end):
    '''
.text:0804F2A0 8D 64 24 F0       lea     esp, [esp-10h]
.text:0804F2A4 89 3C 24          mov     [esp+10h+var_10], edi
.text:0804F2A7 89 54 24 04       mov     [esp+10h+var_C], edx
.text:0804F2AB 89 4C 24 08       mov     [esp+10h+var_8], ecx
.text:0804F2AF 89 44 24 0C       mov     [esp+10h+var_4], eax
.text:0804F2B3 B9 96 74 00 00    mov     ecx, 7496h
.text:0804F2B8 E8 0B 77 0B 00    call    __afl_maybe_log
.text:0804F2BD 8B 44 24 0C       mov     eax, [esp+10h+var_4]
.text:0804F2C1 8B 4C 24 08       mov     ecx, [esp+10h+var_8]
.text:0804F2C5 8B 54 24 04       mov     edx, [esp+10h+var_C]
.text:0804F2C9 8B 3C 24          mov     edi, [esp+10h+var_10]
.text:0804F2CC 8D 64 24 10       lea     esp, [esp+10h]
    '''
    #print('Find__afl_maybe_log')
    for addr in xrange(start, end-16):
        if g_ins_1 == idc.Qword(addr) and g_ins_2 == idc.Qword(addr+8):
            print(idc.GetFunctionName(start))
            print(hex(addr), idc.GetDisasm(addr))
            break
    return


def get_fun_bbls(self, function_ea):
    """
    Get bbls of function.
    @function_ea - function address
    @return - bbs of function
    """
    f_start = function_ea
    f_end = idc.FindFuncEnd(function_ea)

    boundaries = set((f_start,))
    fun_metrics = dict()
    
    for head in idautils.Heads(f_start, f_end):
        # If the element is an instruction
        if head == ida_idaapi.BADADDR:
            raise Exception("Invalid head for parsing")
        if isCode(idc.GetFlags(head)):

            # Get the references made from the current instruction
            # and keep only the ones local to the function.
            refs = idautils.CodeRefsFrom(head, 0)
            refs_filtered = set()
            for ref in refs:
                if ref == ida_idaapi.BADADDR:
                    print "Invalid reference for head", head
                    raise Exception("Invalid reference for head")

                if ref >= f_start and ref < f_end:
                    refs_filtered.add(ref)
            refs = refs_filtered

            if refs:
                # If the flow continues also to the next (address-wise)
                # instruction, we add a reference to it.
                # For instance, a conditional jump will not branch
                # if the condition is not met, so we save that
                # reference as well.
                next_head = idc.NextHead(head, f_end)
                if next_head == ida_idaapi.BADADDR:
                    print "Invalid next head after ", head
                    raise Exception("Invalid next head")
                if isFlow(idc.GetFlags(next_head)):
                    refs.add(next_head)

                # Update the boundaries found so far.
                boundaries.update(refs)

    #end of for head in idautils.Heads(chunk[0], chunk[1]):
        
    bbls = []
    bbl = [] # a list of heads
    # NOTE: We can handle if jump xrefs to chunk address space.

    for head in idautils.Heads(f_start, f_end):
        if head in boundaries:
            #print('%x') % head
            if len(bbl) > 0:
                if bbl[0] == head:
                    continue
                bbl.append(head)
                bbls.append(bbl)
                bbl = []
            bbl.append(head)
        elif self.GetInstructionType(head) == self.BRANCH_INSTRUCTION:
            if len(bbl) > 0 and bbl[0] == head + idc.ItemSize(head):
                continue
            bbl.append(head + idc.ItemSize(head))
            bbls.append(bbl)
            bbl = []
            bbl.append(head + idc.ItemSize(head))
        else:
            pass
    # add last basic block
    if len(bbl) and bbl[0] != chunk[1]:
        bbl.append(chunk[1])
        bbls.append(bbl)
    return bbls

    #i = 0
    #for bbl in bbls:
    #    print('%02d %x %x') % (i+1, bbl[0], bbl[1])
    #    i += 1
    #i = 1


def CountEdgeInBranch(func, parent, cur, stack):
    '''
    Calculate the total number of edges under branches
    @func       function address
    @parent     parent node address
    @cur        the address to start the search. This vuale is typically the starting address of BBL.
    @stack      stack of search address, avoid recusion loops
    '''
    global g_num_edge
    global g_off_set_random
    global g_size_ins_block
    global g_ins_1
    global g_ins_2

    # current pos must in func
    end = idc.GetFunctionAttr(func, idc.FUNCATTR_END)
    if cur < func:
        return

    # avoid recusion loops.
    if cur in stack:
        return
    stack.append(cur)

    ea = cur
    while ea < end and BADADDR != ea: #idaapi.BADADDR
        #print(hex(ea), idc.GetDisasm(ea))
        flag = idc.GetFlags(ea)
        if idc.isData(flag):
            ea += idc.ItemSize(ea)
            continue

        if not idc.isCode(flag):
            ea += 1
            continue

        # code
        # found a child node, stop
        if ea < end - g_size_ins_block and g_ins_1 == idc.Qword(ea) and g_ins_2 == idc.Qword(ea+8):
            g_num_edge += 1
            return

        asm = idc.GetDisasm(ea)
        if 0 == len(asm):
            ea += 1
            continue
                
        elif asm[:3] == 'ret':
            return

        # jmp jz jnz ja ......
        elif 'j' == asm[0]: # and 'm' != idc.GetDisasm(ea)[1]:
            
            for xref in idautils.XrefsFrom(ea): # idautils.ida_xref.XREF_ALL)
                if xref.type == 18 or xref.type == 19: # 18 :'Code_Far_Jump', 19 : 'Code_Near_Jump',   please see XrefTypeName                    
                    CountEdgeInBranch(func, parent, xref.to, stack)

                elif xref.type == 20: # 20 : 'Code_User'
                    print('******************************************')
                    print('Code_User', hex(parent), hex(ea), idc.GetDisasm(ea))

                elif xref.type == 21: # 21 : 'Ordinary_Flow'
                    CountEdgeInBranch(func, parent, xref.to, stack)
            
            return
        
        else:
            ea += idc.ItemSize(ea)

    return


def FindChildNode(func, parent, cur, stack, num_call):
    '''
    Find 1st layer child.
    @func       function address
    @parent     parent node address
    @cur        the address to start the search. This vuale is typically the starting address of BBL.
    @stack      stack of search address, avoid recusion loops
    @num_call   indicates how many call is contained in one edge.
    '''
    global g_f
    global g_off_set_random
    global g_size_ins_block
    global g_ins_1
    global g_ins_2
    global g_off_random

    num_mem = 0
    write_head = 0

    # current pos must in func
    end = idc.GetFunctionAttr(func, idc.FUNCATTR_END)
    if cur < func:
        return

    # avoid recusion loops
    if cur in stack:
        return
    stack.append(cur)

    ea = cur
    while ea < end and BADADDR != ea: #idaapi.BADADDR
        #print(hex(ea), idc.GetDisasm(ea))
        flag = idc.GetFlags(ea)
        if idc.isData(flag):
            ea += idc.ItemSize(ea)
            continue

        if not idc.isCode(flag):
            ea += 1
            continue

        # code
        # found a child node, stop
        if ea < end - g_size_ins_block and g_ins_1 == idc.Qword(ea) and g_ins_2 == idc.Qword(ea+8):
            parent_id = idc.Dword(parent+g_off_random) #(int)(idc.GetOpnd(parent, 1).strip('h'), 16)
            child_id = idc.Dword(ea+g_off_set_random+g_off_random) #(int)(idc.GetOpnd(ea+0x13, 1).strip('h'), 16)
            #if len(g_dict_func_edge):
            if 1 == write_head:
                g_f.write(("%d %d\n") % ( num_call, num_mem ))
                return

            if parent != ea+g_off_set_random:
                #g_f.write(("%x %x %x %x %d %d %d\n") % ( parent, ea+0x13, parent_id, child_id, (parent_id >> 1) ^ child_id, num_call, num_mem ))
                g_f.write(("%d %d %d %d %d ") % ( parent, ea+g_off_set_random, parent_id, child_id, (parent_id >> 1) ^ child_id))
                write_head = 1
            #return

        mnem = idc.GetMnem(ea) #asm = idc.GetDisasm(ea)
        if 0 == len(mnem):
            ea += 1
            continue
                
        elif mnem[:3] == 'ret': #asm[:3] == 'ret':
            if write_head:
                g_f.write(("%d %d\n") % ( num_call, num_mem ))
            return

        # jmp jz jnz ja ......
        elif 'j' == mnem[0]: # and 'm' != idc.GetDisasm(ea)[1]:
            
            if write_head:
                g_f.write(("%d %d\n") % ( num_call, num_mem ))
                return

            num_call = 0 #

            for xref in idautils.XrefsFrom(ea): # idautils.ida_xref.XREF_ALL)
                if xref.type == 18 or xref.type == 19: # 18 :'Code_Far_Jump', 19 : 'Code_Near_Jump',   please see XrefTypeName                    
                    FindChildNode(func, parent, xref.to, stack, num_call)

                elif xref.type == 20: # 20 : 'Code_User'
                    print('******************************************')
                    print('Code_User', hex(parent), hex(ea), idc.GetDisasm(ea))

                elif xref.type == 21: # 21 : 'Ordinary_Flow'
                    FindChildNode(func, parent, xref.to, stack, num_call)
            
            return

        # call.  count call ins.
        elif mnem == 'call': #asm.startswith('call'):
            to = 0
            for to in idautils.CodeRefsFrom(ea, False):                
                fun_name = idc.GetFunctionName(to)
                if fun_name.find('alloc') >= 0 or fun_name.find('free') >= 0 or fun_name.find('create') >= 0 or fun_name.find('delete') >= 0:
                    num_mem += 1
                break
             # only count instrumented function
            if idc.SegName(ea) == idc.SegName(to):
                if g_ins_1 == idc.Qword(to) and g_ins_2 == idc.Qword(to+8):
                    #if len(g_dict_func_edge):
                    #    num_call += g_dict_func_edge[to]
                    #else:
                    num_call += 1
            ea += idc.ItemSize(ea)
            continue

        else:
            ea += idc.ItemSize(ea)
            #ea += idc.DecodeInstruction(ea)
            #ea = idc.NextNotTail(ea)

    
    if write_head:
        g_f.write(("%d %d\n") % ( num_call, num_mem ))

    return


def HandleFunc(func):
    
    global g_off_set_random
    global g_size_ins_block
    global g_ins_1
    global g_ins_2

    #for ins in idautils.FuncItems(start):
    #    print(idc.GetDisasm(ins))    

    ea = func
    end = idc.GetFunctionAttr(func, idc.FUNCATTR_END)
    while ea <= end-g_size_ins_block:
        if g_ins_1 == idc.Qword(ea) and g_ins_2 == idc.Qword(ea+8): #  idc.FindBinary()
            #print(idc.GetFunctionName(start))
            #print(hex(ea), idc.GetDisasm(addr))
            #idc.SetColor(ea+0x13, CIC_ITEM, 0x0000FF)
            call_stack = []
            FindChildNode(func, ea+g_off_set_random, ea+g_size_ins_block, call_stack, 0)
            ea += g_size_ins_block
        else:
            ea += 1
    pass
    

def HandleFunc_GetInOut(func):

    count = 0
    ea = func
    end = idc.GetFunctionAttr(func, idc.FUNCATTR_END)
    while ea < end and BADADDR != ea:
        mnem = idc.GetMnem(ea)
        if 0 == len(mnem):
            ea += 1
            continue
                
        elif mnem[:3] == 'ret': #asm[:3] == 'ret':
            count += 1
            if count >= 2:
                print(hex(func))
                return

        ea += idc.ItemSize(ea)

               

def main():
    idaapi.msg("Loading AFL_Node_Extract\n")
    
    global g_num_edge
    global g_dict_func_edge
    global g_off_set_random
    global g_size_ins_block
    global g_ins_1
    global g_ins_2
    global g_off_random

    dict_func_edge = {}

    if __EA64__: # 64bit
        g_off_set_random = 0x16
        g_size_ins_block = 0x38
        g_ins_1 = 0xFFFFFF6824A48D48
        g_ins_2 = 0x244C894824148948
        g_off_random = 3
    else: # 32bit
        print('g_off_set_random g_size_ins_block g_ins_1 g_ins_2 need right value in 32bit')
        g_off_set_random = 0x10
        g_size_ins_block = 0x2A
        g_ins_1 = 0xFFFFFF6824A48D48
        g_ins_2 = 0x244C894824148948
        g_off_random = 1

    #func = 0x80E3440
    #print('%d %d') % (func, idc.GetFunctionAttr(func, idc.FUNCATTR_END))
    #HandleFunc(func)

    #for func in idautils.Functions():
    #    g_num_edge = 0
    #    HandleFunc(func)
    #    dict_func_edge[func] = g_num_edge

    g_dict_func_edge = dict_func_edge
    for func in idautils.Functions():
        HandleFunc(func)

    try:
        #for func in idautils.Functions():
        #    Find__afl_maybe_log(func, idc.GetFunctionAttr(func, idc.FUNCATTR_END)) #print hex(func), idc.GetFunctionName(func)
            
        #func = 0x804F2A0
        #print('%d %d') % (func, idc.GetFunctionAttr(func, idc.FUNCATTR_END))
        #HandleFunc(func)
        pass
    except Exception:
        pass



def main_standalone():
	print("main_standalone")

if __name__ == "__main__":
    print(IDA_ENABLED)
    if IDA_ENABLED:
        main()
    else:
        main_standalone()

    g_f.write('analyse time: ' + str(time.time() - g_time_start) + 's\n')
    g_f.close()
    print('analyse time: ' + str(time.time() - g_time_start) + 's\n')

