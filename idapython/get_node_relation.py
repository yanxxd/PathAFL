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

import idc
import idaapi
import idautils
from idaapi import PluginForm, plugin_t


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


def IsInstrumentIns(ea):
    '''
    is ea instrument instruction?
    '''
    if idc.__EA64__: # 64bit
        '''
.text:00000000005AC870 48 8D A4 24 68 FF FF FF lea     rsp, [rsp-98h]
.text:00000000005AC878 48 89 14 24             mov     [rsp+48h+var_48], rdx
.text:00000000005AC87C 48 89 4C 24 08          mov     [rsp+48h+var_40], rcx
.text:00000000005AC881 48 89 44 24 10          mov     [rsp+48h+var_38], rax
.text:00000000005AC886 48 C7 C1 6C 1A 00 00    mov     rcx, 1A6Ch
.text:00000000005AC88D E8 DE 0E 00 00          call    __afl_maybe_log_10
.text:00000000005AC892 48 8B 44 24 10          mov     rax, [rsp+48h+var_38]
.text:00000000005AC897 48 8B 4C 24 08          mov     rcx, [rsp+48h+var_40]
.text:00000000005AC89C 48 8B 14 24             mov     rdx, [rsp+48h+var_48]
.text:00000000005AC8A0 48 8D A4 24 98 00 00 00 lea     rsp, [rsp+98h]
        '''
        if 0xFFFFFF6824A48D48 == idc.Qword(ea) and 0x244C894824148948 == idc.Qword(ea+8):
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


def GetFunBbls(function_ea):
    """
    Get bbls of function.
    @function_ea - function address
    @return - bbls of function
    """
    f_start = function_ea
    f_end = idc.FindFuncEnd(function_ea)

    boundaries = set((f_start,))
    
    for head in idautils.Heads(f_start, f_end):
        # If the element is an instruction
        if head == idaapi.BADADDR:
            raise Exception("Invalid head for parsing")
        if idc.isCode(idc.GetFlags(head)):

            # Get the references made from the current instruction
            # and keep only the ones local to the function.
            refs = idautils.CodeRefsFrom(head, 0)
            refs_filtered = set()
            for ref in refs:
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
                if next_head != idaapi.BADADDR and idc.isFlow(idc.GetFlags(next_head)):
                    refs.add(next_head)
                
                # Update the boundaries found so far.
                boundaries.update(refs)

    #end of for head in idautils.Heads(chunk[0], chunk[1]):
        
    bbls = []
    bbl = [] # a list of heads
    # NOTE: We can handle if jump xrefs to chunk address space.

    for head in idautils.Heads(f_start, f_end):
        if head in boundaries:
            #print('%d') % head
            if len(bbl) > 0:
                if bbl[0] == head:
                    continue
                bbl.append(head)
                bbls.append(bbl)
                bbl = []
            bbl.append(head)
        #elif self.GetInstructionType(head) == self.BRANCH_INSTRUCTION:
        elif idc.GetMnem(head).startswith('j'):
            if len(bbl) > 0 and bbl[0] == head + idc.ItemSize(head):
                continue
            bbl.append(head + idc.ItemSize(head))
            bbls.append(bbl)
            bbl = []
            bbl.append(head + idc.ItemSize(head))
        else:
            pass
    # add last basic block
    if len(bbl) and bbl[0] != f_end:
        bbl.append(f_end)
        bbls.append(bbl)
        
    return bbls


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

    # current pos must in func
    end = idc.GetFunctionAttr(func, idc.FUNCATTR_END)
    if cur < func:
        return

    # avoid recusion loops.
    if cur in stack:
        return
    stack.append(cur)

    ea = cur
    while ea < end and idaapi.BADADDR != ea: #idaapi.BADADDR
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
        if ea < end - g_size_ins_block and IsInstrumentIns(ea):
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
    Recusion when encounter jump instruction. Stop when found a child node.
    @func       function address
    @parent     parent node address
    @cur        the address to start the search. This vuale is typically the starting address of BBL.
    @stack      stack of search address, avoid recusion loops
    @num_call   indicates how many call is contained in one edge.
    @write_head 
    '''
    global g_f
    global g_off_set_random
    global g_size_ins_block
    global g_off_random

    num_call = 0 # don't count call in head bbl
    num_mem = 0  # don't count call mem function in head bbl
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
    while ea < end and idaapi.BADADDR != ea: #idaapi.BADADDR
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
        if ea < end - g_size_ins_block and IsInstrumentIns(ea):
            parent_id = idc.Dword(parent+g_off_random) #(int)(idc.GetOpnd(parent, 1).strip('h'), 16)
            child_id = idc.Dword(ea+g_off_set_random+g_off_random) #(int)(idc.GetOpnd(ea+0x13, 1).strip('h'), 16)
            #if len(g_dict_func_edge):
            if 1 == write_head: # found a child node, stop
                g_f.write(("%d %d\n") % ( num_call, num_mem ))
                return

            if parent != ea+g_off_set_random:
                #g_f.write(("%d %d %d %d %d %d %d\n") % ( parent, ea+0x13, parent_id, child_id, (parent_id >> 1) ^ child_id, num_call, num_mem ))
                g_f.write(("%d %d %d %d %d ") % ( parent, ea+g_off_set_random, parent_id, child_id, (parent_id >> 1) ^ child_id))
                write_head = 1
            #return # found a child node, stop

        mnem = idc.GetMnem(ea) #asm = idc.GetDisasm(ea)
        if 0 == len(mnem):
            ea += 1
            continue
                
        elif mnem[:3] == 'ret': #asm[:3] == 'ret':
            if write_head: # found a child node, stop
                g_f.write(("%d %d\n") % ( num_call, num_mem ))
            return

        # jmp jz jnz ja ......
        elif 'j' == mnem[0]: # and 'm' != mnem[1]:   jmp dst addr has been instumented.
            
            if write_head: # found a child node, stop
                g_f.write(("%d %d\n") % ( num_call, num_mem ))
                return 

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
                if IsInstrumentIns(to):
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
    
    if write_head: # found a child node, stop
        g_f.write(("%d %d\n") % ( num_call, num_mem ))

    return


def FindChildNode2(func, bbl_heads, parent, cur, stack, num_call, write_head):
    '''
    Handle function which was instrumented by ratio.
    Find 1st layer instrumented child.
    Recusion when encounter jump instruction. Stop when found a child node.
    @func       function address
    @bbl_heads  all bbl heads of function.
    @parent     parent node address
    @cur        the address to start the search. This vuale is typically the starting address of BBL.
    @stack      stack of search address, avoid recusion loops
    @num_call   indicates how many call is contained in one edge.
    @write_head list
    '''
    global g_f
    global g_off_set_random
    global g_size_ins_block
    global g_off_random

    # num_call = 0 # don't count call in parent bbl
    num_mem = 0  # don't count call mem function in parent bbl

    # current pos must in func
    end = idc.GetFunctionAttr(func, idc.FUNCATTR_END)
    if cur < func:
        return

    # avoid recusion loops
    if cur in stack:
        return
    stack.append(cur)

    ea = cur
    while ea < end and idaapi.BADADDR != ea: #idaapi.BADADDR
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
        if ea < end - g_size_ins_block and IsInstrumentIns(ea):
            parent_id = idc.Dword(parent+g_off_random) #(int)(idc.GetOpnd(parent, 1).strip('h'), 16)
            child_id = idc.Dword(ea+g_off_set_random+g_off_random) #(int)(idc.GetOpnd(ea+0x13, 1).strip('h'), 16)
            #if len(g_dict_func_edge):
            if 1 == write_head[0]: # found a child node, stop
                g_f.write(("%d %d\n") % ( num_call, num_mem ))
                write_head[0] = 0
                return

            if parent != ea+g_off_set_random:
                #g_f.write(("%d %d %d %d %d %d %d\n") % ( parent, ea+0x13, parent_id, child_id, (parent_id >> 1) ^ child_id, num_call, num_mem ))
                g_f.write(("%d %d %d %d %d ") % ( parent, ea+g_off_set_random, parent_id, child_id, (parent_id >> 1) ^ child_id))
                write_head[0] = 1
            #return

        if ea in bbl_heads:
            pass

        mnem = idc.GetMnem(ea) #asm = idc.GetDisasm(ea)
        if mnem[:3] == 'ret': #asm[:3] == 'ret':
            if write_head[0]: # found a child node, stop
                g_f.write(("%d %d\n") % ( num_call, num_mem ))
                write_head[0] = 0
            return

        # jmp jz jnz ja ......
        elif 'j' == mnem[0]: # and 'm' != mnem[1]:   jmp dst addr has been instumented.
            
            if write_head[0]: # found a child node, stop
                g_f.write(("%d %d\n") % ( num_call, num_mem ))
                write_head[0] = 0
                return

            for xref in idautils.XrefsFrom(ea): # idautils.ida_xref.XREF_ALL)
                if xref.type == 18 or xref.type == 19: # 18 :'Code_Far_Jump', 19 : 'Code_Near_Jump',   please see XrefTypeName                    
                    FindChildNode2(func, bbl_heads, parent, xref.to, stack, num_call, write_head)

                elif xref.type == 20: # 20 : 'Code_User'
                    print('******************************************')
                    print('Code_User', hex(parent), hex(ea), idc.GetDisasm(ea))

                elif xref.type == 21: # 21 : 'Ordinary_Flow'
                    FindChildNode2(func, bbl_heads, parent, xref.to, stack, num_call, write_head)
            
            return

        # call.  count call ins.
        elif mnem == 'call': #asm.startswith('call'):
            to = 0
            for to in idautils.CodeRefsFrom(ea, False):                
                fun_name = idc.GetFunctionName(to).lower()
                if IsSanFunc(fun_name):
                    continue
                if fun_name.find('alloc') >= 0 or fun_name.find('free') >= 0 \
                    or fun_name.find('create') >= 0 or fun_name.find('delete') >= 0 \
                    or fun_name.find('destroy') >= 0:
                    num_mem += 1
                break
             # only count instrumented function
            if idc.SegName(ea) == idc.SegName(to):
                if not IsSanFunc(fun_name) and IsInstrumentIns(to):
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
    
    if write_head[0]:
        g_f.write(("%d %d\n") % ( num_call, num_mem ))
        write_head[0] = 0

    return


def HandleFunc(func):
    
    global g_off_set_random
    global g_size_ins_block

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
    

def HandleFunc_GetInOut(func):

    count = 0
    ea = func
    end = idc.GetFunctionAttr(func, idc.FUNCATTR_END)
    while ea < end and idaapi.BADADDR != ea:
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
    global g_off_random

    dict_func_edge = {}

    if idc.__EA64__: # 64bit
        g_off_set_random = 0x16
        g_size_ins_block = 0x38
        g_off_random = 3
    else: # 32bit
        g_off_set_random = 3
        g_size_ins_block = 0x10
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
        if IsSanFunc(func):
            continue
        print('%d %s') % (func, idc.GetFunctionName(func))
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

    g_f.write('analyse time: ' + str(time.time() - g_time_start) + 's\n')
    g_f.close()
    print('analyse time: ' + str(time.time() - g_time_start) + 's\n')


if __name__ == "__main__":    
    main()


