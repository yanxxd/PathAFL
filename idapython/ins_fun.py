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
import json
import random


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
save_path = idb_path[:-4] + '_ins_fun'
print(save_path)


def main():

    idaapi.msg("alter instrument function\n")
    
    addr_afl_maybe_log_fun = 0
    addr_afl_maybe_log = 0
    fun_info = []

    try:
        for func in idautils.Functions():
            fun_name = idc.GetFunctionName(func)
            if fun_name.find('afl_maybe_log_fun') > 0:
                addr_afl_maybe_log_fun = func
            elif fun_name.find('afl_maybe_log') > 0:
                addr_afl_maybe_log = func
            if addr_afl_maybe_log_fun and addr_afl_maybe_log:
                break

        if not addr_afl_maybe_log_fun or not addr_afl_maybe_log:
            print("don't find add_afl_maybe_fun\n")
            return

        print("find add_afl_maybe_fun ok\n")

        # find instrumented function
        for func in idautils.Functions():

            f_end = idc.FindFuncEnd(func)
            
            if f_end - func <= 0x28:
                continue            
           
            # call    __afl_maybe_log
            if __EA64__: # 64bit
                addr_call = func + 0x1D
            else: # 32bit                
                addr_call = func + 0x15
 
            mnem = idc.GetMnem(addr_call)
            if mnem != 'call':
                continue
            
            for to in idautils.CodeRefsFrom(addr_call, False):
                fun_name = idc.GetFunctionName(to)
                if fun_name.find('afl_maybe_log') < 0:
                    continue
                fun_info.append((func, f_end-func, addr_call))
                
        fun_info.sort(key=lambda x:x[1])
        num = len(fun_info)
        for i in range(num-1, -1, -1):
            if fun_info[i][1] < 0x200 or i < num*90.0/100.0 and random.randint(0, 99) < 80: # remove fun instrumented #or i < num/3 
                idc.PatchDword(fun_info[i][2] + 1, addr_afl_maybe_log - fun_info[i][2] - 5)
            else:
                print(hex(fun_info[i][0]))

        
        #idc.SaveBase('')
        #idc.Exit(0)

    except Exception as e:
        print(e)
    
    print('analyse time: ' + str(time.time() - g_time_start) + 's\n')


def main_standalone():
	print("main_standalone")

if __name__ == "__main__":
    print(IDA_ENABLED)
    if IDA_ENABLED:
        main()
    else:
        main_standalone()


