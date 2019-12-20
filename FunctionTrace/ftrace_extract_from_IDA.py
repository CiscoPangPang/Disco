from idautils import *
from idaapi import *
from idc import *
from find_string_functions import string_func_list
import os
import time

# edit this path
output_filename = os.getenv("USERPROFILE") + "\\Disco-Private\\Ftrace\\ftrace_func_list.txt"
printf_ban_filename = os.getenv("USERPROFILE") + "\\Disco-Private\\Ftrace\\printf_ban.txt"

'''
writing format:
function_offset stack_size reg1 reg1's store_stack_size reg2 reg2's store_stack_size

# sw = 0
# lw = 1
'''

reg_list = [ '$zero', '$at', '$v0', '$v1', '$a0', '$a1', '$a2', '$a3',
            '$t0', '$t1', '$t2', '$t3', '$t4', '$t5', '$t6',
            '$t7', '$s0', '$s1', '$s2', '$s3', '$s4', '$s5',
            '$s6', '$s7', '$t8', '$t9', '$k0', '$k1', '$gp',
            '$sp', '$fp', '$ra']

func_list  = []
ban_list = []

IDA_OFFSET = 0x968

def ReturnFunc(addr):
	return GetMnem(addr) == "addiu"

def FuncJal(funclist, cnt):
    global func_list

    if cnt == 0:
        return

    jalist = []
    for func in funclist:
        if func != BADADDR:
            start = GetFunctionAttr(func, FUNCATTR_START)
            end = GetFunctionAttr(func, FUNCATTR_END)

            for i in range(start, end, 4):
                if GetMnem(i) == "jal":
                    tmp = LocByName(GetOpnd(i,0))
                    if tmp != BADADDR and ReturnFunc(tmp):
                        jalist.append(tmp)

    cnt -= 1

    func_list.extend(jalist)
    func_list = list(set(func_list))

    if jalist != []:
        FuncJal(jalist, cnt)
    else:
        return


def StrFuncXref(strings, name, depth=1):
    print "[+] Seed String is \"%s\"( Case Insensitive )" % name
    global func_list
    names = [s for s in strings if re.search(name,str(s)) is not None]

    for name in names:
        for ref in DataRefsTo(name.ea):
            start = GetFunctionAttr(ref, FUNCATTR_START)
            end = GetFunctionAttr(ref, FUNCATTR_END)

            if start != BADADDR and ReturnFunc(start):
                func_list.append(start)

    func_list = list(set(func_list))
    FuncJal(func_list, depth)
    func_list = list(set(func_list))


def gogo():
    cnt = 0
    f = open(output_filename, "w")
    stack_set = set()
    reg1_set = set()
    reg2_set = set()
    total_reg_set = set()
    func_offset_set = set() # need to erase duplication
    for func_addr in func_list:
        if GetMnem(func_addr) == "addiu" and GetOpnd(func_addr, 0) == "$sp":
            if GetMnem(func_addr+4) in ["sw", "lw"] and "($sp)" in GetOpnd(func_addr+4, 1):
                if GetMnem(func_addr+8) in ["sw", "lw"] and "($sp)" in GetOpnd(func_addr+8, 1):
                    func_offset = func_addr - get_imagebase()

                    if func_offset in func_offset_set:
                        print "[!] %08x alread in list! pass it!" % func_addr
                        continue

                    if func_offset in ban_list:
                        print "[!] %08x in ban list!" % func_addr
                        continue

                    stack_size = 0x10000 - int(GetManyBytes(func_addr+2, 2).encode('hex'), 16)

                    # $t0~$t7 are actively used in code_cave, i can't perfectly restore it's value... so i filter it
                    if GetMnem(func_addr+4) == "sw" and (GetOpnd(func_addr+4, 0).startswith("$t") or GetOpnd(func_addr+4, 0) == "$sp"):
                        print "[!] sorry, I can't restore sw(=store word) instrunction at 0x%08x" % (func_addr + 4)
                        continue

                    if GetMnem(func_addr+8) == "sw" and (GetOpnd(func_addr+8, 0).startswith("$t") or GetOpnd(func_addr+8, 0) == "$sp"):
                        print "[!] sorry, I can't restore sw(=store word) instrunction at 0x%08x" % (func_addr + 8)
                        continue

                    # those registers are used in ftrace
                    if GetMnem(func_addr+4) == "lw" and GetOpnd(func_addr+4, 0) in ["$t7", "$t2", "$t3", "$t4", "$t6", "$sp"]:
                        print "[!] sorry, I can't restore lw(=load word) instrunction at 0x%08x" % (func_addr + 4)
                        continue

                    if GetMnem(func_addr+8) == "lw" and GetOpnd(func_addr+8, 0) in ["$t7", "$t2", "$t3", "$t4", "$t6", "$sp"]:
                        print "[!] sorry, I can't restore lw(=load word) instrunction at 0x%08x" % (func_addr + 8)
                        continue

                    # some of string functions are used in GDP RSP you can get stuck if you write that area
                    func_name = GetFunctionName(func_addr)
                    if func_name in string_func_list or func_name.strip("_wrapper") in string_func_list:
                        print "[!] sorry, I am too scared to patch %s()..." % func_name
                        continue

                    if func_addr <= (get_imagebase() + IDA_OFFSET):
                        print "[+] I think you are kernel-land function"
                        continue
                    
                    reg1 = GetOpnd(func_addr+4, 0)
                    if reg1 not in reg_list:
                        print "[!] reg %s not in list" % reg1
                        continue

                    reg1_offset = int(GetManyBytes(func_addr+4+2, 2).encode('hex'), 16)

                    reg2 = GetOpnd(func_addr+8, 0)
                    if reg2 not in reg_list:
                        print "[!] reg %s not in list" % reg2
                        continue

                    reg2_offset = int(GetManyBytes(func_addr+8+2, 2).encode('hex'), 16)

                    if GetMnem(func_addr+4) == "lw":
                        reg1_offset |= 1
                    
                    if GetMnem(func_addr+8) == "lw":
                        reg2_offset |= 1
                    
                    f.write("%08x %04x %02x %04x %02x %04x\n" % (func_offset, stack_size, reg_list.index(reg1), reg1_offset, reg_list.index(reg2), reg2_offset))

                    stack_set.add(stack_size)
                    reg1_set.add(reg1_offset)
                    reg2_set.add(reg2_offset)
                    total_reg_set.add(reg1_offset)
                    total_reg_set.add(reg2_offset)
                    func_offset_set.add(func_offset)
                    cnt += 1
    
    print "[+] Totally %d functions extracted" % cnt
    print "[+] stack size diversity = %d" % len(stack_set)
    print "[+] register 1 offset diversity = %d" % len(reg1_set)
    print "[+] register 2 offset diversity = %d" % len(reg2_set)
    print "[+] total register offset diversity = %d" % len(total_reg_set)
    f.close()

print "\n" * 10
print "-" * 80
print "[+] IDA_OFFSET = 0x%x" % IDA_OFFSET
startTime = time.time()
with open(printf_ban_filename, "r") as f:
    ban_list = [int(x, 16) for x in f.read().split("\n") if x != '']

# method 1 - extract every candidate functions in idb
# func_list.extend(list(Functions()))

# method 2 - extract specific string related functions with depth
StrFuncXref(Strings(), "snmp", 1)

gogo()
print "[+] Elapsed Time: %.3f seconds" % (time.time() - startTime)
print "-" * 80