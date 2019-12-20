from idautils import *
from idaapi import *
from idc import *
from find_string_functions import string_func_list
import os
import time

# edit this path
output_filename = os.getenv("USERPROFILE") + "\\Disco-Private\\Ftrace\\printf_ban.txt"

func_list  = []

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
                    if tmp != BADADDR:
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

            if start != BADADDR:
                func_list.append(start)

    func_list = list(set(func_list))
    FuncJal(func_list, depth)
    func_list = list(set(func_list))


def gogo():
    cnt = 0
    f = open(output_filename, "w")

    for func_addr in func_list:
        func_offset = func_addr - get_imagebase()
        f.write("%08x\n" % (func_offset))
        cnt += 1
    
    print "[+] Totally %d functions extracted" % cnt
    f.close()

print "\n" * 10
print "-" * 80
startTime = time.time()

StrFuncXref(Strings(), "printf", 7)

gogo()
print "[+] Elapsed Time: %.3f seconds" % (time.time() - startTime)
print "-" * 80