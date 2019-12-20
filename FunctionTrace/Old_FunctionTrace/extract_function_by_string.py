from idaapi import *
from idautils import *
import re
import os

function_list = []

def ReturnFunc(addr):
	return GetMnem(addr) == "addiu"

def FuncJal(funclist, cnt):
	global function_list

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

	function_list.extend(jalist)
	function_list = list(set(function_list))

	if jalist != []:
		FuncJal(jalist, cnt)
	else:
		return


def StrFuncXref(strings, name, depth=1):
	global function_list
	names = [s for s in strings if re.search(name,str(s)) is not None]

	for name in names:
		for ref in DataRefsTo(name.ea):
			start = GetFunctionAttr(ref, FUNCATTR_START)
			end = GetFunctionAttr(ref, FUNCATTR_END)

			if start != BADADDR and ReturnFunc(start):
				function_list.append(start)

	function_list = list(set(function_list))
	FuncJal(function_list,depth)


def SaveResult(base, proto):
	global function_list
	f = open(os.getenv("USERPROFILE") + "\\Downloads\\"+proto+"_C2900_Result.txt","a")

	for addr in function_list:
		f.write("%08x\n" % (addr-base))

	f.close()

if __name__ == '__main__':
	initString = Strings()
	protocol = "snmp"
	StrFuncXref(initString, protocol, 1)
	function_list = list(set(function_list)) # remove dup
	SaveResult(0x30000000, protocol)

	print "[*] "+str(len(function_list))+" functions found"
