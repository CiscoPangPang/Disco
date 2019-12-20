from idautils import *
from idaapi import *
from idc import *

# This code is written by @y0ny0ns0n
# As you can see, he is a terrible programmer
# His mouse always say LGTM

string_func_list = [
	"strchr", 
	"strblk", 
	"strerror", 
	"memchr", 
	"memcmp", 
	"memcpy", 
	"memmove", 
	"memset", 
	"strcat", 
	"strchr", 
	"strcmp", 
	"strcmpi", 
	"strcpy", 
	"strcspn", 
	"strerror", 
	"strftime", 
	"stricmp", 
	"strlen", 
	"strlwr", 
	"strncat", 
	"strncmp", 
	"strncmpi", 
	"strncpy", 
	"strnicmp", 
	"strpbrk", 
	"strrchr", 
	"strspn", 
	"strstr", 
	"strstri", 
	"strtod", 
	"strtok", 
	"strtol", 
	"strupr", 
	"memchr", 
	"memcmp", 
	"memcpy", 
	"memmove", 
	"strcat", 
	"strcmp", 
	"strcmpi", 
	"strcpy", 
	"strcspn", 
	"strftime", 
	"stricmp", 
	"strlen", 
	"strlwr", 
	"strncmp", 
	"strncmpi", 
	"strncpy", 
	"strnicmp", 
	"strpbrk", 
	"strrchr", 
	"strspn", 
	"strstr", 
	"strstri", 
	"strtod", 
	"strtok", 
	"strtol", 
	"strupr", 
	"strtab", 
	"strlcat", 
	"strlcpy", 
	"bzero", 
	"strcasecmp_s", 
	"strcasestr_s", 
	"strcat_s", 
	"strcmp_s", 
	"strcmpfld_s", 
	"strcpy_s", 
	"strcpyfld_s", 
	"strcpyfldin_s", 
	"strcpyfldout_s", 
	"strcspn_s", 
	"strfirstchar_s", 
	"strfirstdiff_s", 
	"strisalphanumeric_s", 
	"strisascii_s", 
	"strisdigit_s", 
	"strishex_s", 
	"strislowercase_s", 
	"strismixedcase_s", 
	"strispassword_s", 
	"strisuppercase_s", 
	"strlastchar_s", 
	"strlastdiff_s", 
	"strljustify_s", 
	"strncat_s", 
	"strncpy_s", 
	"strnlen_s", 
	"strpbrk_s", 
	"strprefix_s", 
	"strremovews_s", 
	"strspn_s", 
	"strstr_s", 
	"strtok_s", 
	"strtolowercase_s", 
	"strtouppercase_s", 
	"strzero_s", 
]

'''
There's a bug
[+] strncpy_wrapper
[+] 0x37305074
[+] strncpy
[+] 0x37309830

[+] strcpy_wrapper
[+] 0x37304c28
[+] strcpy
[+] 0x37309830

those two call same function, so strcpy renamed to strncpy
'''

def main():
    sc = Strings()
    IDA_BASE_ADDR = 0x30000000
    
    for s in sc:
    	tmp = str(s)
    
    	if tmp in string_func_list:
    		xref_addrs = list(DataRefsTo(s.ea))
    
    		if len(xref_addrs) == 0:
    			continue
    		elif len(xref_addrs) == 1:
    			addr = xref_addrs[0]
    			func_name = get_func_name(addr)
    			if len(func_name) == 0:
    				continue
    		elif len(xref_addrs) == 2:
    			addr1 = xref_addrs[0]
    			addr2 = xref_addrs[1]
    			func_name1 = get_func_name(addr1)
    			func_name2 = get_func_name(addr2)
    
    			if len(func_name1) == 0 and len(func_name2) == 0:
    				continue
    			elif len(func_name1) == 0:
    				func_name = func_name2
    			else:
    				func_name = func_name1
    		else:
    			continue
    
    		func_addr = get_name_ea_simple(func_name)
    		print "[+] " + tmp + "_wrapper"
    		print "[+] " + hex(func_addr).strip("L")
    		MakeNameEx(func_addr, tmp + "_wrapper", idc.SN_NOWARN)
    		dism_addrs = list(FuncItems(func_addr))
    
    		trigger = False
    		for dism_addr in dism_addrs[::-1]:
    			if trigger:
    				break
    
    			if GetMnem(dism_addr) == "jal" or GetMnem(dism_addr) == "j":
    				target_addr = GetOperandValue(dism_addr, 0)
    				print "[+] " + tmp
    				print "[+] " + hex(target_addr).strip("L")
    				MakeNameEx(target_addr, tmp, idc.SN_NOWARN)
    				trigger = True
    
    print "[+] the end"
    

if __name__ == "__main__":
	main()