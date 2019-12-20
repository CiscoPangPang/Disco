# -*- encoding: utf-8 -*-
import argparse
import serial
import time
import os
from struct import pack, unpack
from keystone import *

'''
1. get printf()'s address and beginning of the null padding in main:text from user input
2. get dynamic base address from Cisco IOS via Serial port
3. calculate address of printf() and nop padding
4. read function offset list from file
5. connect to Cisco IOS as Debug Mode( using "gdb kernel" or "boot -vn 'IOS path'" on ROMMON mode )
....
'''

DEBUG = True
printf_addr = 0
noppad_addr = 0
noppad_size = 0
code_cave_text = 0
code_cave_data = 0
enable_password = "cisco"

COM_PORT = "COM3"
ser = ''

IDA_BASE_ADDR = 0x4000f000
# c2900-universalk9-mz.SPA.153-3.M9.bin  = offset 0x968
# c2900-universalk9-mz.SPA.157-3.M4b.bin = offset 0x8f8
IDA_OFFSET = 0x8d0
IDA_PC = 0x40072B94

func_offset_file = "ftrace_func_list_2811.txt"

base_addr = 0
main_text_len = 0

offset_list = []
reg_stack_offset_list = []
fmt_str = "[DEBUG] sub_%08x() called\n"

offset_list_addr = 0
reg_stack_offset_list_addr = 0
fmt_str_addr = 0
reg_store_addr = 0

restore_lw_addr = 0
restore_sw_addr = 0

stack_size_list = []
func_dict = dict()

ks = Ks(KS_ARCH_MIPS, KS_MODE_BIG_ENDIAN | KS_MODE_MIPS32)
mips_asm = lambda x : "".join("%02x" % v for v in ks.asm(x)[0])

code_cave = ""

reg_map =   {1: 'at', 2: 'v0', 3: 'v1', 4:'a0', 
            5:'a1', 6: 'a2', 7: 'a3', 8: 't0', 
            9: 't1', 10: 't2', 11: 't3', 12: 't4', 
            13: 't5', 14: 't6', 15: 't7', 16: 's0', 
            17: 's1', 18: 's2', 19: 's3', 20: 's4',
            21: 's5', 22: 's6', 23: 's7', 24: 't8', 
            25: 't9', 26: 'k0', 27: 'k1', 28: 'gp', 
            29:'sp', 30: 's8', 31:'ra', 37:'pc'}

reg_map_rev = {}

for k, v in reg_map.iteritems():
    reg_map_rev[v] = k

pusha = mips_asm("""
lui $t2, 0x1337
addiu $t2, $t2, 0x1337
""").replace("1337", "%04x")

popa = mips_asm("""
lui $t2, 0x1337
addiu $t2, $t2, 0x1337
""").replace("1337", "%04x")

pusha += mips_asm("""
sw $at, 0x0($t2)
sw $v0, 0x4($t2)
sw $v1, 0x8($t2)
sw $a0, 0xc($t2)
sw $a1, 0x10($t2)
sw $a2, 0x14($t2)
sw $a3, 0x18($t2)
sw $t0, 0x1c($t2)
sw $t1, 0x20($t2)
sw $t3, 0x28($t2)
sw $t4, 0x2c($t2)
sw $t5, 0x30($t2)
sw $t6, 0x34($t2)
sw $t7, 0x38($t2)
sw $s0, 0x3c($t2)
sw $s1, 0x40($t2)
sw $s2, 0x44($t2)
sw $s3, 0x48($t2)
sw $s4, 0x4c($t2)
sw $s5, 0x50($t2)
sw $s6, 0x54($t2)
sw $s7, 0x58($t2)
sw $t8, 0x5c($t2)
sw $t9, 0x60($t2)
sw $k0, 0x64($t2)
sw $k1, 0x68($t2)
sw $sp, 0x70($t2)
sw $s8, 0x74($t2)
sw $ra, 0x78($t2)
move $t2, $zero
""")

popa += mips_asm("""
lw $at, 0x0($t2)
lw $v0, 0x4($t2)
lw $v1, 0x8($t2)
lw $a0, 0xc($t2)
lw $a1, 0x10($t2)
lw $a2, 0x14($t2)
lw $a3, 0x18($t2)
lw $t0, 0x1c($t2)
lw $t1, 0x20($t2)
lw $t3, 0x28($t2)
lw $t4, 0x2c($t2)
lw $t5, 0x30($t2)
lw $t6, 0x34($t2)
lw $t7, 0x38($t2)
lw $s0, 0x3c($t2)
lw $s1, 0x40($t2)
lw $s2, 0x44($t2)
lw $s3, 0x48($t2)
lw $s4, 0x4c($t2)
lw $s5, 0x50($t2)
lw $s6, 0x54($t2)
lw $s7, 0x58($t2)
lw $t8, 0x5c($t2)
lw $t9, 0x60($t2)
lw $k0, 0x64($t2)
lw $k1, 0x68($t2)
lw $sp, 0x70($t2)
lw $s8, 0x74($t2)
lw $ra, 0x78($t2)
move $t2, $zero
""")

# keystone insert nop(=00000000) after jump or branch automatically
go_back_home = mips_asm("""
move $ra, $t6
jr $ra
move $ra, $t0
""").replace("00000000", "")

#-------------------------------------------------------------------------------------
# Below codes need dynamic instrumentation( only 1 time or each functions )
#-------------------------------------------------------------------------------------
# RULE 
#
# 1. replace 1337 to %04x
#
# 2. jal has 4 different opcode
#     1) 0C AA BB CC = jal (0xAABBCC * 4)
#     2) 0D AA BB CC = jal (0xAABBCC * 4) + 0x04000000
#     3) 0E AA BB CC = jal (0xAABBCC * 4) + 0x08000000
#     4) 0F AA BB CC = jal (0xAABBCC * 4) + 0x0C000000
# I can't decide opcode because of ASLR, patch it to %08x for later
#
# 3. calculate dynamic address need follow if statement
# if (dyn_addr & 0xffff) >= 0x8000:
#     lui $t2, (dyn_addr & 0xffff0000) + 0x10000
#     addiu $t2, $t2, (dyn_addr & 0xffff) - 0x10000
# else:
#     lui $t2, (dyn_addr & 0xffff0000)
#     addiu $t2, $t2, (dyn_addr & 0xffff)
#
# 4. If you have any relative branch to calculate later, use "b 0x4ce0" 
# 10 00 13 37 = b 0x4ce0, 0x4ce0 = 0x1337 * 4 + 4
# RULE 1 is most important!
# 
#-------------------------------------------------------------------------------------
# only 1 time
#-------------------------------------------------------------------------------------

# &offset_list
load_offsets = mips_asm("""
lui $t2, 0x1337
addiu $t2, $t2, 0x1337
sll $t1, $t1, 2
add $t2, $t2, $t1
lw $t1, ($t2)
srl $t3, $t1, 0x10
andi $t4, $t3, 0x07ff  // $t4 = reg2's offset( 10 bit ), lw or sw( 1 bit )
andi $t3, $t3, 0xf800  // $t3 = reg2( 5 bit )
srl $t3, $t3, 11       // right shift to delete zero padding
andi $t2, $t1, 0x07ff  // $t2 = reg1's offset( 10 bit ), lw or sw( 1 bit ) 
andi $t1, $t1, 0xf800  // $t1 = reg1( 5 bit )
srl $t1, $t1, 11       // right shift to delete zero padding
""").replace("1337", "%04x")

# &fmt_str
# &printf
call_printf = ""
call_printf += mips_asm("""
addi $a1, $ra, -12
lui $a0, 0x1337
addiu $a0, $a0, 0x1337
""").replace("1337", "%04x")
call_printf += "%08x" # jal printf
call_printf += mips_asm("nop")

restore_lw = ""
restore_sw = ""
#--------------------------------------------------------------------------------------------------------
restore_lw += mips_asm("""
add $t2, $t2, $sp
addi $t5, $zero, 0
""")

for i in range(1, 33):
    restore_lw += mips_asm("""
        bne $t1, $t5, 0x10
        add $t5, $zero, %d
        b %d
    """ % (i, (520 - (0x10 * i)))).replace("00000000", "")
    if i == 32:
        restore_lw += mips_asm("lw $t0, ($t2)") # $t0 will move its value to $ra at go_back_home
    else:
        restore_lw += mips_asm("lw $%d, ($t2)" % (i-1))

restore_lw += mips_asm("jr $ra")
#--------------------------------------------------------------------------------------------------------
restore_sw += mips_asm("""
add $t2, $t2, $sp
addi $t5, $zero, 0
""")
for i in range(1, 33):
    restore_sw += mips_asm("""
        bne $t1, $t5, 0x10
        add $t5, $zero, %d
        b %d
    """ % (i, (520 - (0x10 * i)))).replace("00000000", "")
    if i == 32:
        restore_sw += mips_asm("sw $t0, ($t2)") # $t0 store return address of original function
    else:
        restore_sw += mips_asm("sw $%d, ($t2)" % (i-1))
restore_sw += mips_asm("jr $ra")
#--------------------------------------------------------------------------------------------------------

# &reg_stack_offset_list
restore_opcodes = mips_asm("""
sub $sp, $t5
move $t6, $ra
lui $t5, 0x1337
addiu $t5, $t5, 0x1337
sll $t2, $t2, 1
add $t5, $t5, $t2
lh $t2, ($t5)
and $t5, $t2, 1
beqz $t5, 0x18
""").replace("1337", "%04x")

restore_opcodes += "%08x" # jal restore_lw
restore_opcodes += mips_asm("and $t2, $t2, 0xfffe")
restore_opcodes += mips_asm("b 0x10")

restore_opcodes += "%08x" # jal restore_sw
restore_opcodes += mips_asm("and $t2, $t2, 0xfffe")

# &reg_stack_offset_list
restore_opcodes += mips_asm("""
move $t1, $t3
move $t2, $t4
lui $t5, 0x1337
addiu $t5, $t5, 0x1337
sll $t2, $t2, 1
add $t5, $t5, $t2
lh $t2, ($t5)
and $t5, $t2, 1
beqz $t5, 0x18
""").replace("1337", "%04x")

restore_opcodes += "%08x" # jal restore_lw
restore_opcodes += mips_asm("and $t2, $t2, 0xfffe")
restore_opcodes += mips_asm("b 0x10")

restore_opcodes += "%08x" # jal restore_sw
restore_opcodes += mips_asm("and $t2, $t2, 0xfffe")

#-------------------------------------------------------------------------------------
# each functions 
#-------------------------------------------------------------------------------------

func_prologue_patch = ""
func_prologue_patch += mips_asm("move $t0, $ra")
func_prologue_patch += "%08x"   # jal code_cave_entry_x
func_prologue_patch += mips_asm("addiu $t1, $zero, 0x1337").replace("1337", "%04x")

code_cave_entry = ""
code_cave_entry += mips_asm("b 0x4ce0").replace("1337", "%04x").replace("00000000", "")
code_cave_entry += mips_asm("addiu $t5, $zero, 0x1337").replace("1337", "%04x")

#-------------------------------------------------------------------------------------
def DisplayRegistersMIPS(regbuffer) :
    regvals = [''] * 39
    buf = regbuffer
    for k, dword in enumerate([buf[i:i+8] for i in range(0, len(buf), 8)]) :
        regvals[k] = dword
    return regvals

def OnReadReg(display=True) :
    buf = GdbCommand('g')
    regs =  DisplayRegistersMIPS(buf)
    if display == True :
        print '======================== All registers: ========================'
        for k, reg_name in reg_map.iteritems() :
            if k % 5 == 0 :
                print "{}: {}".format(reg_name, regs[reg_map_rev[reg_name]])
            else :
                print "{}: {}".format(reg_name, regs[reg_map_rev[reg_name]]), 
        print '\nControl registers: ',
        print "PC: {} SP: {} RA: {}".format(regs[reg_map_rev['pc']],regs[reg_map_rev['sp']], regs[reg_map_rev['ra']])
        print '================================================================'
    return regs

def create_lists():
    global reg_stack_offset_list
    global stack_size_list
    global offset_list
    global func_dict
    with open(func_offset_file, "r") as f:
        buf = [x for x in f.read().split("\n") if x != '']

    first_dict = dict()
    tmp_stack_size_set = set()
    tmp_reg_offset_set = set()
    cntForDebug = 0
    for line in buf:
        func_offset, stack_size, reg1, reg1_offset, reg2, reg2_offset = [int(x, 16) for x in line.split(" ")]

        printf_offset = printf_addr - base_addr
        if func_offset in [printf_offset]:
            continue
        
        func_addr = base_addr + func_offset
        first_dict[func_addr] = [stack_size, reg1, reg1_offset, reg2, reg2_offset]
        tmp_stack_size_set.add(stack_size)
        tmp_reg_offset_set.add(reg1_offset)
        tmp_reg_offset_set.add(reg2_offset)

        # For debugging purpose
        if cntForDebug == 1000:
            break

        cntForDebug += 1
    
    stack_size_list = list(tmp_stack_size_set)
    reg_stack_offset_list = list(tmp_reg_offset_set)
    second_dict = dict()
    tmp_offset_set = set()
    for k,v in first_dict.iteritems():
        stack_size, reg1, reg1_offset, reg2, reg2_offset = v
        stack_size_idx = stack_size_list.index(stack_size)
        reg1_offset_idx = reg_stack_offset_list.index(reg1_offset)
        reg2_offset_idx = reg_stack_offset_list.index(reg2_offset)

        offset = ((reg2 & 0b11111) << 27)
        offset |= ((reg2_offset_idx & 0b11111111111) << 16)    
        offset |= ((reg1 & 0b11111) << 11)
        offset |= (reg1_offset_idx & 0b11111111111)

        second_dict[k] = [stack_size_idx, offset]
        tmp_offset_set.add(offset)

    offset_list = list(tmp_offset_set)
    for k,v in second_dict.iteritems():
        stack_size_idx, offset = v
        func_dict[k] = [stack_size_idx, offset_list.index(offset)]


def checksum(command):
    csum = 0
    reply = ""
    for x in command:
        csum = csum + ord(x)
    csum = csum % 256
    reply = "$" + command + "#%02x" % csum
    return reply


def decodeRLE(data):
    i=2
    multiplier=0
    reply=""
    while i < len(data):
        if data[i] == "*":
            multiplier = int(data[i+1] + data[i+2],16)
            for j in range (0, multiplier):
                reply = reply + data[i-1]
            i = i + 3
        if data[i] == "#":
            break   
        reply = reply + data[i]
        i = i + 1
    return reply


def GdbCommand(command) :
    ser.write('{}'.format(checksum(command)))
    if command == 'c' :
        return ''
    out = ''
    char =''
    while char != "#" :
        char = ser.read(1)
        out += char

    ser.read(2)
    newrle = decodeRLE(out)
    decoded = newrle.decode()
    if len(decoded) == 0 :
        return ''
    while decoded[0] == "|" or decoded[0] == "+" or decoded[0] == "$" :
        decoded = decoded[1:]
    return decoded


def isValidDword(hexdword):
    if len(hexdword) != 8:
        return False
    try:
        hexdword.decode('hex')
    except TypeError:
        return False
    return True


def OnReadMem(addr, length):
    if not isValidDword(addr):
        return None
    if length > 199:
        return None    
    res = GdbCommand('m{},{}'.format(addr.lower(),hex(length)[2:]))
    if res.startswith('E0'):
        return None
    else:
        return res


def OnWriteMem(addr, data):
    res = GdbCommand('M{},{}:{}'.format(addr.lower(), len(data)/2, data))
    if 'OK' in res:
        return True
    else:
        return None


def attach(cnt=0):
    global ser
    if cnt == 10:
        return
    try:
        ser = serial.Serial(port=COM_PORT, timeout=0.5)
        ser.writeTimeout = 0.5
        ser.interCharTimeout = 0.5
    except Exception as e:
        print 'fuck : ' + str(e)
        time.sleep(0.5)
        print "[!] serial connection to Cisco Device Failed, Make sure there's any other connection exist, %d try" % (cnt+1)
        attach(cnt+1)


def get_text_addr():
    global base_addr
    global printf_addr
    global noppad_addr
    global noppad_size
    global code_cave_text
    global code_cave_data
    global reg_store_addr

    reg_store_addr = 0x5F3FFF00
    regs = OnReadReg(0)
    pc = unpack('>I', regs[reg_map_rev['pc']].decode('hex'))[0]
    base_addr = IDA_BASE_ADDR + (pc - IDA_PC) 
    main_text_start, main_text_end = (base_addr, base_addr + (0x45160000 - base_addr))
    printf_addr = (printf_addr - IDA_BASE_ADDR) + base_addr
    noppad_addr = (noppad_addr - IDA_BASE_ADDR) + base_addr + 0x1000
    noppad_size = main_text_end - noppad_addr

    # I love aligned address as much as mmap()
    if (noppad_addr & 0xF) != 0:
       code_cave_text = (noppad_addr & ~0xF) + 0x10
    else:
        code_cave_text = noppad_addr
        
    code_cave_data = code_cave_text + ((noppad_size / 2) & ~0xF)


def create_jal(addr):
    offset = addr & 0x0FFFFFFF
    return 0x0c000000 + (offset / 4)


def create_addr_load_list(addr):
    ret = []
    if (addr & 0xffff) >= 0x8000:
        ret.append(((addr & 0xffff0000) + 0x10000) >> 16)
    else:
        ret.append((addr & 0xffff0000) >> 16)

    ret.append(addr & 0xffff)
    return ret


def OnWriteMem_by_N(write_addr, val, N=0x4):
    for i in range(0, len(val) / 2, N):
        value = val[i*2:i*2+(N*2)]
        addr = "%08x" % (write_addr + i)
        OnWriteMem(addr, value)
        # print '[DEBUG] addr : %s'%addr
        # print '[DEBUG] value : %s'%value
        # print '[DEBUG] status : %s'%str(OnWriteMem(addr, value))


def parse_args():
    parser = argparse.ArgumentParser(description="Cisco IOS Function Tracer")
    parser.add_argument("-p", "--printf", type=str, required=True, help="Cisco IOS's printf() address to print via serial( based on IDA )")
    parser.add_argument("-n", "--noppad", type=str, required=True, help="address of nop padding attached to the end of a main:text to inject code cave( based on IDA )")
    parser.add_argument("-s", "--serial", type=str, required=False, help="serial Port connected to the Cisco Router( default = COM3 )")
    parser.add_argument("-f", "--funclist", type=str, required=False, help="file that store function offset list( default = ftrace_func_list_2811.txt )")
    parser.add_argument("--idabase", type=str, required=False, help="IDA Imagebase address of Cisco IOS( default = 0x4000f000 )")
    parser.add_argument("--idaoffset", type=str, required=False, help="padding offset between main:text and start of IDA Imagebase opcode")
    parser.add_argument("--enablepw", type=str, required=False, help="password for 'enable' command")
    return parser.parse_args()


def main():
    global IDA_BASE_ADDR
    global IDA_OFFSET
    global COM_PORT
    global func_offset_file
    global printf_addr
    global noppad_addr
    global enable_password
    global offset_list_addr
    global reg_stack_offset_list_addr
    global fmt_str_addr
    global restore_lw_addr
    global restore_sw_addr
    global pusha
    global popa
    global code_cave

    args = parse_args()
    try:
        printf_addr = int(args.printf, 16)
        noppad_addr = int(args.noppad, 16)
        if args.idabase:
            IDA_BASE_ADDR = int(args.idabase, 16)
        if args.idaoffset:
            IDA_OFFSET = int(args.idaoffset, 16)
    except ValueError:
        print "[!] non-hexadecimal address detected"
        return

    if args.serial:
        COM_PORT = args.serial

    if args.funclist:
        func_offset_file = args.funclist

    if args.enablepw:
        enable_password = args.enablepw

    if not os.path.exists(func_offset_file):
        print "[!] %s file not exist" % func_offset_file
        return

    startTime = time.time()

    attach()
    get_text_addr()
    if base_addr < IDA_BASE_ADDR:
        print '[DEBUG] base : 0x%x'%base_addr
        print '[DEBUG] IDA_BASE_ADDR : 0x%x'%IDA_BASE_ADDR
        print "[!] base_addr is invalid"
        return

    print "=" * 80

    print "[+] base address = 0x%08x" % base_addr
    print "[+] printf() = 0x%08x" % printf_addr
    print "[+] nop padding of main:text = 0x%08x" % noppad_addr
    print "[+] nop padding size = 0x%x" % noppad_size
    print "[+] code_cave:text = 0x%08x" % code_cave_text
    print "[+] code_cave:data = 0x%08x" % code_cave_data

    print "=" * 80

    create_lists()
    print "[+] stack size diversity = %d( need %d bytes )" % (len(stack_size_list), len(stack_size_list) * 8)
    print "[+] offset diversity = %d( need %d bytes )" % (len(offset_list), len(offset_list) * 4)
    print "[+] register stack offset diversity = %d( need %d bytes )" % (len(reg_stack_offset_list), len(reg_stack_offset_list) * 2)

    print "=" * 80

    offset_list_addr = code_cave_data
    reg_stack_offset_list_addr = offset_list_addr + (len(offset_list) * 4)
    reg_stack_offset_list_addr = (reg_stack_offset_list_addr & ~0xF) + 0x10
    fmt_str_addr = reg_stack_offset_list_addr + (len(reg_stack_offset_list) * 2) 
    fmt_str_addr = (fmt_str_addr & ~0xF) + 0x10
    
    print "[+] &offset_list = 0x%08x"  % offset_list_addr
    print "[+] &reg_stack_offset_list = 0x%08x" % reg_stack_offset_list_addr
    print "[+] &fmt_str = 0x%08x" % fmt_str_addr
    print "[+] &register stored location = 0x%08x" % reg_store_addr

    pusha = pusha % tuple(create_addr_load_list(reg_store_addr))
    popa = popa % tuple(create_addr_load_list(reg_store_addr))

    print "=" * 80

    for i,v in enumerate([x for x in range(len(stack_size_list) * 2) if x & 1][::-1]):
        code_cave += code_cave_entry % (v, stack_size_list[i])
    code_cave += pusha
    code_cave += call_printf
    code_cave += popa
    code_cave += load_offsets
    code_cave += restore_opcodes
    code_cave += go_back_home
    
    restore_lw_addr = code_cave_text + (len(code_cave) / 2) + 10
    code_cave += restore_lw

    restore_sw_addr = code_cave_text + (len(code_cave) / 2) + 10
    code_cave += restore_sw

    print "[+] &restore_lw() = 0x%08x" % restore_lw_addr
    print "[+] &restore_sw() = 0x%08x" % restore_sw_addr

    print "=" * 80

    # Now, you have set dynamic address
    dyn_addr_list = []

    # call_printf = fmt_str_addr, jal printf
    dyn_addr_list.extend(create_addr_load_list(fmt_str_addr))
    dyn_addr_list.append(create_jal(printf_addr))
    
    # load_offset = offset_list_addr
    dyn_addr_list.extend(create_addr_load_list(offset_list_addr))

    # restore_opcodes = jal restore_lw, jal restore_sw, jal restore_lw, jal restore_sw
    dyn_addr_list.extend(create_addr_load_list(reg_stack_offset_list_addr))
    dyn_addr_list.append(create_jal(restore_lw_addr))
    dyn_addr_list.append(create_jal(restore_sw_addr))
    dyn_addr_list.extend(create_addr_load_list(reg_stack_offset_list_addr))
    dyn_addr_list.append(create_jal(restore_lw_addr))
    dyn_addr_list.append(create_jal(restore_sw_addr))

    code_cave = code_cave % tuple(dyn_addr_list)

    if (code_cave_data - code_cave_text)  < len(code_cave):
        print "[!] code_cave:text size is insufficient! reload Cisco IOS Image for more space!"
        return

    if (noppad_size - (code_cave_data - code_cave_text))  < ((len(offset_list) * 4) + (len(reg_stack_offset_list) * 2) + len(fmt_str)):
        print "[!] code_cave:data size is insufficient! reload Cisco IOS Image for more space!"
        return

    # I already privileged after I called get_text_addr()
    # Turn into debug mode
    raw_input("gogo? ")
    ser.close()
    attach()

    # write code_cave on code_cave:text
    print "[+] write code_cave"
    OnWriteMem_by_N(code_cave_text, code_cave)

    # write offset_list on code_cave:data( =offset_list_addr )
    print "[+] write offset_list"
    OnWriteMem_by_N(offset_list_addr, "".join("%08x" % x for x in offset_list))

    # write reg_stack_offset_list on code_cave:data( =reg_stack_offset_list_addr )
    print "[+] write reg_stack_offset_list"
    OnWriteMem_by_N(reg_stack_offset_list_addr, "".join("%04x" % x for x in reg_stack_offset_list))

    # write fmt_str on code_cave:data( =fmt_str_addr )
    print "[+] write fmt_str"
    OnWriteMem_by_N(fmt_str_addr, fmt_str.encode('hex'))

    if DEBUG:
        print "[DEBUG] Below addresses are based on IDA"

    print "[+] Tracing %d functions...." % len(func_dict)
    for func_addr,v in func_dict.iteritems():
        if DEBUG:
            print "[DEBUG] tracing sub_%08x()...sub_%08x() on IDA" % (func_addr, (func_addr - base_addr + IDA_BASE_ADDR))
        stack_size_idx, offset_list_idx = v
        OnWriteMem_by_N(func_addr, func_prologue_patch % (create_jal(code_cave_text + (stack_size_idx * 8)), offset_list_idx))
    print "[+] Function Tracer Finally Done!"
    GdbCommand("c")
    ser.close()

    endTime = time.time()

    print "[+] Elapsed Time: %.3f seconds" % (endTime-startTime)


if __name__ == "__main__":
    main()
