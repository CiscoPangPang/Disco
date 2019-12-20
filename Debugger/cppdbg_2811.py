#-*- coding:utf-8 -*-
#!/usr/bin/python
# Origin Author:
#  Artem Kondratenko (@artkond)

#  And Edited by Team Cisco PangPang in BoB 8th vulnerability analysis track

import serial
import time
import logging
from struct import pack, unpack
import sys
import capstone as cs
from termcolor import colored
from hexdump import *
import os
from time import sleep
import argparse

host = None
pw = None

IDA_OFFSET = None
IDA_BASE_ADDR = 0x4000f000
IDA_PC = 0x40072B94

cwd = os.getcwd()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


p_cnt = 0
variables = {}
CISCO_BASE_ADDR = None
memory_map = []

reg_map =   {1: 'at', 2: 'v0', 3: 'v1', 4:'a0', 
            5:'a1', 6: 'a2', 7: 'a3', 8: 't0', 
            9: 't1', 10: 't2', 11: 't3', 12: 't4', 
            13: 't5', 14: 't6', 15: 't7', 16: 's0', 
            17: 's1', 18: 's2', 19: 's3', 20: 's4',
            21: 's5', 22: 's6', 23: 's7', 24: 't8', 
            25: 't9', 26: 'k0', 27: 'k1', 28: 'gp', 
            29:'sp', 30: 's8', 31:'ra', 37:'pc'}

reg_name = ['at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
            't0', 't1', 't2', 't3', 't4', 't5', 't6',
            't7', 's0', 's1', 's2', 's3', 's4', 's5',
            's6', 's7', 't8', 't9', 'k0', 'k1', 'gp',
            'sp', 's8', 'ra', 'pc']

reg_map_rev = {}

breakpoints = {}
breakpoints_count = 0

isSerial = True

for k, v in reg_map.iteritems():
    reg_map_rev[v] = k

ser = serial.Serial(
    port="COM3",
    timeout=5
)

def usage(_) : 
    print 'usage: %s'%(_)

def hexdump_gen(byte_string, _len=16, base_addr=0, n=0, sep='-'):
    FMT = '{}  {}  |{}|'
    not_shown = ['  ']
    leader = (base_addr + n) % _len
    next_n = n + _len - leader
    while byte_string[n:]:
        col0 = format(n + base_addr - leader, '08x')
        col1 = not_shown * leader
        col2 = ' ' * leader
        leader = 0
        for i in bytearray(byte_string[n:next_n]):
            col1 += [format(i, '02x')]
            col2 += chr(i) if 31 < i < 127 else '.'
        trailer = _len - len(col1)
        if trailer:
            col1 += not_shown * trailer
            col2 += ' ' * trailer
        col1.insert(_len // 2, sep)
        yield FMT.format(col0, ' '.join(col1), col2)
        n = next_n
        next_n += _len


def isValidDword(hexdword):
    if len(hexdword) != 8:
        return False
    try:
        hexdword.decode('hex')
    except TypeError:
        return False
    return True

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

def print_help():
    print R'''Command reference:

continue                        - continue program execution
stepi                           - step into
nexti                           - step over
reg                             - print registers
set <reg_name> <value>          - set register value
break <addr> [ida]              - set break point. Optional "ida" parameter to set breakpoint to ida's address
info break                      - view breakpoints set
del <break_num>                 - delete breakpoint
read <addr> <len>               - read memory
write <addr> <value>            - write memory
dump <startaddr> <endaddr>      - dump memory within specified range
disas <addr> [ida]              - disassemble at address. Optional "ida" parameter to disassemble to ida's address
p[/{x, d, c, s}] <$name, value> - print reg's or value to fit type (default is Hexadecimal)
cisco <message>                 - send message in cisco gdb rsp command to RLE
vmmap [addr]                    - view virtual memory map of address
ctoi <addr>                     - calculate cisco address to ida address
itoc <addr>                     - calculate ida address to cisco address
base                            - print base address of ida and cisco ios 
isalive                         - print the current status of debugger
help                            - view gdb command
set_base                        - set Cisco IOS base address

you can also manually send any GDB RSP command
    '''

def CreateGetMemoryReq(address, len) :
    address = "m" + address + "," + len
    formatted = checksum(address)
    formatted = formatted + "\n"
    return formatted

def DisplayRegistersMIPS(regbuffer) :
    regvals = [''] * 39
    buf = regbuffer
    for k, dword in enumerate([buf[i:i+8] for i in range(0, len(buf), 8)]) :
        regvals[k] = dword
    return regvals

def GdbCommand(command) : 
    global isSerial
    command = str(command)
    logger.debug('GdbCommand sending: %s'%(checksum(command))) 
    
    ser.write(str('%s'%(checksum(command))))
    if command == 'c' :
        return ''
    out = ''
    char =''
    while char != "#" :
        char = ser.read(1)     
        out += char
    ser.read(2)            
    logger.debug('Raw output from cisco: {}'.format(out))
    newrle = decodeRLE(out)
    decoded = newrle.decode()
    if len(decoded) == 0 :
        return ''
    while decoded[0] == "|" or decoded[0] == "+" or decoded[0] == "$" :
        decoded = decoded[1:]
    return decoded    

def OnReadReg(display=True) :
    buf = GdbCommand('g')
    regs =  DisplayRegistersMIPS(buf)
    if display == True :
        print '======================== All registers: ========================'
        for k, reg_name in reg_map.iteritems() :
            if k % 5 == 0 :
                print "%s: %s"%(reg_name, regs[reg_map_rev[reg_name]])
            else :
                print "%s: %s"%(reg_name, regs[reg_map_rev[reg_name]]), 
        print '\nControl registers: ',
        print "PC: %s SP: %s RA: %s"%(regs[reg_map_rev['pc']],regs[reg_map_rev['sp']], regs[reg_map_rev['ra']])
        print '================================================================'
    return regs

def OnWriteReg(command) :
    lex = command.split(' ')
    if len(lex) != 3 :
        usage('set reg value')
        return
    (_ , reg_name, reg_val) = lex[0:3]
    if reg_name not in reg_map_rev :
        logger.error('Unknown register specified')
        return
    if reg_val.startswith('0x') :
        reg_val = reg_val.strip('L')[2:]
    else :
        if not isValidDword(reg_val) :
            logger.error('Invalid register value supplied')
            return
    logger.debug("Setting register {} with value {}".format(reg_name, reg_val))
    regs =  OnReadReg(0)
    regs[reg_map_rev[reg_name]] = reg_val.lower()
    buf = ''.join(regs)
    logger.debug("Writing register buffer: {}".format(buf))
    send = 'G%s'%(buf)
    send = str(send)
    res = GdbCommand(send)
    if 'OK' in res :
        return True
    else :
        return None

def OnReadMem(addr, length) :
    addr = int(addr.strip('L'), 16)
    left_len = length
    buf = ''
    while left_len > 0 :
        if(left_len >= 0xc7) :
            res = GdbCommand('m%08x,00c7'%(addr))
            addr += 0xc7
            left_len -= 0xc7
        else : 
            res = GdbCommand('m%08x,%04x'%(addr,left_len))
            left_len -= left_len
        if res.startswith('E0') :
            return buf
        buf += res
    
    return buf
    
def OnWriteMem(addr, data) :
    addr = int(addr.strip('L'), 16)
    res = GdbCommand('M%08x,%d:%s'%(addr, len(data)/2, data))
    if 'OK' in res :
        return True
    else :
        return None
    
def hex2int(s) :
    return unpack(">I", s.decode('hex'))[0]

def int2hex(num) :
    return pack(">I", num & 0xffffffff).encode('hex')

def OnBreak(command) :
    global breakpoints
    global breakpoints_count
    lex = command.split(' ')
    IsIda = None
    addr = None
    if lex == 3:
        (_, addr, IsIda) = lex[0:3]
    else :
        (_ ,addr) = lex[0:2]
    try :
        addr = int(addr, 16)
    except TypeError:
        print usage('b <address>')

    if IsIda != None :
        if IsIda.lower() == 'i' or IsIda.lower() == 'ida' :
            addr = itoc(addr)
    addr = hex(addr)[2:]
    addr = addr.strip('L')
    if addr in breakpoints:
        logger.info('breakpoint already set')
        return
    opcode_to_save = OnReadMem(addr, 4)
    if opcode_to_save is None :
        logger.error('Can\'t set breakpoint at {}. Read error'.format(addr))
        return
    res = OnWriteMem(addr, '0000000d')
    if res :
        breakpoints[addr] = (breakpoints_count, opcode_to_save)
        breakpoints_count += 1
        logger.info('Breakpoint set at {}'.format(addr))
    else :
        logger.error('Can\'t set breakpoint at {}. Error writing'.format(addr))

def OnDelBreak(command) :
    global breakpoints
    global breakpoints_count
    (_, b_num) = command.rstrip().split(' ')
    logger.debug('OnDelBreak')
    item_to_delete = None
    for k, v in breakpoints.iteritems():
        try:
            if v[0] == int(b_num) :
                res = OnWriteMem(k, v[1])
                if res:
                    item_to_delete = k
                    break
                else:
                    logger.error('Error deleting breakpoint {} at {}'.format(b_num, k))
                    return
        except ValueError:
            logger.error('Invalid breakpoint num supplied')
            return
    if item_to_delete is not None:
        del breakpoints[k]
        logger.info('Deleted breakpoint {}'.format(b_num))

def OnSearchMem(addr, pattern) :
    cur_addr = int(addr,16)
    buf = ''
    i = 0
    while True:
        i += 1
        mem = GdbCommand('m%08x,00c7'%(cur_addr))
        buf += mem
        if i %1000 == 0:
            print "Searching... " + hex(cur_addr)
            print hexdump(mem.decode('hex'))
        if pattern in buf:
            print 'FOUND at {}'.format(hex(cur_addr)[2:])
            return
        cur_addr += 0xc7

def OnListBreak() :
    global breakpoints
    global breakpoints_count
    print 'num    {}\t{}'.format(colored('Cisco     ', 'white'), colored('IDA', 'cyan'))
    for k, v in breakpoints.iteritems():
        cisco = colored('0x%08x'%int(k, 16), 'white')
        ida = colored('0x%08x'%ctoi(int(k, 16)), 'cyan')
        print '%-4d : %s\t%s'%(v[0], cisco, ida)

def OnStepInto(line) :
    next_line = line - 1
    regs = OnReadReg(0)
    pc = unpack('>I', regs[reg_map_rev['pc']].decode('hex'))[0]
    md = cs.Cs(cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN)
    is_break = False
    opcode = OnReadMem(hex(pc), 4)
    
    if opcode == '0000000d' :
        is_break = True
        for k, v in breakpoints.iteritems() :
            if int(k, 16) == pc :
                OnWriteMem(hex(pc), v[1])
                opcode = v[1]
                break
    for i in md.disasm(opcode.decode('hex'), pc) :
        inst = i.mnemonic
        location = i.op_str
    if inst.startswith('j') :
        if location.startswith('0x') :
            pc_after_branch = int(location, 16)
        elif location.startswith('$') :
            pc_after_branch = int(regs[reg_map_rev[location[1:]]], 16)
    else : 
        pc_after_branch = pc + 4 
    pc_in_hex = pack('>I', pc_after_branch).encode('hex')
    opcode_to_save = OnReadMem(hex(pc_after_branch), 4)
    OnWriteMem(hex(pc_after_branch), '0000000d')
    GdbCommand('c')
    OnWriteMem(hex(pc_after_branch), opcode_to_save)
    if is_break :
        OnWriteMem(hex(pc), '0000000d')
    if next_line == 0 :
        OnReadReg()
        OnDisas('disas')
        return
    OnStepInto(next_line)

def OnNext(line) :
    next_line = line - 1
    regs = OnReadReg(0)
    pc = unpack('>I', regs[reg_map_rev['pc']].decode('hex'))[0]
    md = cs.Cs(cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN)
    is_break = False
    opcode = OnReadMem(hex(pc), 4)

    if opcode == '0000000d' :
        is_break = True
        for k, v in breakpoints.iteritems() :
            if int(k, 16) == pc :
                OnWriteMem(hex(pc), v[1])
                opcode = v[1]
                break
    for i in md.disasm(opcode.decode('hex'), pc) :
        inst = i.mnemonic
        location = i.op_str
    if inst.startswith('jal') :
        pc_after_branch = pc + 8
    elif inst.startswith('j') and not inst.startswith('jal') :
        if location.startswith('0x') :
            pc_after_branch = int(location, 16)
        elif location.startswith('$') :
            pc_after_branch = int(regs[reg_map_rev[location[1:]]], 16)
    else :    
        pc_after_branch = pc + 4
    pc_in_hex = pack('>I', pc_after_branch).encode('hex')
    opcode_to_save = OnReadMem(hex(pc_after_branch), 4)
    OnWriteMem(hex(pc_after_branch), '0000000d')
    GdbCommand('c')
    OnWriteMem(hex(pc_after_branch), opcode_to_save)
    if is_break :
        OnWriteMem(hex(pc), '0000000d')
    if next_line == 0 :
        OnReadReg()
        OnDisas('disas')
        return
    OnNext(next_line)

def OnDumpMemory(start, stop) :
    buf = ''
    
    start = int(start,16)
    stop = int(stop,16)
    size = stop - start
    #print start, stop
    cur_addr = start
    '''
    if not isValidDword(start) or not isValidDword(stop):
        logger.error('Invalid memory range specified')
        return 
    '''
    #if size >= 0x10000:
    #    print "Max Dump Size is 0xffff"
    dumpsize = 0 
    while cur_addr < stop:

        if size > 0xc7 :
            res = GdbCommand('m%08x,00c7'%(cur_addr))
            dumpsize += 0xc7
            size -= dumpsize
        else:
            res = GdbCommand('m%08x,%04x'%(cur_addr, size))
            dumpsize += size

        logger.info('Dumping at 0x%08x len 0x%08x'%(cur_addr, len(res)))
        cur_addr += dumpsize
        buf += res

    print hexdump(buf)
    return buf

def OnDisas(command) :
    lex = command.rstrip().split(' ')
    IsIda = None
    addr = None
    for k, v in breakpoints.iteritems() :
        OnWriteMem(hex(int(k, 16)), v[1])

    regs = OnReadReg(0)
    pc = hex2int(regs[reg_map_rev['pc']])
    
    if len(lex) == 2 :
        addr = lex[1]
    elif len(lex) == 3:
        (addr, IsIda) = lex[1:3]
    if addr != None :
        if addr.startswith('0x') :
            pc = int(addr, 16)
        else :
            pc = int(addr)
    if IsIda != None :
        if IsIda.lower() == 'i' or IsIda.lower() == 'ida' :
            pc = itoc(pc) 


    logger.debug('OnDisas PC = {}'.format(pc))
    buf = OnReadMem(int2hex(pc - 5 * 4), 11 * 4)
    md = cs.Cs(cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN)
    print colored('===================================IDA===================================', 'cyan')
    for i in md.disasm(buf.decode('hex'), ctoi(pc - 5 * 4)) :
        color = 'green' if itoc(i.address) == pc else 'blue'
        out = i.op_str
        try :
            if int(str(i.op_str), 16) > 0x30000000 :
                out = hex(ctoi(int(str(i.op_str), 16))).strip('L').encode()
        except :
            pass
        
        print("0x%x:\t%s\t%s" %(i.address, colored(i.mnemonic, color), colored(out, color)))
    print colored('================================CISCO IOS================================', 'white')
    for i in md.disasm(buf.decode('hex'), pc - 5 * 4) :
        color = 'green' if i.address == pc else 'blue'
        print("0x%x:\t%s\t%s" %(i.address, colored(i.mnemonic, color), colored(i.op_str, color)))

    for k, v in breakpoints.iteritems() :
        OnWriteMem(hex(int(k, 16)), '0000000d')

def Escape(buf) :
    buf = buf.replace(R"\'", "'").replace(R'\"', '"').replace(R'\n', '\n')
    buf = buf.replace(R'\r', '\r').replace(R'\t', '\t').replace(R'\a', '\a')
    buf = buf.replace(R'\f', '\f').replace(R'\v', '\v').replace(R'\b', '\b')
    buf = buf.replace(R'\\', '\\')
    return buf

def DeEscape(buf) :
    buf = buf.replace('\n', R'\n')
    buf = buf.replace('\r', R'\r').replace('\t', R'\t').replace('\a', R'\a')
    buf = buf.replace('\f', R'\f').replace('\v', R'\v').replace('\b', R'\b')
    return buf


def OnPrintValue(command) :
    global reg_name
    global p_cnt
    global variables

    t, out = command.split(' ')
    regs =  OnReadReg(0)
    name = ''
    value = ''

    if len(t) >= 3 :
        if t[-2] == '/' :
            t = t[-1]
        else :
            t = ''

    else :
        t = ''

    if out[0] == '$':
        name = out.replace('$', '')
        if name in reg_name : 
            value = int(regs[reg_map_rev[name]], 16)
        elif name in [i for i, _ in variables.iteritems()] :
            value = variables[name]
        else :
            print R"undefined name.."
            usage(R'p[/{x, d, c, s}] <$name, value>')
            return
    
    elif out[0] == "'" :
        if out[-1] != "'" or out[-2:] == R"\'" :
            print 'Unmatched single quote.'
            return
        elif out[-1] == "'" :
            value = "c" + out[1:-1]
            value = Escape(value)
            if len(value) > 2 :
                print 'not character type.'
                return
        else :
            print 'Unexpected token.'
            return 

    elif out[0] == '"' :
        if out[-1] != '"' or out[-2:] == R'\"' :
            print 'Unterminated string in expression.'
            return
        elif out[-1] == '"' :
            value = "s" + out[1:-1]
            value = Escape(value)
             
        else : 
            print 'Unexpected token.'
            return 

    elif out.startswith('0x') :
        value = int(out, 16)
    else :
        value = int(out)

    p_cnt += 1
    variables[str(p_cnt)] = value
    if t == 'd' :
        if type(value) == str :
            if value[0] == 'c' :
                print '$%d = %d'%(p_cnt, ord(value[1]))
            elif value[0] == 's' :
                output = '$%d = {'%p_cnt
                for i in range(1, len(value)) :
                    output += "%d '%c'"%(ord(value[i]), value[i])
                    output += ', '
                    if i + 1 == len(value) :
                        output += '0'
                        break
                output += R'}'
                output = DeEsacpe(output)
                print output

        elif type(value) == int :
            print '$%d = '%(p_cnt) + str(value)
        
    elif t == 'c' :
        if type(value) == str :
            if value[0] == 's' :
                output = '$%d = {'%p_cnt
                for i in range(1, len(value)) :
                    output += "%d '%c'"%(ord(value[i]), value[i])
                    output += ', '
                    if i + 1 == len(value) :
                        output += '0'
                        break
                output += R'}'
                output = DeEscape(output)
                print output

            elif value[0] == 'c' :
                print "$%d = %d '%c'"%(p_cnt, ord(value[1]), value[1])


        elif type(value) == int :
            while value > 0xff :
                value /= 0x10

            print "$%d = %d '%c'"%(p_cnt, value, value)

    elif t == 's' :
        if type(value) == str :
            if value[0] == 's' :
                print '$%d = "%s"'%(p_cnt, value[1:])
            elif value[0] == 'c' :
                print "$%d = %d '%c'"%(p_cnt, ord(value[1]), value[1])
        elif type(value) == int :
            print '$%d = '%(p_cnt) + hex(value)

    elif t == ''  or t == 'x' :
        if type(value) == str :
            if value[0] == 'c'  :
                print '"0x%x"'%ord(value[1])
            elif value[0] == 's' :
                output = '$%d = {'%p_cnt
                for i in range(1, len(value)) :
                    output += "0x%x '%c'"%(ord(value[i]), value[i])
                    output += ', '
                    if i + 1 == len(value) :
                        output += '0x0'
                        break
                output += R'}'
                output = DeEscape(output)
                print output
        elif type(value) == int :
            print '$%d = '%(p_cnt) + hex(value)

    else :
        p_cnt -= 1
        print R"undefined type.."
        usage('p/x $ra')
        return


def OnSendCisco(command) :
    _, msg = command.split(' ')
    ans = raw_input('Do you want to send raw command: {} ? [yes]'.format(checksum(msg)))
    if ans == '' or ans.lower() == 'yes' or ans.lower() == 'y' :
        print 'Your message: %s'%checksum(msg)
        reply = GdbCommand(msg)
        print "Cisco response: %s"%reply.rstrip()
    else :
        pass

def IsAlive() :
    status = 'dead'
    for i in range(10) :
        length = len(GdbCommand('g'))
        if length >= 200 :
            status = 'debug'
        else :
            ser.write('\r\n')
            buf = ser.read_until(host)
            ser.read(1)
            if host in buf or '% Bad' in buf:
                status = 'continue'
        if status != 'dead' :
            break
    return status

def OnGdbContinue() :
    global ser
    print 'Now continuing...'
    while True:
        concmd = raw_input(colored('continue...> ', 'green')).strip().strip('\n')
        if len(concmd) == 0 :
            continue

        if concmd == 'exit' :
            return False
        
        elif concmd == 'isalive' :
            print IsAlive()

        elif concmd == 'c' or concmd == 'continue' :
            if IsAlive() == 'debug' :
                return True
            
            elif IsAlive() == 'dead' :
                print 'Router\'s status is "Died".'
                sys.exit(0)
            else :
                print 'router\'s status is still "Continue".'
                continue
        else :
            print R'''Command Reference :

exit           - Exit debugger
isalive        - print the current status of debugger
continue (c)   - Change "Continuing" status to "Debugging" 
            
            '''

def OnSetCiscoBase():
    global IDA_OFFSET
    global CISCO_BASE_ADDR

    regs = OnReadReg(0)
    pc = unpack('>I', regs[reg_map_rev['pc']].decode('hex'))[0]
    CISCO_BASE_ADDR = IDA_BASE_ADDR + (pc - IDA_PC)# - IDA_OFFSET 
    '''
    '''


def OnLoadInfo(): # save IOS information just like break point, Cisco IOS Router base address and memory map 
    global CISCO_BASE_ADDR
    f_name = cwd + R'\\.info'
    bp_buf = ''
    if not os.path.exists(f_name) :
        return
    else :
        with open(f_name, 'rb') as f :
            bp_buf = f.read()

    bp_info = bp_buf.split('\r\n')
    CISCO_BASE_ADDR = int(bp_info[0], 16)
    breakpoints_count = int(bp_info[1])
    for i in range(2, len(bp_info) - 1, 3) :
        breakpoints[bp_info[i]] = (int(bp_info[i + 1]), bp_info[i + 2])
    return 

def OnSaveInfo() :
    global CISCO_BASE_ADDR
    global breakpoints_count
    global breakpoints
    global cwd

    f_name = cwd + R'\\.info'
    buf = hex(CISCO_BASE_ADDR) + '\r\n'
    buf += str(breakpoints_count) + '\r\n'
    for n, v in breakpoints.iteritems() :
        buf += str(n) + '\r\n'
        buf += str(v[0]) + '\r\n'
        buf += str(v[1]) + '\r\n'
    with open(f_name, 'wb') as f:
        f.write(buf)

def OnSetArg() :
    global host
    global pw
    global IDA_OFFSET
    parser = argparse.ArgumentParser(description='mips(Cisco IOS)-only Debugger')
    add_arg = parser.add_argument
    parse_arg = parser.parse_args

    add_arg('-n', '--name', help='Router\'s hostname. default is "Router"' , required=False)
    add_arg('-pw', '--password', help='Router\'s "enable mode" entry password. default is "Cisco"', required=False)
    args = parse_arg()
    host = args.name
    pw = args.password
    print_help()

    if host == None :
        host = 'Router'
    if pw == None :
        pw = 'cisco'


def OnStartDbg() :
    OnSetArg()
    print_help()
    OnSetCiscoBase()
    OnLoadInfo()

def ctoi(cisco_addr) :
    global CISCO_BASE_ADDR
    global IDA_BASE_ADDR
    offset = cisco_addr - CISCO_BASE_ADDR
    return IDA_BASE_ADDR + offset 
def itoc(ida_addr) :
    global CISCO_BASE_ADDR
    global IDA_BASE_ADDR
    offset = ida_addr - IDA_BASE_ADDR
    return CISCO_BASE_ADDR + offset 

def OnCtoi(command) :
    global CISCO_BASE_ADDR
    global regs
    global reg_map_rev
    _, addr = command.split(' ')
    regs = OnReadReg(0)
    try :
        if addr.startswith('$') :
            addr = int(regs[reg_map_rev[addr[1:]]], 16)
        elif addr.startswith('0x') :
            addr = int(addr,16)
        else :
            addr = int(addr)
    except :
        usage('ctoi <$ra>')

    if addr - CISCO_BASE_ADDR < 0 :
        print 'Check the address.'
        return 0

    return ctoi(addr)

def OnItoc(command) :
    global IDA_BASE_ADDR
    _, addr = command.split(' ')
    if addr.startswith('0x') :
        addr = int(addr,16)
    else :
        addr = int(addr)
    if addr - IDA_BASE_ADDR < 0 :
        print 'Check the address.'
        return 0
    return itoc(addr)

def OnVmmap(command) :
    '''
    '''
def OnExit() :
    OnSaveInfo()
    sys.exit(0)


def main() :
    global CISCO_BASE_ADDR
    global IDA_BASE_ADDR
    global cwd

    OnStartDbg()
    prev = ''
    while True :
        try :
            command = raw_input(colored('cppdbg> ', 'red')).strip().strip('\n')
            if len(command) == 0 :
                command = prev
                if len(command) == 0 :
                    continue
            prev = command
            if command == 'exit' :
                OnExit()
            elif command == 'help' or command == 'h' :
                print_help()
            elif command == 'c' or command == 'continue' :
                GdbCommand('c')
                if OnGdbContinue() == False : 
                    OnExit()
                OnReadReg()
                OnDisas('disas')
            elif command.startswith('stepi') or command.startswith('si') :
                lex = command.split(' ')
                line = 1
                if len(lex) == 2 :
                    line = int(lex[1])
                elif len(lex) > 2 :
                    usage('stepi <line>')
                    continue
                OnStepInto(line)
            elif command.startswith('nexti') or command.startswith('ni') :
                lex = command.split(' ')
                line = 1
                if len(lex) == 2 :
                    line = int(lex[1])
                elif len(lex) > 2 :
                    usage('nexti <line>')
                    continue
                OnNext(line)
            elif command == 'reg' or command == 'regs' or command == 'i r' or command == 'info reg' or command == 'info register' or command == 'info registers' :
                OnReadReg()
            elif command == 'info b' or command == 'i b' or command == 'info breakpoint' or command == 'info break' or command == 'list':
                OnListBreak()
            elif command.startswith('setreg') or (command.startswith('set') and not command.startswith('set_')):
                OnWriteReg(command)
            elif command.startswith('break') or (command.startswith('b') and not command.startswith('base')):
                OnBreak(command)
            elif command.startswith('del') or (command.startswith('d') and not command.startswith('disas') and not command.startswith('dump')):
                OnDelBreak(command)
            elif command.startswith('read') or command.startswith('r'):
                _, start, length = command.split(' ')
                print _, start, length
                if length.startswith('0x') :
                    length = str(int(length, 16))
                buf = OnReadMem(start, int(length))
                for line in hexdump_gen(buf.decode('hex'), base_addr=hex2int(start), sep=' '):
                    print line
            elif command.startswith('write') or command.startswith('w'):
                _, dest, value = command.split(' ')
                value.decode('hex')
                OnWriteMem(dest, value)
            elif command.startswith('search'):
                _, addr, pattern = command.split(' ') 
                OnSearchMem(addr, pattern)

            elif command.startswith('dump'):
                _, start, stop = command.split(' ')
                buf = OnDumpMemory(start.lower(), stop.lower())
                if buf is None:
                    continue
                else:
                    cnt = 0
                    while True :
                        f_name = cwd + R'\\dump_file' + '%d'%cnt
                        if os.path.exists(f_name) :
                            cnt += 1
                            continue
                        else :
                            with open(f_name,'wb') as f :
                                f.write(buf)
                            logger.info('Wrote memory dump to "{}"'.format(f_name))
                            break
            elif command.startswith('disassemble') or command.startswith('disas'):
                OnDisas(command)
                '''
            elif command.startswith('vmmap') :
                OnVmmap(command)
                '''
            elif command.startswith('ctoi') or command.startswith('ciscotoida') :
                print colored('OnCtoi : ' + hex(OnCtoi(command)), 'cyan')
            elif command.startswith('itoc') or command.startswith('idatocisco') :
                print colored('OnItoc : ' + hex(OnItoc(command)), 'white')
            elif command.startswith('print') or command.startswith('p') :
                OnPrintValue(command)
            elif command.startswith('cisco') :
                OnSendCisco(command)
            elif command == 'isalive' :
                print IsAlive()
            elif command == 'base' :
                print colored('Cisco Base : ' + hex(CISCO_BASE_ADDR), 'white')
                print colored('Ida Base   : ' + hex(IDA_BASE_ADDR), 'cyan')
            elif command.startswith('set_base') :
                lex = command.split(' ')[:2]
                if len(lex) != 2 or lex[1].strip() == '':
                    print 'please.. help me.. T.T' 
                if lex[1].startswith('0x') :
                    addr = int(lex[1], 16)
                else :
                    try :
                        addr = int(lex[1], 10)
                    except :
                        print 'please... nono..'
                CISCO_BASE_ADDR = addr
            else:
                print 'Undefined command: "{}".  Try "help".'.format(command)
        except (KeyboardInterrupt, serial.serialutil.SerialException, ValueError, TypeError) as e :
            print '\n{}'.format(e)
            print 'Type "exit" to end debugging session'


if __name__ == '__main__' :
    main()
