import serial
import os
import sys
import time

# This is a function tracer for Cisco IOS
# Inspired by @gamozolab's https://github.com/gamozolabs/mesos
# Written By @y0ny0ns0n

# 1. Extract all the function address offset from IDA, read it from func_offset_list.txt.
# 1.1. If it doesn't exist, run extract_function_offset.py in IDA that Cisco IOS loaded.

# 2. connect to the router with serial, enter "show region" to read main:text address

# 3. calculated base address to main:text address - IDA_OFFSET
# ( I dunno this offset is fixed in our Cisco IOS version or globally acceptable... )

# 4. set breakpoint at every functions(base + offset) and continue.

# 5. check that breakpoint is triggered or not.
# 5.1. if triggered, print that address and continue

# 6. If I quit, delete all breakpoint and exit
'''
trouble list
1. offset 0 ~ IDA_OFFSET is not writable, you can't make a breakpoint in there
'''

COM_PORT = "COM3"

IDA_BASE_ADDR = 0x30000000

# c2900-universalk9-mz.SPA.153-3.M9.bin  = offset 0x968
# c2900-universalk9-mz.SPA.157-3.M4b.bin = offset 0x8f8
IDA_OFFSET = 0x968

offset_fname = "snmp_C2900_Result.txt"
string_offset_fname = "string_func_list.txt"
func_offset_list = []
base_addr = 0
ser = None

#-----------------------------------------------------------------------------------------------------------------
# Below codes are copied from mips_rsp.py(https://github.com/klsecservices/ios_mips_gdb/blob/master/mips_rsp.py)
#-----------------------------------------------------------------------------------------------------------------
breakpoints = {}
breakpoints_count = 0


def checksum(command):
    csum = 0
    reply = ""
    for x in command:
        csum = csum + ord(x)
    csum = csum % 256
    reply = "$" + command + "#%02x" % csum
    return reply


def decodeRLE(data):
    i = 2
    multiplier = 0
    reply = ""

    while i < len(data):
        if data[i] == "*":
            multiplier = int(data[i + 1] + data[i + 2], 16)
            for j in range(0, multiplier):
                reply = reply + data[i - 1]
            i = i + 3
        if data[i] == "#":
            break
        reply = reply + data[i]
        i = i + 1
    return reply


def GdbCommand(command):
    ser.write('{}'.format(checksum(command)))
    if command == 'c':
        return ''
    out = ''
    char = ''
    while char != "#":
        char = ser.read(1)
        out += char

    ser.read(2)
    newrle = decodeRLE(out)
    decoded = newrle.decode()

    if len(decoded) == 0:
        return ''
    while decoded[0] == "|" or decoded[0] == "+" or decoded[0] == "$":
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
    res = GdbCommand('m{},{}'.format(addr.lower(), hex(length)[2:]))
    if res.startswith('E0'):
        return None
    else:
        return res


def OnWriteMem(addr, data):
    res = GdbCommand('M{},{}:{}'.format(addr.lower(), len(data) / 2, data))
    if 'OK' in res:
        return True
    else:
        return None


def OnBreak(addr):
    global breakpoints
    global breakpoints_count

    if not isValidDword(addr):
        print "[!] OnBreak: %s is not valid dword" % addr
        return

    addr = addr.lower().rstrip()
    if addr in breakpoints:
        return
    opcode_to_save = OnReadMem(addr, 4)
    if opcode_to_save is None:
        print "[!] OnBreak: we can't read opcodes from %s" % addr
        return
    res = OnWriteMem(addr, '0000000d')
    if res:
        breakpoints[addr] = (breakpoints_count, opcode_to_save)
        breakpoints_count += 1
    else:
        print "[!] OnBreak: we can't write bkpt to %s" % addr


def OnDelBreak(b_num):
    global breakpoints
    global breakpoints_count

    item_to_delete = None
    for k, v in breakpoints.iteritems():
        try:
            if v[0] == int(b_num):
                res = OnWriteMem(k, v[1])
                if res:
                    item_to_delete = k
                    break
                else:
                    print "[!] OnDelBreak: we can't restore opcode at %s" % k
                    return
        except ValueError:
            print "[!] OnDelBreak: there are something wrong..."
            return
    if item_to_delete is not None:
        del breakpoints[k]


def OnStepInto():
    ser.write("$s#73\r\n")
    ser.read(5)


reg_map = {
    1: 'at',
    2: 'v0',
    3: 'v1',
    4: 'a0',
    5: 'a1',
    6: 'a2',
    7: 'a3',
    8: 't0',
    9: 't1',
    10: 't2',
    11: 't3',
    12: 't4',
    13: 't5',
    14: 't6',
    15: 't7',
    16: 's0',
    17: 's1',
    18: 's2',
    19: 's3',
    20: 's4',
    21: 's5',
    22: 's6',
    23: 's7',
    24: 't8',
    25: 't9',
    26: 'k0',
    27: 'k1',
    28: 'gp',
    29: 'sp',
    30: 's8',
    31: 'ra',
    37: 'pc'
}

reg_name = [
    'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 't4',
    't5', 't6', 't7', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8',
    't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra', 'pc'
]

reg_map_rev = {}

for k, v in reg_map.iteritems():
    reg_map_rev[v] = k

#-------------------------------------------------------------------------------------------------------------


def IsAlive():
    status = 'dead'
    host = "# "

    for i in range(10):
        ser.write('\r\n')
        buf = ser.read_until(host)
        ser.read(1)
        length = len(GdbCommand('g'))
        if host in buf or '% Bad' in buf:
            status = 'continue'
        elif length >= 200:
            status = 'debug'
        if status != 'dead':
            break

    return status


def attach():
    global ser
    try:
        ser = serial.Serial(port=COM_PORT, timeout=0.5)
        ser.writeTimeout = 0.5
        ser.interCharTimeout = 0.5
    except Exception:
        print "[!] serial connection to Cisco Device Failed, Make sure there's any other connection exist"
        sys.exit(-1)


def get_base_addr():
    global base_addr

    # step 2
    ser.write("enable\r\n")
    ser.read(2)  # receive \r\n

    # If password required, using default password. cisco
    if ser.read(4) == "Pass":
        ser.read_until("word: ")
        ser.write("cisco\r\n")
        ser.read_until("# ")

    ser.write("show region\r\n")
    buf = ser.read_until("main:text").split("\r\n")[-1]

    # step 3
    base_addr = int(buf.split(" ")[1], 16) - IDA_OFFSET

    # flush other output
    ser.read_until("# ")


def main():
    global func_offset_list

    print "[+] Make sure that Cisco IOS doesn't hunged on BP!"
    attach()

    # step 1
    if not os.path.exists(offset_fname):
        print "[!] %s not exist! extract it from IDA using extract_function_by_string.py!" % offset_fname
        return

    if not os.path.exists(string_offset_fname):
        print "[!] %s not exist! extract it from IDA using extract_string_functions.py!" % string_offset_fname
        return

    with open(offset_fname, "r") as f:
        buf = f.read()
        func_offset_list = buf.split("\n")[:-1]

    with open(string_offset_fname, "r") as f:
        buf = f.read()
        buf = buf.split("\n")[:-1]
        str_func_list = []
        for func_pair in buf:
            func_name, func_offset = func_pair.split(" ")
            str_func_list.append({
                "name": func_name,
                "offset": int(func_offset, 16)
            })

    get_base_addr()
    if base_addr <= IDA_BASE_ADDR:
        print "[+] base address is invalid!"
        return

    print "[+] Cisco IOS base addr : 0x%08x" % base_addr

    ser.write("gdb kernel\r\n")
    buf = ser.readlines()[-1][-4:]

    if buf == "||||":
        ser.close()
        attach()
        print "[+] Now, we re-connect to router as debug mode and magic happen!"
    else:
        print "[!] gdb kernel doesn't working...why?"
        print "[!] Maybe, gdb kernel are not supported anymore"
        print buf.encode('hex')
        return

    # step 4
    func_offset_list = func_offset_list[:1001]  # just for debugging
    print "[+] I need %d breakpoints...!!!" % len(func_offset_list)
    startTime = time.time()

    cnt = 0
    for func_offset in func_offset_list:
        try:
            if func_offset == '':
                continue

            func_offset = int(func_offset, 16)

            isBanned = False
            for str_funcs in str_func_list:
                if str_funcs["offset"] == func_offset:
                    print "[!] offset 0x%08x is %s! pass it for mental health" % (
                        func_offset, str_funcs["name"])
                    isBanned = True
                    break

            if isBanned:
                continue

            if func_offset in [0x32DC150, 0x3628FC0]:
                continue

            func_addr = "%08x" % (base_addr + func_offset)
            OnBreak(func_addr)
            '''
            if (cnt%200) == 0 and (cnt != 0):
                print "[+] re-connect to serial and sleep 0.1 seconds"
                time.sleep(0.1)
                ser.close()
                attach()
            '''

            if breakpoints_count % 100 == 0 and breakpoints_count != 0:
                print "[+] %d breakpoints" % breakpoints_count

            cnt += 1
        except KeyboardInterrupt:
            break

    print "[+] Elapsed Time: %d seconds" % (time.time() - startTime)
    print "[+] %d breakpoints" % breakpoints_count
    GdbCommand('c')
    ser.close()

    # I tried to make automatic ban list
    max_seconds_limits = 30
    max_seconds_limits += ((len(breakpoints) / 500) * 15)
    print "[+] some useless idle functions will be banned!"
    print "[+] Maximum time limits for ban: %d seconds" % max_seconds_limits
    startTime = time.time()
    while True:
        try:
            endTime = time.time()
            attach()
            if IsAlive() == "debug":
                buf = GdbCommand("g")
                regvals = [''] * 39
                for k, dword in enumerate(
                    [buf[i:i + 8] for i in range(0, len(buf), 8)]):
                    regvals[k] = dword
                # pc's index == 37
                pc_offset = int(regvals[37], 16) - base_addr
                sub_for_ida = "sub_%08x()" % (pc_offset + IDA_BASE_ADDR)
                idle_addr = "%08x" % (pc_offset + base_addr)

                print "[+] You are banned. %s" % sub_for_ida
                if idle_addr in breakpoints:
                    OnDelBreak(str(breakpoints[idle_addr][0]))
                else:
                    odd_bp_addr = "%08x" % (pc_offset + base_addr + 4
                                            )  # fxxking MIPS pipe lining 1
                    if odd_bp_addr in breakpoints:
                        OnDelBreak(str(breakpoints[odd_bp_addr][0]))
                    else:
                        print "[!] %s are not exist in breakpoint list...why?" % sub_for_ida

                GdbCommand('c')

            ser.close()
            if (endTime - startTime) > max_seconds_limits:
                break

        except KeyboardInterrupt:
            break
    # step 5
    regvals = [''] * 39
    print "[+] function address are based on IDA"
    while True:
        try:
            attach()
            ser.flushInput()
            ser.flushOutput()
            time.sleep(0.0001)
            if IsAlive() == "debug":
                # print function and argument and blahblah
                buf = GdbCommand("g")
                for k, dword in enumerate(
                    [buf[i:i + 8] for i in range(0, len(buf), 8)]):
                    regvals[k] = dword

                # pc's index == 37
                pc = regvals[37]
                pc_offset = int(pc, 16) - base_addr
                print "sub_%08x() called" % (IDA_BASE_ADDR + pc_offset)
                if pc in breakpoints:
                    OnWriteMem(pc, breakpoints[pc][1])
                    OnStepInto()
                    # time.sleep(0.0001)
                    OnWriteMem(pc, "0000000d")  # write bkpt
                    GdbCommand('c')
                else:
                    pc = "%08x" % (pc_offset + base_addr + 4
                                   )  # fxxking MIPS pipe lining 2
                    if pc in breakpoints:
                        OnWriteMem(pc, breakpoints[pc][1])
                        OnStepInto()
                        # time.sleep(0.0001)
                        OnWriteMem(pc, "0000000d")  # write bkpt
                        GdbCommand('c')
                    else:
                        print "    [!] WTF?? this address(=0x%s) not exist on breakpoints list" % pc
                        GdbCommand('c')

            ser.close()
        except KeyboardInterrupt:
            ser.close()
            attach()
            break

    # flush buffer
    ser.flushInput()
    ser.flushOutput()
    time.sleep(0.1)
    ser.write("gdb kernel\r\n")
    ser.close()
    attach()

    # step 6
    print "[+] delete every breakpoints! wait or reboot the box!"
    for i in range(breakpoints_count):
        if i % 100 == 0 and i != 0:
            print "[+] %d breakpoints deleted" % i

        OnDelBreak(str(i))

    # continue Cisco IOS process
    print "[+] I delete all breakpoints. process will be continue"
    GdbCommand('c')
    ser.close()


if __name__ == "__main__":
    main()