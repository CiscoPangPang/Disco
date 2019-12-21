# cppdbg

`cppdbg` is a Debugger for Cisco IOS analysis.



## Description

`cppdbg` is a python script that works by accessing Cisco IOS directly through the `RSP protocol`. Because most commands are the same as regular `GDB`, people familiar with GDB can use `cppdbg` without problems in most situations. Since `cppdbg` is the first version after development, it only implements essential functions for debugging and is not classed or modularized, but is planned to be modularized and classified in consideration of future plug-ins and various additional functions.

Existing debuggers did not work at all as the version was upgraded and the compatibility with the RSP protocol was not appropriate. Also, the newly created debugger that solved the issue had many problems that the function implementation was not at all or insufficient. 

(For example, typing a command like `p/x $pc` will not work.) 

That's why we need a debugger that addresses these issues for Cisco IOS analysis.



## How to use?

It is very easy to install. You can use `python` regardless of operating system such as `windows` or `unix`, and if you install the `python modules` together with `git clone` by entering the following command on the PC connected to the serial port directly to the router, you can use `cppdbg` directly.

### install

```shell
git clone https://github.com/CiscoPangPang/Disco.git
cd Debugger
python -m pip install pyserial
python -m pip install logging
python -m pip install hexdump
python -m pip install termcolor
python -m pip install argparse
python -m pip install capstone
```

`cppdbg` only supports `python2`.



### usage

```sh
usage: cppdbg.py [-h] [-n NAME] [-pw PASSWORD] -o OFFSET

mips(Cisco IOS)-only Debugger

optional arguments:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  Router's hostname. default is "Router"
  -pw PASSWORD, --password PASSWORD
                        Router's "enable mode" entry password. default is
                        "Cisco"
  -o OFFSET, --offset OFFSET
                        Cisco Router IOS Codebase's offset (show region is not
                        real address)
```



### usage (cppdbg_2811.py)

```sh
usage: cppdbg_2811.py [-h] [-n NAME] [-pw PASSWORD]

mips(Cisco IOS)-only Debugger

optional arguments:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  Router's hostname. default is "Router"
  -pw PASSWORD, --password PASSWORD
                        Router's "enable mode" entry password. default is
                        "Cisco"
```



Both versions require you to delete the `.info` file every time you reboot `Cisco IOS`.

Additionally, If you want to know additional `command of debugger`, use `help command`.



### example

```sh
λ rm .info # essential factor
λ python cppdbg.py -o 0x968
Command reference:

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

you can also manually send any GDB RSP command

cppdbg> i r
======================== All registers: ================================
at: 3b670000 v0: 3a270000 v1: 00000001 a0: 36e10000 a1: 00000000
a2: 319b3c88 a3: 00000000 t0: 00000100 t1: 50009fe1 t2: 00008100
t3: ffff00ff t4: 30015428 t5: 3c3bb0a8 t6: 00000000 t7: 3c3bb280
s0: 3b670000 s1: 212b3b40 s2: 217b73cc s3: 212b3b40 s4: 3c3bb318
s5: 217b73cc s6: 00000000 s7: 3b670000 t8: 00000000 t9: 3000e660
k0: 504080e1 k1: fffffffe gp: 3b670e40 sp: 3c3bb2f0 s8: 00000000
ra: 319b3c9c pc: 30e86380
Control registers:  PC: 30e86380 SP: 3c3bb2f0 RA: 319b3c9c
=========================================================================
cppdbg> base
Cisco Base : 0x30008900
Ida Base   : 0x30000000
cppdbg> isalive
debug
cppdbg> c
Now continuing...
continue...> help
Command Reference :

exit           - Exit debugger
debug          - Interrupt "Continuing" status and reach "Debugging" status
isalive        - print the current status of debugger
continue (c)   - Change "Continuing" status to "Debugging"


continue...> isalive
continue
continue...> isalive
continue
continue...> debug
======================== All registers: ================================
at: 3b670000 v0: 3a270000 v1: 00000001 a0: 36e10000 a1: 00000000
a2: 319b3c88 a3: 00000000 t0: 00000100 t1: 50009fe1 t2: 00008100
t3: ffff00ff t4: 30015428 t5: 3c3bb0a8 t6: 00000000 t7: 3c3bb280
s0: 3b670000 s1: 212b3b40 s2: 217b73cc s3: 212b3b40 s4: 3c3bb318
s5: 217b73cc s6: 00000000 s7: 3b670000 t8: 00000000 t9: 3000e660
k0: 504080e1 k1: fffffffe gp: 3b670e40 sp: 3c3bb2f0 s8: 00000000
ra: 319b3c9c pc: 30e86380
Control registers:  PC: 30e86380 SP: 3c3bb2f0 RA: 319b3c9c
=========================================================================
===================================IDA===================================
0x30e7da6c:     lui     $t0, 0x3b67
0x30e7da70:     lw      $t0, -0x7168($t0)
0x30e7da74:     nop
0x30e7da78:     ori     $t0, $t0, 0x100
0x30e7da7c:     mtc0    $t0, $t5, 0
0x30e7da80:     nop
0x30e7da84:     nop
0x30e7da88:     j       0x30e7da94
0x30e7da8c:     addiu   $v0, $zero, 1
0x30e7da90:     move    $v0, $zero
0x30e7da94:     lw      $ra, 0x10($sp)
================================CISCO IOS================================
0x30e8636c:     lui     $t0, 0x3b67
0x30e86370:     lw      $t0, -0x7168($t0)
0x30e86374:     nop
0x30e86378:     ori     $t0, $t0, 0x100
0x30e8637c:     mtc0    $t0, $t5, 0
0x30e86380:     nop
0x30e86384:     nop
0x30e86388:     j       0x30e86394
0x30e8638c:     addiu   $v0, $zero, 1
0x30e86390:     move    $v0, $zero
0x30e86394:     lw      $ra, 0x10($sp)
cppdbg> c
Now continuing...
continue...> exit
```



## Who?

`cppdbg` and `Disco Framework` are open source projects developed by the `CiscoPangPang` team, the `KITRI Best of the Best` 8th project team.



## Contact

If you have any questions about this debugger or the Disco framework, please contact CiscoPangPang@gmail.com.

