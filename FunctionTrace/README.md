# Cisco IOS Function Trace

![그림2](https://user-images.githubusercontent.com/56502205/71259830-a8046a80-237c-11ea-932f-f8c5ab7989a4.PNG)

Function Tracer for Cisco IOS analysis.



## Description

Because Cisco IOS is a big ELF executable file with hundreds of thousands of functions, it is diffcult to find specific function routine that analyst wants to analyze. Function Tracer is a tool created to resolve such problem, which extracts a list of functions that analyst want to trace from IDA and then dynamically patches the Function Tracer code via the debug mode of Cisco IOS.

After the dynamic patch, each time a function that was patched is called, wired serial communication with the Cisco Router outputs the address of  called function. With this functionality, it is possible to see which functions are called in what order when certain features of Cisco IOS are executed.



## How to use

`Function Tracer` consists of a total three python scripts:

1. ### **create_printf_ban.py**

: extract a list of functions that generate errors when using the function tracer through IDA and store them in a file.

``` 
File - Script File - create_printf_ban.py
```



2. ### **ftrace_extract_from_IDA.py**

: extract informations from traceable functions and stores them in a file, except for functions that are not available with the Function Tracer through IDA.

```
File - Script File - ftrace_extract_from_IDA.py
```



3. ### **ftrace.py**

: create Function Tracer code with previously extracted information and then inserts it into Cisco IOS through debug mode.

#### usage

```sh
usage: ftrace_2811.py [-h] -p PRINTF -n NOPPAD [-s SERIAL] [-f FUNCLIST]
                      [--idabase IDABASE] [--idaoffset IDAOFFSET]
                      [--enablepw ENABLEPW]

Cisco IOS Function Tracer

optional arguments:
  -h, --help            show this help message and exit
  -p PRINTF, --printf PRINTF
                        Cisco IOS's printf() address to print via serial(
                        based on IDA )
  -n NOPPAD, --noppad NOPPAD
                        address of nop padding attached to the end of a
                        main:text to inject code cave( based on IDA )
  -s SERIAL, --serial SERIAL
                        serial Port connected to the Cisco Router( default =
                        COM3 )
  -f FUNCLIST, --funclist FUNCLIST
                        file that store function offset list( default =
                        ftrace_func_list.txt )
  --idabase IDABASE     IDA Imagebase address of Cisco IOS( default =
                        0x30000000 )
  --idaoffset IDAOFFSET
                        padding offset between main:text and start of IDA
                        Imagebase opcode
  --enablepw ENABLEPW   password for 'enable' command
```



#### example

```sh
$ python ftrace_2811.py -p 41f2f348 -n 4512dda8
================================================================================
[+] base address = 0x400140a0
[+] printf() = 0x41f343e8
[+] nop padding of main:text = 0x45133e48
[+] nop padding size = 0x2c1b8
[+] code_cave:text = 0x45133e50
[+] code_cave:data = 0x45149f20
================================================================================
[+] stack size diversity = 22( need 176 bytes )
[+] offset diversity = 70( need 280 bytes )
[+] register stack offset diversity = 42( need 84 bytes )
================================================================================
[+] &offset_list = 0x45149f20
[+] &reg_stack_offset_list = 0x4514a040
[+] &fmt_str = 0x4514a0a0
[+] &register stored location = 0x5f3fff00
================================================================================
[+] &restore_lw() = 0x451340c8
[+] &restore_sw() = 0x451342d8
================================================================================
gogo?
[+] write code_cave
[+] write offset_list
[+] write reg_stack_offset_list
[+] write fmt_str
[DEBUG] Below addresses are based on IDA
[+] Tracing 252 functions....
[DEBUG] tracing sub_40357600()...sub_40352560() on IDA
[DEBUG] tracing sub_4164e300()...sub_41649260() on IDA
[DEBUG] tracing sub_444e7e04()...sub_444e2d64() on IDA
[DEBUG] tracing sub_4180daa8()...sub_41808a08() on IDA
[DEBUG] tracing sub_42141208()...sub_4213c168() on IDA
[DEBUG] tracing sub_415338ac()...sub_4152e80c() on IDA
[DEBUG] tracing sub_41d3960c()...sub_41d3456c() on IDA
[DEBUG] tracing sub_45054210()...sub_4504f170() on IDA
[DEBUG] tracing sub_427dda58()...sub_427d89b8() on IDA
```



#### result

![그림1](https://user-images.githubusercontent.com/56502205/71259848-b2beff80-237c-11ea-9d16-d959f06df1db.png)





## Who?

`cppdbg` and `Disco Framework` are open source projects started by the `CiscoPangPang` team, the `KITRI Best of the Best` 8th project team.



## Contact

If you have any questions about this debugger or the Disco framework, please contact CiscoPangPang@gmail.com.

