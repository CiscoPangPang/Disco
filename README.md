# Cisco IOS Exploit Framework (a.k.a DISCO Framework = Destroy cISCO)
![그림](https://user-images.githubusercontent.com/56502205/71272083-d7c06c00-2396-11ea-954a-58831f07ff9e.PNG)

## Fuzzer


Create an Smart Packet based on the coverage received through Instrumentation and send it to the Router for efficient fuzzing.

## FunctionTrace


Send Test Packet for the major basic block of code-patched IOS firmware, extract coverage, and send it to the Fuzzer connected by Serial Port.

## Debugger


CISCO IOS Mips Debugger with new features such as Backtrace and ASLR-based Dynamic Address Calculation
